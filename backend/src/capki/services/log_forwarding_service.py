"""Mirrors application logs and/or audit-log entries out to a Splunk/Cribl
HTTP Event Collector and/or a syslog receiver, as JSON.

Design:
- A single background thread drains a bounded in-memory queue and does the
  actual network I/O (HEC POST / syslog send). Nothing on a request's
  critical path ever blocks on the network — `logging.Handler.emit()` and
  `audit_service.log_action()` just do a non-blocking queue put. If the
  queue is full (collector down/slow for a while) or the process restarts,
  queued-but-unsent events are dropped — this is deliberately best-effort,
  not a durable delivery guarantee (see README).
- Config is cached in memory (refreshed on every `update_log_forwarding_config`
  call) so the hot paths (`emit()`, `log_action()`) never hit the DB.
- `hec_token` is envelope-encrypted at rest with the app master key, same
  as the SMTP password / Telegram bot token in notification_service.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import ssl
import threading
import urllib.error
import urllib.request
from typing import Any

from sqlalchemy.orm import Session

from capki.config import settings
from capki.core.crypto import envelope
from capki.core.crypto.master_key import load_or_create_master_key
from capki.db.base import utcnow
from capki.db.models.settings import LogForwardingConfig
from capki.db.session import SessionLocal

logger = logging.getLogger(__name__)

_HEC_TOKEN_AAD = b"log_forwarding_config:hec_token"

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
SYSLOG_PROTOCOLS = ("udp", "tcp", "tcp_tls")

_SYSLOG_SEVERITY_BY_LEVELNO = {
    logging.DEBUG: 7,
    logging.INFO: 6,
    logging.WARNING: 4,
    logging.ERROR: 3,
    logging.CRITICAL: 2,
}

_QUEUE_MAXSIZE = 2000
_queue: "queue.Queue[tuple[str, dict[str, Any], int]]" = queue.Queue(maxsize=_QUEUE_MAXSIZE)
_dropped_count = 0
_dropped_lock = threading.Lock()

# In-memory cache of the current config, refreshed on every update and on
# worker startup — avoids a DB round-trip on every single log call.
_cached_config: LogForwardingConfig | None = None
_cache_lock = threading.Lock()


class ForwardingError(Exception):
    """Raised when a HEC/syslog delivery attempt fails — used by the test
    endpoint to report a specific reason back to the caller."""


def get_log_forwarding_config(db: Session) -> LogForwardingConfig:
    config = db.get(LogForwardingConfig, 1)
    if config is None:
        config = LogForwardingConfig(id=1, updated_at=utcnow())
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def _encrypt_secret(plaintext: str) -> tuple[bytes, dict]:
    master_key = load_or_create_master_key()
    return envelope.wrap_with_master_key(plaintext.encode("utf-8"), master_key, _HEC_TOKEN_AAD)


def _decrypt_secret(ciphertext: bytes, meta: dict) -> str:
    master_key = load_or_create_master_key()
    return envelope.unwrap_with_master_key(ciphertext, master_key, meta, _HEC_TOKEN_AAD).decode("utf-8")


def update_log_forwarding_config(
    db: Session,
    *,
    app_log_min_level: str | None = None,
    hec_enabled: bool | None = None,
    hec_send_app_logs: bool | None = None,
    hec_send_audit_logs: bool | None = None,
    hec_url: str | None = None,
    hec_token: str | None = None,
    hec_source: str | None = None,
    hec_sourcetype: str | None = None,
    hec_index: str | None = None,
    hec_verify_tls: bool | None = None,
    syslog_enabled: bool | None = None,
    syslog_send_app_logs: bool | None = None,
    syslog_send_audit_logs: bool | None = None,
    syslog_host: str | None = None,
    syslog_port: int | None = None,
    syslog_protocol: str | None = None,
    syslog_facility: int | None = None,
) -> LogForwardingConfig:
    config = get_log_forwarding_config(db)
    if app_log_min_level is not None:
        if app_log_min_level not in LOG_LEVELS:
            raise ValueError("invalid_log_level")
        config.app_log_min_level = app_log_min_level
    if hec_enabled is not None:
        config.hec_enabled = hec_enabled
    if hec_send_app_logs is not None:
        config.hec_send_app_logs = hec_send_app_logs
    if hec_send_audit_logs is not None:
        config.hec_send_audit_logs = hec_send_audit_logs
    if hec_url is not None:
        config.hec_url = hec_url
    if hec_token:
        config.hec_token_encrypted, config.hec_token_wrap_meta = _encrypt_secret(hec_token)
    if hec_source is not None:
        config.hec_source = hec_source
    if hec_sourcetype is not None:
        config.hec_sourcetype = hec_sourcetype
    if hec_index is not None:
        config.hec_index = hec_index
    if hec_verify_tls is not None:
        config.hec_verify_tls = hec_verify_tls
    if syslog_enabled is not None:
        config.syslog_enabled = syslog_enabled
    if syslog_send_app_logs is not None:
        config.syslog_send_app_logs = syslog_send_app_logs
    if syslog_send_audit_logs is not None:
        config.syslog_send_audit_logs = syslog_send_audit_logs
    if syslog_host is not None:
        config.syslog_host = syslog_host
    if syslog_port is not None:
        config.syslog_port = syslog_port
    if syslog_protocol is not None:
        if syslog_protocol not in SYSLOG_PROTOCOLS:
            raise ValueError("invalid_syslog_protocol")
        config.syslog_protocol = syslog_protocol
    if syslog_facility is not None:
        config.syslog_facility = syslog_facility
    config.updated_at = utcnow()
    db.commit()
    _refresh_cache(config)
    return config


def _refresh_cache(config: LogForwardingConfig) -> None:
    with _cache_lock:
        global _cached_config
        _cached_config = config


def _get_cached_config() -> LogForwardingConfig | None:
    with _cache_lock:
        return _cached_config


# --- HEC ---------------------------------------------------------------


def send_hec_event(config: LogForwardingConfig, event: dict[str, Any]) -> None:
    if not config.hec_url or not config.hec_token_encrypted:
        raise ForwardingError("hec_not_configured")
    token = _decrypt_secret(config.hec_token_encrypted, config.hec_token_wrap_meta)

    body: dict[str, Any] = {
        "time": utcnow().timestamp(),
        "host": settings.app_hostname,
        "source": config.hec_source or "capki",
        "sourcetype": config.hec_sourcetype or "_json",
        "event": event,
    }
    if config.hec_index:
        body["index"] = config.hec_index

    request = urllib.request.Request(
        config.hec_url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Splunk {token}", "Content-Type": "application/json"},
        method="POST",
    )
    ctx = None
    if not config.hec_verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=10, context=ctx) as response:
            if response.status >= 300:
                raise ForwardingError(f"hec_send_failed:{response.status}")
    except urllib.error.HTTPError as exc:
        raise ForwardingError(f"hec_send_failed:{exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ForwardingError(f"hec_send_failed:{exc.reason}") from exc


# --- Syslog (RFC 5424 framing, JSON message body) -----------------------


def _build_syslog_line(config: LogForwardingConfig, event: dict[str, Any], severity: int, msgid: str) -> bytes:
    pri = config.syslog_facility * 8 + severity
    timestamp = utcnow().isoformat()
    hostname = settings.app_hostname or socket.gethostname()
    pid = os.getpid()
    msg = json.dumps(event)
    line = f"<{pri}>1 {timestamp} {hostname} capki {pid} {msgid[:32]} - {msg}\n"
    return line.encode("utf-8")


def send_syslog_event(config: LogForwardingConfig, event: dict[str, Any], severity: int, msgid: str) -> None:
    if not config.syslog_host:
        raise ForwardingError("syslog_not_configured")
    payload = _build_syslog_line(config, event, severity, msgid)

    try:
        if config.syslog_protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.settimeout(5)
                sock.sendto(payload, (config.syslog_host, config.syslog_port))
            finally:
                sock.close()
        else:
            raw = socket.create_connection((config.syslog_host, config.syslog_port), timeout=5)
            try:
                sock = raw
                if config.syslog_protocol == "tcp_tls":
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(raw, server_hostname=config.syslog_host)
                sock.sendall(payload)
            finally:
                sock.close()
    except OSError as exc:
        raise ForwardingError(f"syslog_send_failed:{exc}") from exc


# --- Background worker ---------------------------------------------------


def _enqueue(stream: str, event: dict[str, Any], severity: int) -> None:
    """Non-blocking. `stream` is "app" or "audit". Cheap no-op if
    forwarding is entirely unconfigured, so this is safe to call
    unconditionally from hot paths."""
    config = _get_cached_config()
    if config is None or not (config.hec_enabled or config.syslog_enabled):
        return
    try:
        _queue.put_nowait((stream, event, severity))
    except queue.Full:
        global _dropped_count
        with _dropped_lock:
            _dropped_count += 1
            if _dropped_count % 100 == 1:
                logger.warning(
                    "log forwarding queue full — dropped %d event(s) so far", _dropped_count
                )


def enqueue_app_log(record: logging.LogRecord) -> None:
    config = _get_cached_config()
    if config is None or not (config.hec_enabled or config.syslog_enabled):
        return
    if record.levelno < getattr(logging, config.app_log_min_level, logging.WARNING):
        return
    event: dict[str, Any] = {
        "timestamp": utcnow().isoformat(),
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
        "module": record.module,
        "func": record.funcName,
        "line": record.lineno,
    }
    if record.exc_info:
        event["exception"] = logging.Formatter().formatException(record.exc_info)
    _enqueue("app", event, _SYSLOG_SEVERITY_BY_LEVELNO.get(record.levelno, 6))


def enqueue_audit_event(
    *,
    timestamp,
    actor_type: str,
    actor_user_id: int | None,
    actor_token_id: int | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    detail: dict | None,
    ip_address: str | None,
    success: bool,
) -> None:
    event = {
        "timestamp": timestamp.isoformat(),
        "actor_type": actor_type,
        "actor_user_id": actor_user_id,
        "actor_token_id": actor_token_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "detail": detail,
        "ip_address": ip_address,
        "success": success,
    }
    _enqueue("audit", event, 6 if success else 4)


class _ForwardingLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            enqueue_app_log(record)
        except Exception:
            pass  # never let logging itself raise


def _worker_loop() -> None:
    while True:
        stream, event, severity = _queue.get()
        config = _get_cached_config()
        if config is None:
            continue
        send_app = config.hec_send_app_logs if stream == "app" else config.hec_send_audit_logs
        if config.hec_enabled and send_app:
            try:
                send_hec_event(config, event)
            except Exception:
                logger.debug("HEC delivery failed", exc_info=True)

        syslog_send = config.syslog_send_app_logs if stream == "app" else config.syslog_send_audit_logs
        if config.syslog_enabled and syslog_send:
            try:
                msgid = event.get("action") or event.get("level") or "applog"
                send_syslog_event(config, event, severity, msgid)
            except Exception:
                logger.debug("Syslog delivery failed", exc_info=True)


_worker_started = False
_worker_lock = threading.Lock()


def start(db: Session) -> None:
    """Call once at process startup: loads the config into cache, attaches
    the logging handler to the "capki" logger namespace (so only capki's
    own loggers are forwarded — not uvicorn's access log or third-party
    libraries), and starts the background delivery thread."""
    global _worker_started
    _refresh_cache(get_log_forwarding_config(db))

    with _worker_lock:
        if _worker_started:
            return
        capki_logger = logging.getLogger("capki")
        if not any(isinstance(h, _ForwardingLogHandler) for h in capki_logger.handlers):
            capki_logger.addHandler(_ForwardingLogHandler())

        thread = threading.Thread(target=_worker_loop, name="log-forwarding", daemon=True)
        thread.start()
        _worker_started = True
