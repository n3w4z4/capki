"""The trust store capki uses for its own *outbound* TLS connections
(Telegram, Splunk HEC, TLS syslog, SMTP STARTTLS).

`ssl.create_default_context()` on its own trusts only the OS CA bundle, so a
service sitting behind a private/internal root CA fails verification. This
module layers any operator-added CAs (the `trusted_ca_certs` table, managed
from Settings) on top of the OS defaults.

The enabled CAs are cached in memory as a single concatenated PEM blob,
refreshed on process start and after every add/toggle/delete — same pattern
as `log_forwarding_service`'s config cache. Callers get a fresh
`ssl.SSLContext` per connection via `build_ssl_context()`.
"""

from __future__ import annotations

import logging
import ssl
import threading

from sqlalchemy import select
from sqlalchemy.orm import Session

from capki.db.models.settings import TrustedCaCert

logger = logging.getLogger(__name__)

_cached_pem_blob: str = ""
_cache_lock = threading.Lock()


def load_trusted_ca_pems(db: Session) -> list[str]:
    """The PEM text of every enabled operator-added CA, newest first."""
    rows = db.scalars(
        select(TrustedCaCert).where(TrustedCaCert.enabled).order_by(TrustedCaCert.added_at.desc())
    ).all()
    return [row.certificate_pem for row in rows]


def refresh_cache(db: Session) -> None:
    """Rebuild the in-memory CA blob from the DB. Call on startup and after
    any mutation of `trusted_ca_certs`."""
    blob = "\n".join(pem.strip() for pem in load_trusted_ca_pems(db))
    with _cache_lock:
        global _cached_pem_blob
        _cached_pem_blob = blob


def build_ssl_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> ssl.SSLContext:
    """An `ssl.SSLContext` trusting the OS CA bundle plus every enabled
    operator-added CA. Safe to call on every outbound request."""
    ctx = ssl.create_default_context(purpose)
    with _cache_lock:
        blob = _cached_pem_blob
    if blob:
        try:
            ctx.load_verify_locations(cadata=blob)
        except ssl.SSLError:
            # A malformed stored PEM must not break outbound TLS for
            # everyone — fall back to OS-only trust. Upload validation in
            # trust_service keeps this from happening in practice.
            logger.exception("failed to load operator-added CA certificates; using OS trust only")
    return ctx
