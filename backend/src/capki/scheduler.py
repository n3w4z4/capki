"""In-process background jobs (APScheduler) — no separate worker process,
per the single-simple-process mandate."""

import datetime as dt
import logging

from apscheduler.schedulers.background import BackgroundScheduler

from capki.config import settings
from capki.core.crypto.key_vault import key_vault
from capki.db.base import utcnow
from capki.db.models.audit import ActorType
from capki.db.models.ca import CaStatus, CertificateAuthority
from capki.db.models.certificates import Certificate, CertificateStatus
from capki.db.session import SessionLocal
from capki.services import revocation_service
from capki.services.audit_service import log_action

logger = logging.getLogger(__name__)

EXPIRY_WARNING_WINDOW_DAYS = 30


def _check_root_auto_relock() -> None:
    unlocked_at = key_vault.root_unlocked_at
    if unlocked_at is None:
        return
    idle_seconds = (utcnow() - unlocked_at).total_seconds()
    if idle_seconds >= settings.root_ca_auto_relock_minutes * 60:
        logger.info("Auto-relocking root CA after %s minutes", settings.root_ca_auto_relock_minutes)
        key_vault.lock_root()


def _refresh_all_crls() -> None:
    """Rolls `next_update` forward for every active CA's CRL, independent of
    new revocations. Best-effort: a CA whose key isn't currently available
    (e.g. a locked root) is silently skipped this cycle."""
    db = SessionLocal()
    try:
        cas = db.query(CertificateAuthority).filter(CertificateAuthority.status == CaStatus.ACTIVE).all()
        for ca in cas:
            issuance = revocation_service.refresh_crl(db, ca)
            if issuance is None:
                logger.debug("Skipped CRL refresh for CA %s (issuer key unavailable)", ca.id)
    finally:
        db.close()


def _check_expiring_certs() -> None:
    """Logs an audit-log entry (visible in the UI's Audit Log tab) for every
    valid leaf cert and active CA expiring within EXPIRY_WARNING_WINDOW_DAYS.
    No email/SMTP integration in v1 — this is the simplest thing that makes
    upcoming expiry actually visible to whoever's watching the UI/logs."""
    db = SessionLocal()
    try:
        cutoff = utcnow() + dt.timedelta(days=EXPIRY_WARNING_WINDOW_DAYS)

        expiring_certs = (
            db.query(Certificate)
            .filter(Certificate.status == CertificateStatus.VALID, Certificate.not_after <= cutoff)
            .all()
        )
        for cert in expiring_certs:
            logger.warning("Certificate %s (%s) expires at %s", cert.id, cert.subject_dn, cert.not_after)
            log_action(
                db,
                actor_type=ActorType.SYSTEM,
                action="cert.expiry_warning",
                target_type="certificate",
                target_id=str(cert.id),
                detail={"subject_dn": cert.subject_dn, "not_after": cert.not_after.isoformat()},
            )

        expiring_cas = (
            db.query(CertificateAuthority)
            .filter(CertificateAuthority.status == CaStatus.ACTIVE, CertificateAuthority.not_after <= cutoff)
            .all()
        )
        for ca in expiring_cas:
            logger.warning("CA %s (%s) expires at %s", ca.id, ca.name, ca.not_after)
            log_action(
                db,
                actor_type=ActorType.SYSTEM,
                action="ca.expiry_warning",
                target_type="certificate_authority",
                target_id=str(ca.id),
                detail={"name": ca.name, "not_after": ca.not_after.isoformat()},
            )
    finally:
        db.close()


def start_scheduler() -> BackgroundScheduler:
    scheduler = BackgroundScheduler()
    scheduler.add_job(_check_root_auto_relock, "interval", minutes=1, id="root_auto_relock")
    scheduler.add_job(_refresh_all_crls, "interval", hours=6, id="crl_refresh")
    scheduler.add_job(_check_expiring_certs, "interval", hours=24, id="expiry_check")
    scheduler.start()
    return scheduler
