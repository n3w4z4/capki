"""Pre-flight step run once before Uvicorn starts (see docker/entrypoint.sh).

Uvicorn needs --ssl-certfile/--ssl-keyfile as process arguments, before the
FastAPI app's own startup/lifespan hooks ever run — so materializing the TLS
listener cert has to happen here, outside the ASGI app, not in main.py.
"""

import logging

from capki.core.crypto.tls_bootstrap import ensure_tls_listener_config, materialize_tls_files
from capki.db.session import SessionLocal

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main() -> None:
    db = SessionLocal()
    try:
        config = ensure_tls_listener_config(db)
        cert_path, key_path = materialize_tls_files(config)
        logger.info("TLS listener ready: cert=%s key=%s source=%s", cert_path, key_path, config.source)
    finally:
        db.close()


if __name__ == "__main__":
    main()
