from sqlalchemy.orm import Session

from capki.db.base import utcnow
from capki.db.models.settings import SamlConfig


def get_saml_config(db: Session) -> SamlConfig:
    config = db.get(SamlConfig, 1)
    if config is None:
        config = SamlConfig(id=1, enabled=False, updated_at=utcnow())
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


def update_saml_config(db: Session, **fields) -> SamlConfig:
    config = get_saml_config(db)
    for key, value in fields.items():
        if value is not None:
            setattr(config, key, value)
    config.updated_at = utcnow()
    db.commit()
    return config
