from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    app_hostname: str = "localhost"
    database_path: Path = Path("/data/app.db")

    # Master key used to auto-unlock the intermediate CA key and the web
    # listener's TLS key on every process start (see key_vault.py). Prefer
    # a file (Docker secret); fall back to an inline env var; if neither is
    # set the app generates one on first boot and persists it here.
    ca_master_key_file: Path = Path("/data/secrets/master.key")
    ca_master_key: str | None = None

    tls_materialized_dir: Path = Path("/run/app-tls")
    tls_listen_port: int = 8443

    initial_admin_username: str | None = None
    initial_admin_password: str | None = None
    initial_admin_password_file: Path | None = None

    session_cookie_name: str = "capki_session"
    session_cookie_secure: bool = True
    session_idle_timeout_minutes: int = 480
    session_absolute_timeout_minutes: int = 1440

    root_ca_auto_relock_minutes: int = 30

    static_dir: Path = Path(__file__).resolve().parent / "static"


settings = Settings()
