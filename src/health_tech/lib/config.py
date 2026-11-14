"""Service settings read from the environment and an optional .env file."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

PRODUCTION_ENV = "prod"


class Settings(BaseSettings):
    """Configuration shared by all services."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = ""
    database_url: str = "sqlite:///./health_tech.db"
    db_host: str = ""
    db_port: int = 5432
    db_user: str = ""
    db_password: str = ""
    db_name: str = "health_tech"
    user_service_port: int = 8080
    auth_service_port: int = 8081
    jwt_secret: str = ""
    mail_backend: str = "smtp"
    smtp_user: str = ""
    smtp_pass: str = ""

    @property
    def is_production(self) -> bool:
        """Report whether ENV is set to prod."""
        return self.env == PRODUCTION_ENV


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings."""
    return Settings()
