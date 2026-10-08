"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """CyberShield configuration loaded from environment or .env file."""

    APP_NAME: str = "CyberShield"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    HOST: str = "0.0.0.0"
    PORT: int = 8000

    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"
    DATABASE_URL: str = "sqlite:///./data/cybershield.db"

    # JWT Authentication Settings
    JWT_SECRET_KEY: str = "cybershield-dev-secret-key-change-in-production-min-32-chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # File Integrity Monitoring (FIM) Settings
    FIM_ALLOWED_ROOTS: str = "./monitored,./data"
    FIM_MAX_FILE_SIZE_BYTES: int = 104857600  # 100 MB max per file
    FIM_MAX_FILES_PER_BASELINE: int = 1000  # Maximum files in a single directory baseline

    # Defensive Log Analyzer Settings
    LOG_ALLOWED_ROOTS: str = "./logs,./data/logs"
    LOG_MAX_FILE_SIZE_BYTES: int = 52428800  # 50 MB max per log file
    LOG_MAX_LINE_LENGTH: int = 4096  # Max line length to prevent ReDoS / memory exhaustion
    LOG_MAX_LINES_PER_RUN: int = 50000  # Cap on lines processed in a single run
    LOG_BRUTE_FORCE_THRESHOLD: int = 5  # Failures before triggering High finding
    LOG_BRUTE_FORCE_WINDOW_SECONDS: int = 300  # Correlation sliding window (5 min)

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origins_list(self) -> List[str]:
        """Return CORS origins as a list of strings."""
        if isinstance(self.CORS_ORIGINS, str):
            return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
        return ["*"]

    @property
    def fim_allowed_roots_list(self) -> List[str]:
        """Return list of authorized FIM monitoring roots as absolute strings."""
        from pathlib import Path

        roots: List[str] = []
        if isinstance(self.FIM_ALLOWED_ROOTS, str):
            for r in self.FIM_ALLOWED_ROOTS.split(","):
                cleaned = r.strip()
                if cleaned:
                    resolved = str(Path(cleaned).resolve())
                    if resolved not in roots:
                        roots.append(resolved)
        return roots

    @property
    def log_allowed_roots_list(self) -> List[str]:
        """Return list of authorized Log monitoring roots as absolute strings."""
        from pathlib import Path

        roots: List[str] = []
        if isinstance(self.LOG_ALLOWED_ROOTS, str):
            for r in self.LOG_ALLOWED_ROOTS.split(","):
                cleaned = r.strip()
                if cleaned:
                    resolved = str(Path(cleaned).resolve())
                    if resolved not in roots:
                        roots.append(resolved)
        return roots


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton instance."""
    return Settings()
