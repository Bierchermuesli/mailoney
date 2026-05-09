"""
Configuration handling for Mailoney
"""
import os
import logging
from typing import Dict, Any, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)

class Settings(BaseSettings):
    """Application settings"""
    # Server settings
    bind_ip: str = Field(default="0.0.0.0")
    bind_port: int = Field(default=25)
    server_name: str = Field(default="mail.example.com")
    
    # Database settings.
    # An explicitly empty value (MAILONEY_DB_URL=) disables the DB and runs
    # in event-logging-only mode.
    db_url: str = Field(default="sqlite:///mailoney.db")

    # Logging settings
    log_level: str = Field(default="INFO")
    log_json: bool = Field(default=False)
    
    # Configure the settings to use the MAILONEY_ prefix for environment variables
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="MAILONEY_",
        case_sensitive=False,
        extra="ignore"
    )

def get_settings() -> Settings:
    """
    Get application settings
    
    Returns:
        Settings object
    """
    return Settings()

def configure_logging(
    level: Optional[str] = None,
    json_format: Optional[bool] = None,
) -> None:
    """
    Configure the root logger for operational (non-event) log records.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        json_format: When True, every operational record is rendered as
            a JSON Lines object (``{"event": "log", "logger": ...}``).
            When False or None, records render as human-readable text.
            Defaults to ``Settings.log_json`` when omitted.
    """
    if level is None:
        level = get_settings().log_level
    if json_format is None:
        json_format = get_settings().log_json

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    # Lazy import so events.py stays a leaf module (no config dep).
    from .events import JsonOperationalFormatter

    root = logging.getLogger()
    root.setLevel(numeric_level)
    # Replace any existing StreamHandler (e.g. installed by basicConfig)
    # so a second call swaps the formatter instead of stacking handlers.
    for handler in list(root.handlers):
        if isinstance(handler, logging.StreamHandler):
            root.removeHandler(handler)

    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonOperationalFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            )
        )
    root.addHandler(handler)
