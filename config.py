"""
Application configuration module.
Loads settings from environment variables with secure defaults.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = Path(__file__).parent


class Config:
    """Base configuration with security defaults."""

    # Secret key for sessions and CSRF
    SECRET_KEY = os.environ.get("SECRET_KEY") or os.urandom(32).hex()

    # Database
    DB_PATH = Path(os.environ.get("DATABASE_PATH", "reviews.db"))

    # Admin credentials (from env, never hardcoded)
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "change-me-immediately")

    # Session security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_ENV") == "production"
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("SESSION_LIFETIME_MINUTES", 60)) * 60

    # Rate limiting
    RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 60))

    # CSRF token expiry (seconds)
    CSRF_TOKEN_EXPIRY = 3600


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True


# Config mapping
config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config():
    """Get the appropriate config based on FLASK_ENV."""
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, config_map["default"])
