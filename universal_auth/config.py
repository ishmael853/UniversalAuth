import os
from dotenv import load_dotenv

load_dotenv()

class AuthConfig:
    """central configuration for universal_auth."""

    APP_NAME = "universal_auth"

    # Database configuration
    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "sqlite:///./universalauth.db"
    )

# password security
    PASSWORD_MIN_LENGTH = 8

# login protection
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

# session configuration
    SESSION_TIMEOUT_MINUTES = 30

# Email verification security
    VERIFICATION_CODE_EXPIRY_MINUTES = 10
    MAX_VERIFICATION_ATTEMPTS = 5
    VERIFICATION_RESEND_COOLDOWN_SECONDS = 60 

    VERIFICATION_CODE_SECRET = os.getenv("VERIFICATION_CODE_SECRET")


        # Email delivery configuration
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
    SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")