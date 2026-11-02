import secrets
import hmac
import hashlib

from universal_auth.config import AuthConfig
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from universal_auth.models.verification import Verification


def generate_verification_code() -> str:
    """Generate a secure six-digit verification code."""

    return f"{secrets.randbelow(1_000_000):06d}"


def hash_verification_code(code: str) -> str:
    """Securely hash a verification code using HMAC-SHA256."""

    secret = AuthConfig.VERIFICATION_CODE_SECRET

    if not secret:
        raise ValueError("VERIFICATION_CODE_SECRET is not configured.")

    return hmac.new(
        secret.encode("utf-8"),
        code.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def verify_verification_code(
    code: str,
    stored_hash: str
) -> bool:
    """Check whether a submitted code matches its stored hash."""

    generated_hash = hash_verification_code(code)

    return hmac.compare_digest(generated_hash, stored_hash)

def create_verification(
    db: Session,
    user_id: int,
    purpose: str
) -> str:
    """Generate a code and store its protected verification record."""

    allowed_purposes = ["email_verification", "password_reset"]

    if purpose not in allowed_purposes:
        raise ValueError("Invalid verification purpose.")

    code = generate_verification_code()
    code_hash = hash_verification_code(code)

    verification = Verification(
        user_id=user_id,
        code_hash=code_hash,
        purpose=purpose,
        expires_at=datetime.now(timezone.utc) + timedelta(
            minutes=AuthConfig.VERIFICATION_CODE_EXPIRY_MINUTES
        )
    )

    db.add(verification)
    db.commit()

    return code

def verify_code(
    db: Session,
    user_id: int,
    code: str,
    purpose: str
) -> bool:
    """Verify a code and enforce expiry and attempt limits."""

    verification = db.query(Verification).filter(
        Verification.user_id == user_id,
        Verification.purpose == purpose,
        Verification.used_at.is_(None)
    ).order_by(
        Verification.created_at.desc()
    ).first()

    if not verification:
        return False

    if verification.failed_attempts >= AuthConfig.MAX_VERIFICATION_ATTEMPTS:
        return False

    now = datetime.now(timezone.utc)
    expires_at = verification.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now >= expires_at:
        return False

    if not verify_verification_code(code, verification.code_hash):
        verification.failed_attempts += 1
        db.commit()
        return False

    verification.used_at = now
    db.commit()

    return True