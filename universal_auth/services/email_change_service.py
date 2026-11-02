
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from universal_auth.config import AuthConfig
from universal_auth.models.user import User
from universal_auth.models.email_change import EmailChange
from universal_auth.models.session import Session as AuthSession

from universal_auth.security.passwords import verify_password

from universal_auth.services.verification_service import (
    generate_verification_code,
    hash_verification_code,
    verify_verification_code
)

from universal_auth.adapters.email_adapter import send_email


def request_email_change(
    db: Session,
    user_id: int,
    current_password: str,
    new_email: str
) -> bool:
    """Request an email change and send verification to the new address."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not user.is_active or not user.is_email_verified:
        return False

    if not verify_password(current_password, user.password_hash):
        return False

    if not isinstance(new_email, str):
        raise ValueError("Email must be a string.")

    new_email = new_email.strip().lower()

    if not new_email or "@" not in new_email:
        raise ValueError("Please provide a valid email address.")

    if len(new_email) > 255:
        raise ValueError("Email cannot exceed 255 characters.")

    if new_email == user.email.lower():
        raise ValueError("New email must be different from the current email.")

    existing_user = db.query(User).filter(
        User.email == new_email
    ).first()

    if existing_user:
        raise ValueError("Email is already registered.")

    code = generate_verification_code()

    email_change = EmailChange(
        user_id=user.id,
        pending_email=new_email,
        code_hash=hash_verification_code(code),
        expires_at=datetime.now(timezone.utc) + timedelta(
            minutes=AuthConfig.VERIFICATION_CODE_EXPIRY_MINUTES
        )
    )

    try:
        # Invalidate previous unused email-change requests.
        db.query(EmailChange).filter(
            EmailChange.user_id == user.id,
            EmailChange.used_at.is_(None)
        ).update(
            {"used_at": datetime.now(timezone.utc)},
            synchronize_session=False
        )

        db.add(email_change)

        email_sent = send_email(
            recipient=new_email,
            subject="Verify Your New Email Address",
            body=(
                f"Hello {user.username},\n\n"
                "You requested to change the email address "
                "associated with your account.\n\n"
                f"Your verification code is: {code}\n\n"
                "This code expires in "
                f"{AuthConfig.VERIFICATION_CODE_EXPIRY_MINUTES} minutes.\n\n"
                "If you did not request this change, please ignore this email."
            )
        )

        if not email_sent:
            raise RuntimeError(
                "Email verification message could not be sent."
            )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return True


def confirm_email_change(
    db: Session,
    user_id: int,
    code: str
) -> bool:
    """Verify the code, update the email, and revoke active sessions."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not user.is_active:
        return False

    email_change = db.query(EmailChange).filter(
        EmailChange.user_id == user_id,
        EmailChange.used_at.is_(None)
    ).order_by(
        EmailChange.created_at.desc()
    ).first()

    if not email_change:
        return False

    if email_change.failed_attempts >= AuthConfig.MAX_VERIFICATION_ATTEMPTS:
        return False

    now = datetime.now(timezone.utc)
    expires_at = email_change.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now >= expires_at:
        return False

    if not verify_verification_code(code, email_change.code_hash):
        email_change.failed_attempts += 1
        db.commit()
        return False

    existing_user = db.query(User).filter(
        User.email == email_change.pending_email,
        User.id != user_id
    ).first()

    if existing_user:
        email_change.used_at = now
        db.commit()
        return False

    try:
        user.email = email_change.pending_email
        user.is_email_verified = True
        email_change.used_at = now

        # Revoke all active sessions after the email change.
        db.query(AuthSession).filter(
            AuthSession.user_id == user_id,
            AuthSession.is_active.is_(True)
        ).update(
            {"is_active": False},
            synchronize_session=False
        )

        db.commit()

    except Exception:
        db.rollback()
        raise

    return True
