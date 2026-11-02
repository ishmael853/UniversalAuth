
from sqlalchemy.orm import Session

from universal_auth.models.user import User
from universal_auth.models.verification import Verification
from universal_auth.services.session_service import revoke_user_sessions
from universal_auth.security.passwords import hash_password
from universal_auth.services.verification_service import (
    create_verification,
    verify_code
)
from universal_auth.adapters.email_adapter import send_email
from universal_auth.config import AuthConfig


def request_password_reset(db: Session, email: str) -> bool:
    """Send a password reset verification code to the user's email."""

    user = db.query(User).filter(
        User.email == email
    ).first()

    # Return the same response whether the email exists or not.
    if not user:
        return True

    code = create_verification(
        db,
        user.id,
        "password_reset"
    )

    email_sent = send_email(
        recipient=user.email,
        subject="Password Reset Request",
        body=(
            f"Hello {user.username},\n\n"
            f"Your password reset code is: {code}\n\n"
            "This code expires in "
            f"{AuthConfig.VERIFICATION_CODE_EXPIRY_MINUTES} minutes.\n\n"
            "If you did not request this, please ignore this email."
        )
    )

    if not email_sent:
        raise RuntimeError("Password reset email could not be sent.")

    return True


def reset_password(
    db: Session,
    user_id: int,
    code: str,
    new_password: str
) -> bool:
    """Verify the reset code and update the user's password."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        return False

    if len(new_password) < AuthConfig.PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"Password must contain at least "
            f"{AuthConfig.PASSWORD_MIN_LENGTH} characters."
        )

    verified = verify_code(
        db,
        user_id,
        code,
        "password_reset"
    )

    if not verified:
        return False

    user.password_hash = hash_password(new_password)

    user.failed_login_attempts = 0
    user.locked_until = None

    revoke_user_sessions(db, user.id)

    db.commit()
    
    return True
