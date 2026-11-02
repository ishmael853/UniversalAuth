
import logging

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from universal_auth.config import AuthConfig

from universal_auth.models.user import User
from universal_auth.models.verification import Verification
from universal_auth.models.email_change import EmailChange
from universal_auth.models.device import Device
from universal_auth.models.session import Session as AuthSession
from universal_auth.models.associations import user_roles

from universal_auth.security.passwords import (
    hash_password,
    verify_password
)

from universal_auth.services.session_service import (
    create_session,
    revoke_user_sessions
)

from universal_auth.services.verification_service import (
    create_verification,
    verify_code
)

from universal_auth.services.device_service import (
    get_device,
    register_device
)

from universal_auth.adapters.email_adapter import send_email


logger = logging.getLogger(__name__)


def register_user(
    db: Session,
    username: str,
    email: str,
    password: str
):
    """Register a new user and send an email verification code."""

    existing_username = db.query(User).filter(
        User.username == username
    ).first()

    if existing_username:
        raise ValueError("Username is already taken.")

    existing_email = db.query(User).filter(
        User.email == email
    ).first()

    if existing_email:
        raise ValueError("Email is already registered.")

    hashed_password = hash_password(password)

    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_password,
        is_active=False,
        is_email_verified=False
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    try:
        code = create_verification(
            db,
            new_user.id,
            "email_verification"
        )

        email_sent = send_email(
            recipient=new_user.email,
            subject="Verify Your Account",
            body=(
                f"Hello {new_user.username},\n\n"
                f"Your email verification code is: {code}\n\n"
                "This code expires in "
                f"{AuthConfig.VERIFICATION_CODE_EXPIRY_MINUTES} minutes.\n\n"
                "If you did not request this, please ignore this email."
            )
        )

        if not email_sent:
            raise RuntimeError(
                "Verification email could not be sent. "
                "Please try again later."
            )

    except Exception:
        db.query(Verification).filter(
            Verification.user_id == new_user.id
        ).delete()

        db.delete(new_user)
        db.commit()
        raise

    return new_user


def verify_user_email(
    db: Session,
    user_id: int,
    code: str
) -> bool:
    """Verify a user's email and activate their account."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or user.is_email_verified:
        return False

    verified = verify_code(
        db,
        user_id,
        code,
        "email_verification"
    )

    if not verified:
        return False

    user.is_email_verified = True
    user.is_active = True

    db.commit()

    return True


def authenticate_user(
    db: Session,
    username: str,
    password: str
):
    """Authenticate a user and enforce temporary account lockout."""

    user = db.query(User).filter(
        User.username == username
    ).first()

    if not user or not user.is_active or not user.is_email_verified:
        return None

    now = datetime.now(timezone.utc)

    if user.locked_until:
        locked_until = user.locked_until

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if now < locked_until:
            return None

        user.locked_until = None
        user.failed_login_attempts = 0

    if not verify_password(password, user.password_hash):
        user.failed_login_attempts += 1

        if (
            user.failed_login_attempts
            >= AuthConfig.MAX_LOGIN_ATTEMPTS
        ):
            user.locked_until = now + timedelta(
                minutes=AuthConfig.LOCKOUT_DURATION_MINUTES
            )

        db.commit()
        return None

    user.failed_login_attempts = 0
    user.locked_until = None

    db.commit()

    return user


def deactivate_account(
    db: Session,
    user_id: int,
    current_password: str
) -> bool:
    """Deactivate an account after verifying the current password."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        return False

    if not verify_password(current_password, user.password_hash):
        return False

    user.is_active = False
    user.failed_login_attempts = 0
    user.locked_until = None

    revoke_user_sessions(db, user_id)

    db.commit()

    return True


def reactivate_account(
    db: Session,
    user_id: int
) -> bool:
    """
    Reactivate an email-verified account.

    This function should only be exposed through an authorized
    administrative or account-recovery workflow.
    """

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not user.is_email_verified:
        return False

    user.is_active = True
    user.failed_login_attempts = 0
    user.locked_until = None

    db.commit()

    return True


def change_password(
    db: Session,
    user_id: int,
    current_password: str,
    new_password: str
) -> bool:
    """Change a user's password and revoke existing sessions."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        return False

    if not verify_password(current_password, user.password_hash):
        return False

    if len(new_password) < AuthConfig.PASSWORD_MIN_LENGTH:
        raise ValueError(
            "New password must contain at least "
            f"{AuthConfig.PASSWORD_MIN_LENGTH} characters."
        )

    user.password_hash = hash_password(new_password)
    user.failed_login_attempts = 0
    user.locked_until = None

    revoke_user_sessions(db, user_id)

    db.commit()

    return True


def update_username(
    db: Session,
    user_id: int,
    current_password: str,
    new_username: str
) -> bool:
    """Update a username after verifying the current password."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        return False

    if not verify_password(current_password, user.password_hash):
        return False

    if not new_username or not new_username.strip():
        raise ValueError("Username cannot be empty.")

    new_username = new_username.strip()

    if len(new_username) > 50:
        raise ValueError("Username cannot exceed 50 characters.")

    existing_user = db.query(User).filter(
        User.username == new_username,
        User.id != user_id
    ).first()

    if existing_user:
        raise ValueError("Username is already taken.")

    user.username = new_username

    revoke_user_sessions(db, user_id)

    db.commit()

    return True


def delete_account(
    db: Session,
    user_id: int,
    current_password: str
) -> bool:
    """Permanently delete a user and their associated account data."""

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user:
        return False

    if not verify_password(current_password, user.password_hash):
        return False

    # Remove sessions before removing devices.
    db.query(AuthSession).filter(
        AuthSession.user_id == user_id
    ).delete(synchronize_session=False)

    # Remove registered devices.
    db.query(Device).filter(
        Device.user_id == user_id
    ).delete(synchronize_session=False)

    # Remove verification records.
    db.query(Verification).filter(
        Verification.user_id == user_id
    ).delete(synchronize_session=False)

    # Remove pending email-change requests.
    db.query(EmailChange).filter(
        EmailChange.user_id == user_id
    ).delete(synchronize_session=False)

    # Remove only this user's role assignments.
    db.execute(
        user_roles.delete().where(
            user_roles.c.user_id == user_id
        )
    )

    # Delete the user without deleting shared role records.
    db.delete(user)

    db.commit()

    return True


def login_user(
    db: Session,
    username: str,
    password: str,
    device_token: str = None,
    device_name: str = "Unknown device"
):
    """Authenticate a user, recognize their device, and create a session."""

    user = authenticate_user(db, username, password)

    if user is None:
        return None

    device = None

    if device_token:
        device = get_device(db, user.id, device_token)

    new_device = device is None

    if new_device:
        device_token = register_device(
            db,
            user.id,
            device_name
        )

        device = get_device(
            db,
            user.id,
            device_token
        )

        try:
            send_email(
                recipient=user.email,
                subject="New Device Login Notification",
                body=(
                    f"Hello {user.username},\n\n"
                    "A new device has successfully logged into "
                    "your account.\n\n"
                    f"Device: {device_name}\n"
                    f"Time: {datetime.now(timezone.utc).isoformat()}\n\n"
                    "If this was not you, please secure your account "
                    "and change your password."
                )
            )

        except Exception:
            logger.warning(
                "New-device notification could not be sent."
            )

    session_token = create_session(
        db,
        user.id,
        device.id
    )

    return {
        "user": user,
        "session_token": session_token,
        "device_token": device_token,
        "new_device": new_device
    }
