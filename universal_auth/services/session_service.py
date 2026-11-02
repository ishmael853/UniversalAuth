import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session as DBSession
from universal_auth.config import AuthConfig
from universal_auth.models.session import Session
from universal_auth.models.device import Device
def hash_session_token(token: str) -> str:
    """Hash a session token before storing it."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: DBSession,
    user_id: int,
    device_id: int = None
) -> str:
    """Create and store a secure database-backed session."""

    session_token = secrets.token_urlsafe(32)

    new_session = Session(
        user_id=user_id,
        device_id=device_id,
        token_hash=hash_session_token(session_token),
        expires_at=datetime.now(timezone.utc) + timedelta(
            minutes=AuthConfig.SESSION_TIMEOUT_MINUTES
        )
    )

    db.add(new_session)
    db.commit()

    return session_token


def get_session(db: DBSession, session_token: str):
    """Retrieve a valid database-backed session."""

    token_hash = hash_session_token(session_token)

    session = db.query(Session).filter(
        Session.token_hash == token_hash,
        Session.is_active.is_(True)
    ).first()

    if not session:
        return None

    if session.device_id is not None:
        device = db.query(Device).filter(
            Device.id == session.device_id,
            Device.user_id == session.user_id,
            Device.is_active.is_(True)
        ).first()

        if not device:
            session.is_active = False
            db.commit()
            return None

    expires_at = session.expires_at

    # SQLite may return a timezone-naive datetime.
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) >= expires_at:
        session.is_active = False
        db.commit()
        return None

    return session


def destroy_session(db: DBSession, session_token: str) -> bool:
    """Invalidate an active session."""

    session = get_session(db, session_token)

    if not session:
        return False

    session.is_active = False
    db.commit()

    return True

def revoke_device_sessions(db: DBSession, device_id: int) -> int:
    """Invalidate all active sessions belonging to a device."""

    sessions = db.query(Session).filter(
        Session.device_id == device_id,
        Session.is_active.is_(True)
    ).all()

    for session in sessions:
        session.is_active = False

    db.commit()

    return len(sessions)

def cleanup_sessions(db: DBSession, retention_days: int = 30) -> int:
    """
    Delete expired or inactive sessions older than the retention period.
    """

    cutoff_date = datetime.now(timezone.utc) - timedelta(
        days=retention_days
    )

    sessions = db.query(Session).filter(
        Session.created_at < cutoff_date,
        (
            (Session.is_active.is_(False)) |
            (Session.expires_at < datetime.now(timezone.utc))
        )
    ).all()

    deleted_count = len(sessions)

    for session in sessions:
        db.delete(session)

    db.commit()

    return deleted_count

def revoke_user_sessions(db: DBSession, user_id: int) -> int:
    """Invalidate all active sessions belonging to a user."""

    sessions = db.query(Session).filter(
        Session.user_id == user_id,
        Session.is_active.is_(True)
    ).all()

    for session in sessions:
        session.is_active = False

    db.commit()

    return len(sessions)