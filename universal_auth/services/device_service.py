
import secrets
import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from universal_auth.models.device import Device
from sqlalchemy import desc
from universal_auth.services.session_service import revoke_device_sessions


def generate_device_token() -> str:
    """Generate a cryptographically secure device identifier."""

    return secrets.token_urlsafe(32)


def hash_device_token(token: str) -> str:
    """Hash a device identifier before storing it."""

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def get_device(
    db: Session,
    user_id: int,
    device_token: str
):
    """Find an active device belonging to a user."""

    token_hash = hash_device_token(device_token)

    device = db.query(Device).filter(
        Device.user_id == user_id,
        Device.device_token_hash == token_hash,
        Device.is_active.is_(True)
    ).first()

    if device:
        device.last_used_at = datetime.now(timezone.utc)
        db.commit()

    return device


def register_device(
    db: Session,
    user_id: int,
    device_name: str = "Unknown device"
) -> str:
    """Register a new device and return its original token."""

    device_token = generate_device_token()

    new_device = Device(
        user_id=user_id,
        device_token_hash=hash_device_token(device_token),
        device_name=device_name
    )

    db.add(new_device)
    db.commit()

    return device_token

def revoke_device(db: Session, user_id: int, device_id: int) -> bool:
    """Revoke a device and invalidate its active sessions."""

    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == user_id,
        Device.is_active.is_(True)
    ).first()

    if not device:
        return False

    # Invalidate all sessions associated with this device.
    revoke_device_sessions(db, device.id)

    # Mark the device as revoked.
    device.is_active = False
    db.commit()

    return True

def list_user_devices(db: Session, user_id: int):
    devices = db.query(Device).filter(
        Device.user_id == user_id
    ).order_by(
        desc(Device.created_at)
    ).all()

    return devices

def revoke_all_devices(db: Session, user_id: int) -> int:
    """Revoke all active devices and their associated sessions."""

    devices = db.query(Device).filter(
        Device.user_id == user_id,
        Device.is_active.is_(True)
    ).all()

    for device in devices:
        revoke_device_sessions(db, device.id)
        device.is_active = False

    db.commit()

    return len(devices)

