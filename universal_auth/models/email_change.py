
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey
)
from sqlalchemy.sql import func

from universal_auth.database.connection import Base


class EmailChange(Base):
    """Store pending email-change verification requests."""

    __tablename__ = "email_change_requests"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    pending_email = Column(
        String(255),
        nullable=False,
        index=True
    )

    code_hash = Column(
        String(255),
        nullable=False
    )

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False
    )

    failed_attempts = Column(
        Integer,
        default=0,
        nullable=False
    )

    used_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )
