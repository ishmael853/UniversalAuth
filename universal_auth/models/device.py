from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Boolean
)
from sqlalchemy.sql import func

from universal_auth.database.connection import Base


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(
        Integer,
        ForeignKey("users.id"),
        nullable=False,
        index=True
    )

    device_token_hash = Column(
        String(64),
        unique=True,
        nullable=False,
        index=True
    )

    device_name = Column(String(150), nullable=True)

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    last_used_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
