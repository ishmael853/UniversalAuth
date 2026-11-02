from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from universal_auth.database.connection import Base
from universal_auth.models.associations import user_roles
from universal_auth.models.role import Role


class User(Base):
    """Database model representing an authenticated user."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)

    username = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )

    password_hash = Column(String(255), nullable=False)

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )

    is_email_verified = Column(
        Boolean,
        default=False,
        nullable=False
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now()
    )

    failed_login_attempts = Column(
        Integer,
        default=0,
        nullable=False
    )

    locked_until = Column(
        DateTime(timezone=True),
        nullable=True
    )

    # Role-Based Access Control relationship
    roles = relationship(
        "Role",
        secondary=user_roles,
        back_populates="users"
    )
