
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import relationship

from universal_auth.database.connection import Base
from universal_auth.models.associations import user_roles


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String(50),
        unique=True,
        nullable=False,
        index=True
    )

    description = Column(
        String(255),
        nullable=True
    )

    users = relationship(
        "User",
        secondary=user_roles,
        back_populates="roles"
    )
