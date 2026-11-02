
from sqlalchemy import Column, Integer, ForeignKey, Table

from universal_auth.database.connection import Base


# Association table connecting users and roles
user_roles = Table(
    "user_roles",
    Base.metadata,

    Column(
        "user_id",
        Integer,
        ForeignKey("users.id"),
        primary_key=True
    ),

    Column(
        "role_id",
        Integer,
        ForeignKey("roles.id"),
        primary_key=True
    )
)
