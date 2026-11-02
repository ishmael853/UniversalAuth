
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from universal_auth.config import AuthConfig


engine = create_engine(
    AuthConfig.DATABASE_URL,
    echo=False,
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


Base = declarative_base()


def get_db():
    """Provide a database session and close it after use."""

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def create_database():
    """Create all registered database tables."""

    from universal_auth.models.user import User
    from universal_auth.models.verification import Verification
    from universal_auth.models.device import Device
    from universal_auth.models.session import Session
    from universal_auth.models.role import Role
    from universal_auth.models.email_change import EmailChange

    Base.metadata.create_all(bind=engine)
