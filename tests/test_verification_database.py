import unittest

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base
from universal_auth.models.user import User
from universal_auth.services.verification_service import (
    create_verification,
    verify_code
)


class TestDatabaseVerification(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()

        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="test_hash"
        )

        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)

        self.user_id = user.id

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_successful_verification(self):
        code = create_verification(
            self.db,
            self.user_id,
            "email_verification"
        )

        result = verify_code(
            self.db,
            self.user_id,
            code,
            "email_verification"
        )

        self.assertTrue(result)

    def test_code_cannot_be_reused(self):
        code = create_verification(
            self.db,
            self.user_id,
            "email_verification"
        )

        verify_code(
            self.db,
            self.user_id,
            code,
            "email_verification"
        )

        result = verify_code(
            self.db,
            self.user_id,
            code,
            "email_verification"
        )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()