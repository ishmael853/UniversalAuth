import unittest

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base
from universal_auth.models.user import User
from universal_auth.models.device import Device

from universal_auth.services.session_service import (
    create_session,
    get_session,
    destroy_session,
    revoke_device_sessions,
    revoke_user_sessions,
    cleanup_sessions
)


class TestSessionManagement(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )

        self.db = TestingSession()

        self.user = User(
            username="sessionuser",
            email="session@example.com",
            password_hash="test_hash",
            is_active=True,
            is_email_verified=True
        )

        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

        self.device = Device(
            user_id=self.user.id,
            device_token_hash="a" * 64,
            device_name="Windows Laptop"
        )

        self.db.add(self.device)
        self.db.commit()
        self.db.refresh(self.device)

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        self.engine.dispose()

    def test_create_session(self):
        token = create_session(self.db, self.user.id)

        self.assertIsNotNone(token)
        self.assertEqual(len(token), 43)

    def test_get_valid_session(self):
        token = create_session(self.db, self.user.id)

        session = get_session(self.db, token)

        self.assertIsNotNone(session)
        self.assertEqual(session.user_id, self.user.id)

    def test_destroy_session(self):
        token = create_session(self.db, self.user.id)

        result = destroy_session(self.db, token)

        self.assertTrue(result)
        self.assertIsNone(get_session(self.db, token))

    def test_invalid_session(self):
        session = get_session(self.db, "invalid-token")

        self.assertIsNone(session)

    def test_expired_session(self):
        token = create_session(self.db, self.user.id)

        session = get_session(self.db, token)

        session.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        self.db.commit()

        result = get_session(self.db, token)

        self.assertIsNone(result)
        self.assertFalse(session.is_active)

    def test_session_linked_to_device(self):
        token = create_session(
            self.db,
            self.user.id,
            self.device.id
        )

        session = get_session(self.db, token)

        self.assertEqual(session.device_id, self.device.id)

    def test_inactive_device_invalidates_session(self):
        token = create_session(
            self.db,
            self.user.id,
            self.device.id
        )

        self.device.is_active = False
        self.db.commit()

        session = get_session(self.db, token)

        self.assertIsNone(session)

        stored_session = self.db.query(
            __import__(
                "universal_auth.models.session",
                fromlist=["Session"]
            ).Session
        ).filter_by(
            token_hash=__import__(
                "hashlib"
            ).sha256(token.encode("utf-8")).hexdigest()
        ).first()

        self.assertFalse(stored_session.is_active)

    def test_revoke_device_sessions(self):
        token1 = create_session(
            self.db,
            self.user.id,
            self.device.id
        )

        token2 = create_session(
            self.db,
            self.user.id,
            self.device.id
        )

        revoked_count = revoke_device_sessions(
            self.db,
            self.device.id
        )

        self.assertEqual(revoked_count, 2)
        self.assertIsNone(get_session(self.db, token1))
        self.assertIsNone(get_session(self.db, token2))

    def test_revoke_user_sessions(self):
        token1 = create_session(
            self.db,
            self.user.id
        )

        token2 = create_session(
            self.db,
            self.user.id
        )

        revoked_count = revoke_user_sessions(
            self.db,
            self.user.id
        )

        self.assertEqual(revoked_count, 2)
        
        self.assertIsNone(get_session(self.db, token1))
        self.assertIsNone(get_session(self.db, token2))

    def test_cleanup_old_inactive_sessions(self):
        token = create_session(
            self.db,
            self.user.id
        )

        session = get_session(self.db, token)

        session.created_at = (
            datetime.now(timezone.utc) - timedelta(days=31)
        )

        session.is_active = False
        self.db.commit()

        deleted_count = cleanup_sessions(self.db)

        self.assertEqual(deleted_count, 1)

        remaining_session = self.db.query(
            __import__(
                "universal_auth.models.session",
                fromlist=["Session"]
            ).Session
        ).filter_by(id=session.id).first()


if __name__ == "__main__":
    unittest.main()