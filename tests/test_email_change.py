
import unittest
import re

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base
from universal_auth.models.user import User
from universal_auth.models.email_change import EmailChange

from universal_auth.services.auth_service import (
    register_user,
    verify_user_email
)

from universal_auth.services.email_change_service import (
    request_email_change,
    confirm_email_change
)

from universal_auth.services.session_service import (
    create_session,
    get_session
)


class TestEmailChange(unittest.TestCase):

    def setUp(self):
        self.email_patcher = patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        )

        self.mock_registration_email = self.email_patcher.start()

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()

        self.user = self.register_verified_user()

    def tearDown(self):
        self.email_patcher.stop()
        self.db.close()
        self.engine.dispose()

    def register_verified_user(self):
        user = register_user(
            self.db,
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        email_body = self.mock_registration_email.call_args.kwargs["body"]

        match = re.search(
            r"verification code is: (\d{6})",
            email_body
        )

        self.assertIsNotNone(match)

        verified = verify_user_email(
            self.db,
            user.id,
            match.group(1)
        )

        self.assertTrue(verified)

        return user

    def request_change(self, new_email="new@example.com"):
        with patch(
            "universal_auth.services.email_change_service.send_email",
            return_value=True
        ) as mock_email:

            result = request_email_change(
                self.db,
                self.user.id,
                "SecurePassword123!",
                new_email
            )

        self.assertTrue(result)

        email_body = mock_email.call_args.kwargs["body"]

        match = re.search(
            r"verification code is: (\d{6})",
            email_body
        )

        self.assertIsNotNone(match)

        return match.group(1)

    # SUCCESSFUL EMAIL CHANGE

    def test_successful_email_change(self):
        code = self.request_change()

        result = confirm_email_change(
            self.db,
            self.user.id,
            code
        )

        self.assertTrue(result)

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "new@example.com"
        )

    # PASSWORD VALIDATION

    def test_email_change_rejects_wrong_password(self):
        result = request_email_change(
            self.db,
            self.user.id,
            "WrongPassword123!",
            "new@example.com"
        )

        self.assertFalse(result)

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "ishmael@example.com"
        )

    # EMAIL VALIDATION

    def test_email_change_rejects_duplicate_email(self):
        other_user = register_user(
            self.db,
            "anotheruser",
            "another@example.com",
            "AnotherPassword123!"
        )

        with self.assertRaises(ValueError):
            request_email_change(
                self.db,
                self.user.id,
                "SecurePassword123!",
                other_user.email
            )

    def test_email_change_rejects_invalid_email(self):
        with self.assertRaises(ValueError):
            request_email_change(
                self.db,
                self.user.id,
                "SecurePassword123!",
                "invalid-email"
            )

    def test_email_change_rejects_same_email(self):
        with self.assertRaises(ValueError):
            request_email_change(
                self.db,
                self.user.id,
                "SecurePassword123!",
                "ishmael@example.com"
            )

    # VERIFICATION TESTS

    def test_email_change_rejects_wrong_code(self):
        self.request_change()

        result = confirm_email_change(
            self.db,
            self.user.id,
            "000000"
        )

        self.assertFalse(result)

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "ishmael@example.com"
        )

    def test_email_change_rejects_expired_code(self):
        code = self.request_change()

        request = self.db.query(EmailChange).filter(
            EmailChange.user_id == self.user.id
        ).first()

        request.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        self.db.commit()

        result = confirm_email_change(
            self.db,
            self.user.id,
            code
        )

        self.assertFalse(result)

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "ishmael@example.com"
        )

    def test_email_change_enforces_maximum_attempts(self):
        self.request_change()

        request = self.db.query(EmailChange).filter(
            EmailChange.user_id == self.user.id
        ).first()

        request.failed_attempts = 5
        self.db.commit()

        result = confirm_email_change(
            self.db,
            self.user.id,
            "123456"
        )

        self.assertFalse(result)

    # SESSION SECURITY

    def test_email_change_revokes_existing_sessions(self):
        session_token = create_session(
            self.db,
            self.user.id
        )

        self.assertIsNotNone(
            get_session(self.db, session_token)
        )

        code = self.request_change()

        result = confirm_email_change(
            self.db,
            self.user.id,
            code
        )

        self.assertTrue(result)

        self.assertIsNone(
            get_session(self.db, session_token)
        )

    # PENDING EMAIL SECURITY

    def test_email_remains_unchanged_until_verified(self):
        self.request_change()

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "ishmael@example.com"
        )

    def test_previous_code_is_invalidated_by_new_request(self):
        first_code = self.request_change(
            "first@example.com"
        )

        second_code = self.request_change(
            "second@example.com"
        )

        first_result = confirm_email_change(
            self.db,
            self.user.id,
            first_code
        )

        self.assertFalse(first_result)

        second_result = confirm_email_change(
            self.db,
            self.user.id,
            second_code
        )

        self.assertTrue(second_result)

        self.db.refresh(self.user)

        self.assertEqual(
            self.user.email,
            "second@example.com"
        )


if __name__ == "__main__":
    unittest.main()
