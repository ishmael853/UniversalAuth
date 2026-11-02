
import re
import unittest
from unittest.mock import patch
from universal_auth.services.session_service import (
    create_session,
    get_session
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base
from universal_auth.services.auth_service import register_user, verify_user_email
from universal_auth.services.password_reset_service import (
    request_password_reset,
    reset_password
)
from universal_auth.services.auth_service import authenticate_user


class TestPasswordReset(unittest.TestCase):

    def setUp(self):
        self.email_patcher = patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        )
        self.mock_registration_email = self.email_patcher.start()

        self.reset_email_patcher = patch(
            "universal_auth.services.password_reset_service.send_email",
            return_value=True
        )
        self.mock_reset_email = self.reset_email_patcher.start()

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()

        # Register and verify a test user.
        self.user = register_user(
            self.db,
            "testuser",
            "test@example.com",
            "OldPassword123!"
        )

        registration_body = (
            self.mock_registration_email.call_args.kwargs["body"]
        )

        registration_code = re.search(
            r"verification code is: (\d{6})",
            registration_body
        ).group(1)

        verify_user_email(
            self.db,
            self.user.id,
            registration_code
        )

    def tearDown(self):
        self.email_patcher.stop()
        self.reset_email_patcher.stop()
        self.db.close()
        self.engine.dispose()

    def get_reset_code(self):
        email_body = self.mock_reset_email.call_args.kwargs["body"]

        match = re.search(
            r"password reset code is: (\d{6})",
            email_body
        )

        self.assertIsNotNone(match)

        return match.group(1)

    def test_password_reset_request(self):
        result = request_password_reset(
            self.db,
            "test@example.com"
        )

        self.assertTrue(result)
        self.mock_reset_email.assert_called_once()

    def test_successful_password_reset(self):
        request_password_reset(
            self.db,
            "test@example.com"
        )

        code = self.get_reset_code()

        result = reset_password(
            self.db,
            self.user.id,
            code,
            "NewPassword123!"
        )

        self.assertTrue(result)

        # New password should work.
        user = authenticate_user(
            self.db,
            "testuser",
            "NewPassword123!"
        )

        self.assertIsNotNone(user)

        # Old password should no longer work.
        old_user = authenticate_user(
            self.db,
            "testuser",
            "OldPassword123!"
        )

        self.assertIsNone(old_user)

    def test_password_reset_revokes_existing_sessions(self):
        token = create_session(
            self.db,
            self.user.id
        )

        self.assertIsNotNone(get_session(self.db, token))

        request_password_reset(
            self.db,
            "test@example.com"
        )

        code = self.get_reset_code()

        result = reset_password(
            self.db,
            self.user.id,
            code,
            "NewPassword123!"
        )

        self.assertTrue(result)
        self.assertIsNone(get_session(self.db, token))

    def test_invalid_reset_code(self):
        request_password_reset(
            self.db,
            "test@example.com"
        )

        result = reset_password(
            self.db,
            self.user.id,
            "000000",
            "NewPassword123!"
        )

        self.assertFalse(result)

        # Old password should remain valid.
        user = authenticate_user(
            self.db,
            "testuser",
            "OldPassword123!"
        )

        self.assertIsNotNone(user)

    def test_password_reset_code_cannot_be_reused(self):
        request_password_reset(
            self.db,
            "test@example.com"
        )

        code = self.get_reset_code()

        first_result = reset_password(
            self.db,
            self.user.id,
            code,
            "NewPassword123!"
        )

        second_result = reset_password(
            self.db,
            self.user.id,
            code,
            "AnotherPassword123!"
        )

        self.assertTrue(first_result)
        self.assertFalse(second_result)

    def test_short_password_is_rejected(self):
        request_password_reset(
            self.db,
            "test@example.com"
        )

        code = self.get_reset_code()

        with self.assertRaises(ValueError):
            reset_password(
                self.db,
                self.user.id,
                code,
                "short"
            )


if __name__ == "__main__":
    unittest.main()

