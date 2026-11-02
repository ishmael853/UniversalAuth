
import unittest
import re
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base
from universal_auth.models.user import User

from universal_auth.security.passwords import verify_password

from universal_auth.services.auth_service import (
    register_user,
    verify_user_email,
    authenticate_user,
    login_user,
    change_password,
    deactivate_account,
    reactivate_account,
    update_username
)

from universal_auth.services.session_service import (
    get_session,
    destroy_session
)


class TestUserRegistration(unittest.TestCase):

    def setUp(self):
        self.email_patcher = patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        )

        self.mock_send_email = self.email_patcher.start()

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()

    def tearDown(self):
        self.email_patcher.stop()
        self.db.close()
        self.engine.dispose()

    def register_verified_user(self, username, email, password):

        user = register_user(
            self.db,
            username,
            email,
            password
        )

        email_body = self.mock_send_email.call_args.kwargs["body"]

        code_match = re.search(
            r"verification code is: (\d{6})",
            email_body
        )

        self.assertIsNotNone(code_match)

        code = code_match.group(1)

        verified = verify_user_email(
            self.db,
            user.id,
            code
        )

        self.assertTrue(verified)

        return user

    # REGISTRATION TESTS

    def test_successful_registration(self):
        user = register_user(
            self.db,
            "testuser",
            "test@example.com",
            "password123"
        )

        self.assertIsNotNone(user)
        self.assertFalse(user.is_email_verified)
        self.assertFalse(user.is_active)

        self.mock_send_email.assert_called_once()

    def test_duplicate_username(self):
        register_user(
            self.db,
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        with self.assertRaises(ValueError):
            register_user(
                self.db,
                "ishmael",
                "another@example.com",
                "AnotherPassword123!"
            )

    # LOGIN TESTS

    def test_successful_login(self):
        self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        user = authenticate_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNotNone(user)
        self.assertEqual(user.username, "ishmael")

    def test_wrong_password(self):
        self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        user = authenticate_user(
            self.db,
            "ishmael",
            "WrongPassword123!"
        )

        self.assertIsNone(user)

    def test_account_lockout(self):
        self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        for _ in range(5):
            authenticate_user(
                self.db,
                "ishmael",
                "WrongPassword123!"
            )

        user = self.db.query(User).filter(
            User.username == "ishmael"
        ).first()

        self.assertEqual(user.failed_login_attempts, 5)
        self.assertIsNotNone(user.locked_until)

        result = authenticate_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNone(result)

    # PASSWORD CHANGE TESTS

    def test_successful_password_change(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "OldPassword123!"
        )

        result = change_password(
            self.db,
            user.id,
            "OldPassword123!",
            "NewPassword123!"
        )

        self.assertTrue(result)

        self.db.refresh(user)

        self.assertTrue(
            verify_password(
                "NewPassword123!",
                user.password_hash
            )
        )

        self.assertIsNotNone(
            authenticate_user(
                self.db,
                "ishmael",
                "NewPassword123!"
            )
        )

        self.assertIsNone(
            authenticate_user(
                self.db,
                "ishmael",
                "OldPassword123!"
            )
        )

    def test_password_change_wrong_current_password(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "OldPassword123!"
        )

        result = change_password(
            self.db,
            user.id,
            "WrongPassword123!",
            "NewPassword123!"
        )

        self.assertFalse(result)

    def test_password_change_rejects_short_password(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "OldPassword123!"
        )

        with self.assertRaises(ValueError):
            change_password(
                self.db,
                user.id,
                "OldPassword123!",
                "short"
            )

    def test_password_change_revokes_existing_sessions(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "OldPassword123!"
        )

        login_result = login_user(
            self.db,
            "ishmael",
            "OldPassword123!"
        )

        self.assertIsNotNone(login_result)

        token = login_result["session_token"]

        result = change_password(
            self.db,
            user.id,
            "OldPassword123!",
            "NewPassword123!"
        )

        self.assertTrue(result)
        self.assertIsNone(get_session(self.db, token))

    # ACCOUNT DEACTIVATION TESTS

    def test_successful_account_deactivation(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = deactivate_account(
            self.db,
            user.id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        self.db.refresh(user)

        self.assertFalse(user.is_active)

    def test_deactivation_rejects_wrong_password(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = deactivate_account(
            self.db,
            user.id,
            "WrongPassword123!"
        )

        self.assertFalse(result)

        self.db.refresh(user)

        self.assertTrue(user.is_active)

    def test_deactivation_revokes_existing_sessions(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        login_result = login_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        token = login_result["session_token"]

        result = deactivate_account(
            self.db,
            user.id,
            "SecurePassword123!"
        )

        self.assertTrue(result)
        self.assertIsNone(get_session(self.db, token))

    def test_deactivated_account_cannot_login(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        deactivate_account(
            self.db,
            user.id,
            "SecurePassword123!"
        )

        result = authenticate_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNone(result)

    # ACCOUNT REACTIVATION TESTS

    def test_successful_account_reactivation(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        deactivate_account(
            self.db,
            user.id,
            "SecurePassword123!"
        )

        result = reactivate_account(
            self.db,
            user.id
        )

        self.assertTrue(result)

        self.db.refresh(user)

        self.assertTrue(user.is_active)

    def test_unverified_account_cannot_be_reactivated(self):
        user = register_user(
            self.db,
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = reactivate_account(
            self.db,
            user.id
        )

        self.assertFalse(result)

        self.db.refresh(user)

        self.assertFalse(user.is_active)

    # USERNAME UPDATE TESTS

    def test_successful_username_update(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = update_username(
            self.db,
            user.id,
            "SecurePassword123!",
            "new_username"
        )

        self.assertTrue(result)

        self.db.refresh(user)

        self.assertEqual(
            user.username,
            "new_username"
        )

    def test_username_update_rejects_wrong_password(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = update_username(
            self.db,
            user.id,
            "WrongPassword123!",
            "new_username"
        )

        self.assertFalse(result)

        self.db.refresh(user)

        self.assertEqual(
            user.username,
            "ishmael"
        )

    def test_username_update_rejects_duplicate_username(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        other_user = self.register_verified_user(
            "anotheruser",
            "another@example.com",
            "AnotherPassword123!"
        )

        with self.assertRaises(ValueError):
            update_username(
                self.db,
                user.id,
                "SecurePassword123!",
                other_user.username
            )

        self.db.refresh(user)

        self.assertEqual(
            user.username,
            "ishmael"
        )

    def test_username_update_revokes_existing_sessions(self):
        user = self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        login_result = login_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNotNone(login_result)

        token = login_result["session_token"]

        result = update_username(
            self.db,
            user.id,
            "SecurePassword123!",
            "new_username"
        )

        self.assertTrue(result)

        self.assertIsNone(
            get_session(self.db, token)
        )

    # SESSION TESTS

    def test_login_creates_session(self):
        self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = login_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result["user"].username,
            "ishmael"
        )

        session = get_session(
            self.db,
            result["session_token"]
        )

        self.assertIsNotNone(session)

        self.assertEqual(
            session.user_id,
            result["user"].id
        )

    def test_logout_destroys_session(self):
        self.register_verified_user(
            "ishmael",
            "ishmael@example.com",
            "SecurePassword123!"
        )

        result = login_user(
            self.db,
            "ishmael",
            "SecurePassword123!"
        )

        self.assertIsNotNone(result)

        token = result["session_token"]

        self.assertTrue(destroy_session(self.db, token))
        self.assertIsNone(get_session(self.db, token))


if __name__ == "__main__":
    unittest.main()
