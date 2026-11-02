
import unittest
import re

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from universal_auth.database.connection import Base

from universal_auth.models.user import User
from universal_auth.models.role import Role
from universal_auth.models.associations import user_roles
from universal_auth.models.verification import Verification
from universal_auth.models.email_change import EmailChange
from universal_auth.models.device import Device
from universal_auth.models.session import Session as AuthSession

from universal_auth.services.auth_service import (
    register_user,
    verify_user_email,
    delete_account
)

from universal_auth.services.device_service import register_device
from universal_auth.services.session_service import create_session


class TestAccountDeletion(unittest.TestCase):

    def setUp(self):

        self.email_patcher = patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        )

        self.mock_email = self.email_patcher.start()

        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()

        self.user = self.create_verified_user(
            "ishmael",
            "ishmael@example.com"
        )

        self.other_user = self.create_verified_user(
            "anotheruser",
            "another@example.com"
        )

    def tearDown(self):
        self.email_patcher.stop()
        self.db.close()
        self.engine.dispose()

    def create_verified_user(self, username, email):

        user = register_user(
            self.db,
            username,
            email,
            "SecurePassword123!"
        )

        email_body = self.mock_email.call_args.kwargs["body"]

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

    # BASIC ACCOUNT DELETION

    def test_successful_account_deletion(self):

        user_id = self.user.id

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        deleted_user = self.db.query(User).filter(
            User.id == user_id
        ).first()

        self.assertIsNone(deleted_user)

    def test_account_deletion_rejects_wrong_password(self):

        result = delete_account(
            self.db,
            self.user.id,
            "WrongPassword123!"
        )

        self.assertFalse(result)

        existing_user = self.db.query(User).filter(
            User.id == self.user.id
        ).first()

        self.assertIsNotNone(existing_user)

    def test_account_deletion_rejects_nonexistent_user(self):

        result = delete_account(
            self.db,
            99999,
            "SecurePassword123!"
        )

        self.assertFalse(result)

    # SESSION AND DEVICE CLEANUP

    def test_account_deletion_removes_sessions(self):

        user_id = self.user.id

        register_device(
            self.db,
            user_id,
            "Windows Laptop"
        )

        device = self.db.query(Device).filter(
            Device.user_id == user_id
        ).first()

        create_session(
            self.db,
            user_id,
            device.id
        )

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        remaining_sessions = self.db.query(AuthSession).filter(
            AuthSession.user_id == user_id
        ).count()

        self.assertEqual(remaining_sessions, 0)

    def test_account_deletion_removes_devices(self):

        user_id = self.user.id

        register_device(
            self.db,
            user_id,
            "Windows Laptop"
        )

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        remaining_devices = self.db.query(Device).filter(
            Device.user_id == user_id
        ).count()

        self.assertEqual(remaining_devices, 0)

    # VERIFICATION CLEANUP

    def test_account_deletion_removes_verification_records(self):

        user_id = self.user.id

        self.db.add(
            Verification(
                user_id=user_id,
                code_hash="test-verification-hash",
                purpose="email_verification",
                expires_at=datetime.now(timezone.utc) + timedelta(
                    minutes=10
                )
            )
        )

        self.db.commit()

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        remaining = self.db.query(Verification).filter(
            Verification.user_id == user_id
        ).count()

        self.assertEqual(remaining, 0)

    def test_account_deletion_removes_email_change_requests(self):

        user_id = self.user.id

        self.db.add(
            EmailChange(
                user_id=user_id,
                pending_email="pending@example.com",
                code_hash="test-email-change-hash",
                expires_at=datetime.now(timezone.utc) + timedelta(
                    minutes=10
                )
            )
        )

        self.db.commit()

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        remaining = self.db.query(EmailChange).filter(
            EmailChange.user_id == user_id
        ).count()

        self.assertEqual(remaining, 0)

    # ROLE CLEANUP

    def test_account_deletion_removes_role_assignments(self):

        role = Role(
            name="Administrator",
            description="Administrator role"
        )

        self.user.roles.append(role)

        self.db.commit()

        user_id = self.user.id

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        assignments = self.db.execute(
            user_roles.select().where(
                user_roles.c.user_id == user_id
            )
        ).fetchall()

        self.assertEqual(len(assignments), 0)

    def test_account_deletion_preserves_shared_roles(self):

        role = Role(
            name="Administrator",
            description="Administrator role"
        )

        self.user.roles.append(role)
        self.other_user.roles.append(role)

        self.db.commit()

        role_id = role.id
        user_id = self.user.id

        result = delete_account(
            self.db,
            user_id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        preserved_role = self.db.query(Role).filter(
            Role.id == role_id
        ).first()

        self.assertIsNotNone(preserved_role)

        self.assertEqual(
            len(preserved_role.users),
            1
        )

        self.assertEqual(
            preserved_role.users[0].id,
            self.other_user.id
        )

    # OTHER USERS' DATA

    def test_account_deletion_does_not_affect_other_users(self):

        other_user_id = self.other_user.id

        result = delete_account(
            self.db,
            self.user.id,
            "SecurePassword123!"
        )

        self.assertTrue(result)

        preserved_user = self.db.query(User).filter(
            User.id == other_user_id
        ).first()

        self.assertIsNotNone(preserved_user)

        self.assertEqual(
            preserved_user.email,
            "another@example.com"
        )


if __name__ == "__main__":
    unittest.main()
