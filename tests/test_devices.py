
import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from universal_auth.services.device_service import revoke_all_devices
from universal_auth.database.connection import Base
from universal_auth.models.user import User
from universal_auth.models.device import Device
from universal_auth.services.device_service import (
    generate_device_token,
    hash_device_token,
    register_device,
    get_device,
    revoke_device
)
from unittest.mock import patch
from universal_auth.services.auth_service import (
    login_user,
    verify_user_email
)
from universal_auth.services.verification_service import create_verification
from universal_auth.security.passwords import hash_password
from universal_auth.services.device_service import list_user_devices
from universal_auth.services.session_service import (
    create_session,
    get_session
)


class TestDeviceManagement(unittest.TestCase):

    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=self.engine)

        TestingSession = sessionmaker(bind=self.engine)
        self.db = TestingSession()


        self.user = User(
            username="testuser",
            email="test@example.com",
            password_hash=hash_password("test_password"),
            is_active=True,
            is_email_verified=True
        )

        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

    def tearDown(self):
        self.db.close()
        self.engine.dispose()

    def test_device_token_generation(self):
        token1 = generate_device_token()
        token2 = generate_device_token()

        self.assertIsInstance(token1, str)
        self.assertNotEqual(token1, token2)

    def test_device_token_hashing(self):
        token = generate_device_token()

        hashed_token = hash_device_token(token)

        self.assertNotEqual(token, hashed_token)
        self.assertEqual(len(hashed_token), 64)

    def test_register_device(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = self.db.query(Device).filter(
            Device.user_id == self.user.id
        ).first()

        self.assertIsNotNone(device)
        self.assertEqual(device.device_name, "Windows Laptop")
        self.assertNotEqual(device.device_token_hash, token)
        self.assertEqual(
            device.device_token_hash,
            hash_device_token(token)
        )

    def test_recognize_registered_device(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = get_device(
            self.db,
            self.user.id,
            token
        )

        self.assertIsNotNone(device)
        self.assertEqual(device.device_name, "Windows Laptop")

    def test_unknown_device(self):
        device = get_device(
            self.db,
            self.user.id,
            generate_device_token()
        )

        self.assertIsNone(device)

    def test_revoke_device(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = self.db.query(Device).filter(
            Device.user_id == self.user.id
        ).first()

        result = revoke_device(
            self.db,
            self.user.id,
            device.id
        )

        self.assertTrue(result)

        # A revoked device should no longer be recognized.
        recognized_device = get_device(
            self.db,
            self.user.id,
            token
        )

        self.assertIsNone(recognized_device)

    
    def test_first_login_registers_new_device(self):
        # Authenticate the test user through the login service.
        with patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        ) as mock_email:

            result = login_user(
                self.db,
                "testuser",
                "test_password",
                device_name="Windows Laptop"
            )

        self.assertIsNotNone(result)
        self.assertTrue(result["new_device"])
        self.assertIsNotNone(result["device_token"])
        mock_email.assert_called_once()

        device = get_device(
            self.db,
            self.user.id,
            result["device_token"]
        )

        self.assertIsNotNone(device)

    def test_returning_device_is_recognized(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        with patch(
            "universal_auth.services.auth_service.send_email"
        ) as mock_email:

            result = login_user(
                self.db,
                "testuser",
                "test_password",
                device_token=token,
                device_name="Windows Laptop"
            )

        self.assertIsNotNone(result)
        self.assertFalse(result["new_device"])
        self.assertEqual(result["device_token"], token)
        mock_email.assert_not_called()

    def test_new_device_gets_separate_registration(self):
        first_token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        with patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        ) as mock_email:

            result = login_user(
                self.db,
                "testuser",
                "test_password",
                device_name="Android Phone"
            )

        self.assertIsNotNone(result)
        self.assertTrue(result["new_device"])
        self.assertNotEqual(
            result["device_token"],
            first_token
        )

        self.assertEqual(
            self.db.query(Device).filter(
                Device.user_id == self.user.id
            ).count(),
            2
        )

        mock_email.assert_called_once()

    def test_list_user_devices(self):
        register_device(self.db, self.user.id, "Windows Laptop")
        register_device(self.db, self.user.id, "Android Phone")

        devices = list_user_devices(self.db, self.user.id)

        self.assertEqual(len(devices), 2)

    def test_list_user_devices_includes_revoked(self):
        token = register_device(
            self.db, self.user.id, "Windows Laptop"
        )

        device = get_device(self.db, self.user.id, token)
        revoke_device(self.db, self.user.id, device.id)

        devices = list_user_devices(self.db, self.user.id)

        self.assertEqual(len(devices), 1)
        self.assertFalse(devices[0].is_active)

    def test_list_user_devices_does_not_show_other_users(self):
        devices = list_user_devices(self.db, 999)

        self.assertEqual(len(devices), 0)

    def test_revoke_all_devices(self):
        register_device(self.db, self.user.id, "Windows Laptop")
        register_device(self.db, self.user.id, "Android Phone")

        revoked_count = revoke_all_devices(self.db, self.user.id)

        self.assertEqual(revoked_count, 2)

        devices = list_user_devices(self.db, self.user.id)

        for device in devices:
            self.assertFalse(device.is_active)

    def test_revoke_all_devices_when_none_are_active(self):
        revoked_count = revoke_all_devices(self.db, 999)

        self.assertEqual(revoked_count, 0)

    def test_revoke_all_devices_does_not_affect_other_users(self):
        register_device(self.db, self.user.id, "Windows Laptop")

        revoked_count = revoke_all_devices(self.db, 999)

        self.assertEqual(revoked_count, 0)

        devices = list_user_devices(self.db, self.user.id)

        self.assertTrue(devices[0].is_active)

    def test_revoked_device_is_not_recognized(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = get_device(self.db, self.user.id, token)

        revoke_device(self.db, self.user.id, device.id)

        recognized_device = get_device(
            self.db,
            self.user.id,
            token
        )

        self.assertIsNone(recognized_device)

    def test_revoked_device_is_treated_as_new_during_login(self):
        old_token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = get_device(
            self.db,
            self.user.id,
            old_token
        )

        revoke_device(self.db, self.user.id, device.id)

        with patch(
            "universal_auth.services.auth_service.send_email",
            return_value=True
        ) as mock_email:

            result = login_user(
                self.db,
                "testuser",
                "test_password",
                device_token=old_token,
                device_name="Windows Laptop"
            )

        self.assertIsNotNone(result)
        self.assertTrue(result["new_device"])
        self.assertNotEqual(result["device_token"], old_token)
        mock_email.assert_called_once()

    def test_revoke_device_invalidates_sessions(self):
        token = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        device = get_device(
            self.db,
            self.user.id,
            token
        )

        session_token = create_session(
            self.db,
            self.user.id,
            device.id
        )

        result = revoke_device(
            self.db,
            self.user.id,
            device.id
        )

        self.assertTrue(result)
        self.assertIsNone(
            get_session(self.db, session_token)
        )

    def test_revoke_all_devices_invalidates_sessions(self):
        token1 = register_device(
            self.db,
            self.user.id,
            "Windows Laptop"
        )

        token2 = register_device(
            self.db,
            self.user.id,
            "Android Phone"
        )

        device1 = get_device(self.db, self.user.id, token1)
        device2 = get_device(self.db, self.user.id, token2)

        session1 = create_session(
            self.db,
            self.user.id,
            device1.id
        )

        session2 = create_session(
            self.db,
            self.user.id,
            device2.id
        )

        revoked_count = revoke_all_devices(
            self.db,
            self.user.id
        )

        self.assertEqual(revoked_count, 2)

        self.assertIsNone(get_session(self.db, session1))
        self.assertIsNone(get_session(self.db, session2))



            






if __name__ == "__main__":
    unittest.main()
