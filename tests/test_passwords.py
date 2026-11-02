import unittest

from universal_auth.security.passwords import (
    hash_password,
    verify_password
)


class TestPasswordSecurity(unittest.TestCase):

    def test_password_hashing(self):
        password = "MySecurePassword123!"

        hashed_password = hash_password(password)

        self.assertNotEqual(password, hashed_password)
        self.assertTrue(
            verify_password(password, hashed_password)
        )

    def test_wrong_password(self):
        password = "MySecurePassword123!"

        hashed_password = hash_password(password)

        self.assertFalse(
            verify_password("WrongPassword123!", hashed_password)
        )


if __name__ == "__main__":
    unittest.main()
