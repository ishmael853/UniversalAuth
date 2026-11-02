import unittest

from universal_auth.services.verification_service import (
    generate_verification_code,
    hash_verification_code,
    verify_verification_code
)


class TestVerificationService(unittest.TestCase):

    def test_code_generation(self):
        code = generate_verification_code()

        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())

    def test_code_hashing(self):
        code = "123456"
        hashed_code = hash_verification_code(code)

        self.assertNotEqual(code, hashed_code)
        self.assertTrue(
            verify_verification_code(code, hashed_code)
        )

    def test_wrong_code(self):
        code = "123456"
        hashed_code = hash_verification_code(code)

        self.assertFalse(
            verify_verification_code("654321", hashed_code)
        )


if __name__ == "__main__":
    unittest.main()