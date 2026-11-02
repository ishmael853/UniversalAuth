import unittest

from unittest.mock import patch

from universal_auth.adapters.email_adapter import send_email


class TestEmailAdapter(unittest.TestCase):

    @patch("universal_auth.adapters.email_adapter.AuthConfig")
    def test_missing_smtp_settings(self, mock_config):

        mock_config.SMTP_HOST = None
        mock_config.SMTP_USERNAME = None
        mock_config.SMTP_PASSWORD = None
        mock_config.SMTP_FROM_EMAIL = None

        with self.assertRaises(RuntimeError):
            send_email(
                "test@example.com",
                "Test Email",
                "Testing email delivery."
            )


if __name__ == "__main__":
    unittest.main()