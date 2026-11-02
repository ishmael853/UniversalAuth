import smtplib
from email.message import EmailMessage

from universal_auth.config import AuthConfig


def send_email(
    recipient: str,
    subject: str,
    body: str
) -> bool:
    """Send an email using the configured SMTP provider."""

    required_settings = [
        AuthConfig.SMTP_HOST,
        AuthConfig.SMTP_USERNAME,
        AuthConfig.SMTP_PASSWORD,
        AuthConfig.SMTP_FROM_EMAIL
    ]

    if not all(required_settings):
        raise RuntimeError("SMTP settings are not fully configured.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = AuthConfig.SMTP_FROM_EMAIL
    message["To"] = recipient
    message.set_content(body)

    try:
        with smtplib.SMTP(
            AuthConfig.SMTP_HOST,
            AuthConfig.SMTP_PORT
        ) as server:

            server.starttls()

            server.login(
                AuthConfig.SMTP_USERNAME,
                AuthConfig.SMTP_PASSWORD
            )

            server.send_message(message)

        return True

    except (smtplib.SMTPException, OSError):
        return False
    