"""
UniversalAuth - Basic Usage Example

Demonstrates:
- Database initialization
- User registration
- Email verification
- User login
- Session creation
"""

from getpass import getpass

from universal_auth import (
    register_user,
    verify_user_email,
    login_user,
)

from universal_auth.database.connection import (
    create_database,
    SessionLocal,
)


def main():
    # Initialize database tables.
    create_database()

    db = SessionLocal()

    try:
        print("\n=== UniversalAuth Basic Example ===\n")

        # Collect registration details.
        username = input("Enter username: ").strip()
        email = input("Enter email: ").strip()
        password = getpass("Enter password: ")

        # Register user.
        user = register_user(
            db,
            username=username,
            email=email,
            password=password,
        )

        if not user:
            print("Registration failed.")
            return

        print("\nRegistration successful!")
        print("Check your email for the verification code.")

        # Verify email address.
        code = input("Enter verification code: ").strip()

        verified = verify_user_email(
            db,
            user.id,
            code,
        )

        if not verified:
            print("Email verification failed.")
            return

        print("Email verified successfully!")

        # Log in and create a session.
        result = login_user(
            db,
            username,
            password,
            device_name="Example Computer",
        )

        if not result:
            print("Login failed.")
            return

        print("\nLogin successful!")
        print("New device:", result["new_device"])
        print("Session created successfully!")

        print("\nUniversalAuth example completed successfully.")

    except Exception as error:
        db.rollback()
        print(
            "\nAn error occurred:",
            type(error).__name__,
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()