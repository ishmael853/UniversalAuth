# UniversalAuth Documentation

UniversalAuth is a reusable Python authentication and user management library designed to provide secure, reliable authentication functionality across Python applications.

It provides developers with ready-to-use authentication services, password security, email verification, session management, device recognition, and account management.

## 1. Features

UniversalAuth provides the following features:

- User registration and authentication
- Secure password hashing using Argon2
- Email verification
- Password reset functionality
- Database-backed session management
- Device registration and recognition
- Email change verification
- Account activation and deactivation
- Password changes
- Username updates
- Account deletion
- Role-based access control foundations
- Login attempt protection and temporary account lockout
- Session revocation after sensitive account changes

## 2. Requirements

Before installing UniversalAuth, ensure your environment has:

- Python 3.10 or newer
- SQLAlchemy 2.x
- python-dotenv
- argon2-cffi

## 3. Installation

Install UniversalAuth using pip:

```bash
pip install universal-auth
```

To install a locally built wheel:

```bash
pip install universal_auth-0.1.0-py3-none-any.whl
```

UniversalAuth can also be installed directly from its source distribution.

## 4. Configuration

UniversalAuth uses environment variables for database and email configuration.

Create a `.env` file in your application's working directory.

Example:

```env
DATABASE_URL=sqlite:///./universalauth.db

SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your_email@example.com
SMTP_PASSWORD=your_email_password
SMTP_FROM_EMAIL=your_email@example.com

VERIFICATION_CODE_SECRET=replace_with_a_secure_random_secret
```

Replace the example values with your actual configuration.

**Important security recommendations:**

- Never commit your real `.env` file to a public repository.
- Use a strong, randomly generated verification secret.
- Use secure SMTP credentials.
- Keep database credentials private.
- Use HTTPS when integrating authentication into a web application.

## 5. Importing UniversalAuth

Import the authentication functions directly from the package:

```python
from universal_auth import (
    register_user,
    verify_user_email,
    authenticate_user,
    login_user,
    change_password,
    update_username,
    deactivate_account,
    reactivate_account,
    delete_account,
)
```

Database utilities can be imported separately:

```python
from universal_auth.database.connection import (
    create_database,
    SessionLocal
)
```

## 6. Database Initialization

Initialize the database before using authentication services:

```python
from universal_auth.database.connection import create_database

create_database()
```

UniversalAuth uses SQLAlchemy as its database ORM.

The database initialization process creates the tables required by the library.

These include:

- users
- devices
- sessions
- roles
- user_roles
- verifications
- email_change_requests

## 7. Basic Usage

### 7.1 User Registration

Register a new user using `register_user()`:

```python
from universal_auth import register_user
from universal_auth.database.connection import SessionLocal

db = SessionLocal()

try:
    user = register_user(
        db,
        username="john",
        email="john@example.com",
        password="SecurePassword123!"
    )

    print("User registered:", user.username)

finally:
    db.close()
```

The registration service:

1. Checks whether the username and email are already registered.
2. Hashes the password using Argon2.
3. Creates an inactive, unverified account.
4. Generates an email verification code.
5. Sends the verification code to the user's email address.

### 7.2 Email Verification

Verify the user's email using the code sent during registration:

```python
from universal_auth import verify_user_email
from universal_auth.database.connection import SessionLocal

db = SessionLocal()

try:
    result = verify_user_email(
        db,
        user_id=1,
        code="123456"
    )

    if result:
        print("Email successfully verified.")
    else:
        print("Email verification failed.")

finally:
    db.close()
```

Replace the example user ID and verification code with the actual values.

After successful verification, the account becomes active.

### 7.3 User Authentication

Authenticate a user using their username and password:

```python
from universal_auth import authenticate_user
from universal_auth.database.connection import SessionLocal

db = SessionLocal()

try:
    user = authenticate_user(
        db,
        username="john",
        password="SecurePassword123!"
    )

    if user:
        print("Authentication successful.")
    else:
        print("Invalid credentials or inactive account.")

finally:
    db.close()
```

Authentication also enforces the configured login attempt limit and temporary account lockout.

### 7.4 User Login and Device Recognition

Use `login_user()` to authenticate a user, recognize their device, and create a session:

```python
from universal_auth import login_user
from universal_auth.database.connection import SessionLocal

db = SessionLocal()

try:
    result = login_user(
        db,
        username="john",
        password="SecurePassword123!",
        device_name="Windows Laptop"
    )

    if result:
        print("Login successful.")
        print("Session token:", result["session_token"])
        print("Device token:", result["device_token"])
        print("New device:", result["new_device"])

    else:
        print("Login failed.")

finally:
    db.close()
```

The login response contains:

- `user`: The authenticated user object.
- `session_token`: The newly created session token.
- `device_token`: The device recognition token.
- `new_device`: Indicates whether the device was newly registered.

For subsequent logins from the same device, securely retain and supply its device token:

```python
result = login_user(
    db,
    username="john",
    password="SecurePassword123!",
    device_token="PREVIOUSLY_STORED_DEVICE_TOKEN",
    device_name="Windows Laptop"
)
```

Protect session and device tokens as sensitive credentials. Do not expose them in URLs or logs.

A newly recognized device triggers an email notification.

## 8. Account Management

UniversalAuth provides several account management functions.

### Change Password

```python
from universal_auth import change_password

result = change_password(
    db,
    user_id=1,
    current_password="OldPassword123!",
    new_password="NewPassword123!"
)
```

The function verifies the current password and revokes existing sessions after a successful password change.

### Update Username

```python
from universal_auth import update_username

result = update_username(
    db,
    user_id=1,
    current_password="NewPassword123!",
    new_username="new_username"
)
```

The function checks the current password and prevents duplicate usernames.

### Deactivate Account

```python
from universal_auth import deactivate_account

result = deactivate_account(
    db,
    user_id=1,
    current_password="NewPassword123!"
)
```

Deactivation prevents further authentication and revokes existing sessions.

### Reactivate Account

```python
from universal_auth import reactivate_account

result = reactivate_account(
    db,
    user_id=1
)
```

Only email-verified accounts can be reactivated.

**Security warning:** This function does not independently verify administrator authorization or account ownership. Applications must protect access to it through an appropriate administrator or account-recovery workflow.

### Delete Account

```python
from universal_auth import delete_account

result = delete_account(
    db,
    user_id=1,
    current_password="NewPassword123!"
)
```

Account deletion permanently removes the user's account and associated sessions, devices, verification records, email-change requests, and role assignments.

Shared role records belonging to other users are preserved.

## 9. Security Features

UniversalAuth incorporates several security mechanisms:

- Argon2 password hashing
- Password verification
- Login attempt tracking
- Temporary account lockout
- Email verification codes
- Verification code expiration
- Database-backed session management
- Device registration and recognition
- Session revocation after sensitive account changes
- Password-protected account management operations

Applications should additionally implement secure token storage, HTTPS, authorization checks, input validation, and appropriate access controls.

## 10. Project Structure

The main package is organized into the following modules:

```text
universal_auth/
│
├── adapters/
│   ├── base.py
│   └── email_adapter.py
│
├── database/
│   └── connection.py
│
├── models/
│   ├── associations.py
│   ├── device.py
│   ├── email_change.py
│   ├── role.py
│   ├── session.py
│   ├── user.py
│   └── verification.py
│
├── security/
│   └── passwords.py
│
├── services/
│   ├── auth_service.py
│   ├── device_service.py
│   ├── email_change_service.py
│   ├── password_reset_service.py
│   ├── session_service.py
│   └── verification_service.py
│
├── config.py
└── __init__.py
```

## 11. Testing

UniversalAuth includes automated unit and integration tests.

To run the test suite from the development directory:

```bash
python -m unittest discover -s tests -v
```

The current development test suite contains 85 tests covering authentication, account management, devices, sessions, password security, email changes, and verification.

## 12. License

UniversalAuth is distributed under the MIT License.

Refer to the project's LICENSE file for the complete license terms.

## 13. Project Goal

UniversalAuth aims to simplify authentication development by providing reusable authentication and account management services that can be integrated into different Python applications.

It is designed to serve as a foundation for applications requiring secure user authentication and account management.