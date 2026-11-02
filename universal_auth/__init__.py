"""
UniversalAuth - A reusable Python authentication library.

Provides user authentication, account management,
password security and session management.
"""

__version__ = "0.1.0"

from universal_auth.services.auth_service import (
    register_user,
    verify_user_email,
    authenticate_user,
    login_user,
    deactivate_account,
    reactivate_account,
    change_password,
    update_username,
    delete_account,
)

__all__ = [
    "__version__",
    "register_user",
    "verify_user_email",
    "authenticate_user",
    "login_user",
    "deactivate_account",
    "reactivate_account",
    "change_password",
    "update_username",
    "delete_account",
]
