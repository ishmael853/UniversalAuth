from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# now we create the password hashing utility using the argon2 library. 
# This utility will be used to securely hash and verify passwords in our authentication system.

password_hasher = PasswordHasher()

def hash_password(password: str) -> str:
    """convert a plain-text password into a secure hash using argon2."""

    return password_hasher.hash(password)

def verify_password(password: str, hashed_password: str) -> bool:
    """check whether the password matches its stored hash."""

    try:
        return password_hasher.verify(hashed_password, password)

    except (VerifyMismatchError, VerificationError):
        return False
    