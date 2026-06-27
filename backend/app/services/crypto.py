"""
Token encryption/decryption using Fernet (symmetric encryption).

Fernet guarantees that a message encrypted with it cannot be manipulated
or read without the key. Access and refresh tokens are always stored
encrypted in the database and decrypted only when needed for API calls.
"""

import base64
import hashlib

from cryptography.fernet import Fernet

from app.config import settings


def _get_fernet() -> Fernet:
    # Derive a URL-safe 32-byte base64 key from the secret key.
    # hashlib.sha256 produces exactly 32 bytes.
    raw = hashlib.sha256(settings.secret_key.encode()).digest()
    key = base64.urlsafe_b64encode(raw)
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    """Encrypt a plaintext string. Returns base64-encoded ciphertext."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt a ciphertext string. Returns the original plaintext."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
