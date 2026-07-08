"""
crypto_utils.py — symmetric encryption for at-rest credentials that must
survive across time (unlike the one-off git_token used in a manual scan,
which only ever lives in worker memory and the Redis result backend — see
routers/engagements.py's comment on `task_options`).

Scheduled scans are the first case that genuinely needs this: a recurring
SAST scan against a private repo needs its git_token available every time
it fires, not just once, so it has to be persisted somewhere. Storing it in
plaintext would be a straightforward regression from the existing
not-persisted design; this encrypts it instead.

The Fernet key is derived from settings.jwt_secret via SHA-256 rather than
requiring a brand-new secret to configure. This is a pragmatic choice, not
a purist one — a dedicated, independently-rotatable encryption key would be
better in principle, but this narrowly encrypts one field, and deriving
from an already-required, already-validated-for-length secret means one
fewer thing to configure and one fewer way to misconfigure. If JWT_SECRET
ever rotates, previously-encrypted tokens become undecryptable — scheduled
scans with a stored token would need it re-entered. That's an acceptable
trade-off for how rarely JWT_SECRET should rotate in practice.
"""

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from config import settings


def _fernet() -> Fernet:
    digest = hashlib.sha256(settings.jwt_secret.encode()).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str | None:
    """Returns None (rather than raising) on a bad/rotated key, so a single
    undecryptable scheduled-scan credential degrades to 'run without it'
    rather than crashing the periodic dispatch task for every schedule."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return None
