import hashlib
from binascii import unhexlify

from flask import current_app


def derive_secret(*items: str, digest_size: int = 16) -> bytes:
    blake = hashlib.blake2b(
        b"".join(map(lambda x: x.encode("utf-8"), items)),
        key=unhexlify(current_app.config["SECRET_KEY"]),
        digest_size=digest_size,
    )
    return blake.digest()


def derive_token(*items: str, digest_size: int = 16) -> str:
    secret = derive_secret(*items, digest_size=digest_size)
    return secret.hex()
