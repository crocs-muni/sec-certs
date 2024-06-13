import hashlib
from binascii import unhexlify
from email.encoders import encode_base64

from flask import current_app
from flask_mail import Message as FlaskMessage


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


class Message(FlaskMessage):
    def _mimetext(self, text, subtype="plain"):
        res = super()._mimetext(text, subtype)
        if subtype == "html":
            del res["Content-Transfer-Encoding"]
            encode_base64(res)
        return res
