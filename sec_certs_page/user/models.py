import hashlib
import secrets
from binascii import unhexlify
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from flask import current_app
from flask_login import UserMixin, current_user
from flask_principal import RoleNeed, UserNeed, identity_loaded
from werkzeug.security import check_password_hash, generate_password_hash

from .. import app, login, mongo


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256:1000")


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


def generate_token(username: str, token_type: str, expires: timedelta):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    mongo.db.email_tokens.insert_one(
        {"token": token, "username": username, "type": token_type, "expires_at": now + expires, "created_at": now}
    )
    return token


class UserExistsError(Exception):
    """Raised when a user with the same username or email already exists."""

    pass


class User(UserMixin):
    ROLES = ["admin", "chat"]

    def __init__(
        self,
        username: str,
        pwhash: str,
        email: str,
        roles: List[str],
        email_confirmed: bool = False,
        created_at: Optional[datetime] = None,
        github_id: Optional[str] = None,
    ):
        self.username = username
        self.pwhash = pwhash
        self.email = email
        self.roles = roles
        self.email_confirmed = email_confirmed
        self.created_at = created_at
        self.github_id = github_id

    def check_password(self, password):
        if self.pwhash is None:
            return False
        return check_password_hash(self.pwhash, password)

    @property
    def dict(self):
        return {
            "username": self.username,
            "pwhash": self.pwhash,
            "email": self.email,
            "roles": self.roles,
            "email_confirmed": self.email_confirmed,
            "created_at": self.created_at,
            "github_id": self.github_id,
        }

    @property
    def id(self):
        return self.username

    def save(self):
        """Save or update user in database"""
        mongo.db.users.update_one({"username": self.username}, {"$set": self.dict}, upsert=True)

    def confirm_email(self):
        """Mark email as confirmed"""
        self.email_confirmed = True
        self.save()

    def set_password(self, password):
        """Set new password"""
        self.pwhash = hash_password(password)
        self.save()

    def link_github(self, github_id: str):
        """Link GitHub account"""
        self.github_id = str(github_id)
        self.save()

    def delete(self):
        """Delete user from database"""
        mongo.db.users.delete_one({"username": self.username})

    @staticmethod
    def get(username):
        doc = mongo.db.users.find_one({"username": username})
        if not doc:
            return None
        return User(
            doc["username"],
            doc["pwhash"],
            doc["email"],
            doc["roles"],
            doc.get("email_confirmed", False),
            doc.get("created_at"),
            doc.get("github_id"),
        )

    @staticmethod
    def get_by_email(email):
        doc = mongo.db.users.find_one({"email": email})
        if not doc:
            return None
        return User(
            doc["username"],
            doc["pwhash"],
            doc["email"],
            doc["roles"],
            doc.get("email_confirmed", False),
            doc.get("created_at"),
            doc.get("github_id"),
        )

    @staticmethod
    def get_by_github_id(github_id):
        doc = mongo.db.users.find_one({"github_id": str(github_id)})
        if not doc:
            return None
        return User(
            doc["username"],
            doc["pwhash"],
            doc["email"],
            doc["roles"],
            doc.get("email_confirmed", False),
            doc.get("created_at"),
            doc.get("github_id"),
        )

    @staticmethod
    def create(
        username: str,
        email: str,
        password: Optional[str] = None,
        roles: Optional[List[str]] = None,
        github_id: Optional[str] = None,
    ):
        """Create a new user"""
        if User.get(username) or User.get_by_email(email):
            raise UserExistsError("User with this username or email already exists")

        user = User(
            username=username,
            pwhash=hash_password(password) if password else "",  # Empty password for OAuth users
            email=email,
            roles=roles if roles is not None else [],
            email_confirmed=bool(github_id),  # Auto-confirm OAuth users
            created_at=datetime.now(timezone.utc),
            github_id=github_id,
        )
        user.save()
        return user

    @staticmethod
    def generate_confirmation_token(username: str) -> str:
        """Generate email confirmation token"""
        return generate_token(username, token_type="email_confirmation", expires=timedelta(hours=24))

    @staticmethod
    def generate_password_reset_token(username: str) -> str:
        """Generate password reset token"""
        return generate_token(username, token_type="password_reset", expires=timedelta(hours=1))

    @staticmethod
    def generate_magic_link_token(username: str) -> str:
        """Generate magic link login token"""
        return generate_token(username, token_type="magic_link", expires=timedelta(minutes=15))

    @staticmethod
    def verify_token(token: str, token_type: str) -> Optional["User"]:
        """Verify token and return user_id if valid"""
        doc = mongo.db.email_tokens.find_one(
            {"token": token, "type": token_type, "expires_at": {"$gt": datetime.now(timezone.utc)}}
        )
        if doc:
            return User.get(doc["username"])
        return None

    def consume_token(self, token: str, token_type: str):
        """Consume (delete) a token after use"""
        mongo.db.email_tokens.delete_one({"username": self.username, "token": token, "type": token_type})

    def clear_tokens(self):
        """Clear all tokens for this user (e.g. after password change)"""
        mongo.db.email_tokens.delete_many({"username": self.username})


login.user_loader(User.get)


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, "id"):
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the User model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, "roles"):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role))
