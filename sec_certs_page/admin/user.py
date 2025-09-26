from typing import List
from datetime import datetime, timedelta
import secrets

from flask_login import UserMixin, current_user
from flask_principal import RoleNeed, UserNeed, identity_loaded
from werkzeug.security import check_password_hash, generate_password_hash

from .. import app, login, mongo


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256:1000")


class User(UserMixin):
    def __init__(self, username: str, pwhash: str, email: str, roles: List[str], 
                 email_confirmed: bool = False, created_at: datetime = None):
        self.username = username
        self.pwhash = pwhash
        self.email = email
        self.roles = roles
        self.email_confirmed = email_confirmed
        self.created_at = created_at or datetime.utcnow()

    def check_password(self, password):
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
        }

    @property
    def id(self):
        return self.username

    def save(self):
        """Save or update user in database"""
        mongo.db.users.update_one(
            {"username": self.username},
            {"$set": self.dict},
            upsert=True
        )

    def confirm_email(self):
        """Mark email as confirmed"""
        self.email_confirmed = True
        self.save()

    def set_password(self, password):
        """Set new password"""
        self.pwhash = hash_password(password)
        self.save()

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
            doc.get("created_at", datetime.utcnow())
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
            doc.get("created_at", datetime.utcnow())
        )

    @staticmethod
    def create(username: str, email: str, password: str, roles: List[str] = None):
        """Create a new user"""
        if roles is None:
            roles = []
        
        if User.get(username) or User.get_by_email(email):
            return None  # User already exists
        
        user = User(
            username=username,
            pwhash=hash_password(password),
            email=email,
            roles=roles,
            email_confirmed=False,
            created_at=datetime.utcnow()
        )
        user.save()
        return user

    @staticmethod
    def generate_confirmation_token(user_id: str) -> str:
        """Generate email confirmation token"""
        token = secrets.token_urlsafe(32)
        mongo.db.email_tokens.insert_one({
            "token": token,
            "user_id": user_id,
            "type": "email_confirmation",
            "expires_at": datetime.utcnow() + timedelta(hours=24),
            "created_at": datetime.utcnow()
        })
        return token

    @staticmethod
    def generate_password_reset_token(user_id: str) -> str:
        """Generate password reset token"""
        token = secrets.token_urlsafe(32)
        mongo.db.email_tokens.insert_one({
            "token": token,
            "user_id": user_id,
            "type": "password_reset",
            "expires_at": datetime.utcnow() + timedelta(hours=1),
            "created_at": datetime.utcnow()
        })
        return token

    @staticmethod
    def generate_magic_link_token(user_id: str) -> str:
        """Generate magic link login token"""
        token = secrets.token_urlsafe(32)
        mongo.db.email_tokens.insert_one({
            "token": token,
            "user_id": user_id,
            "type": "magic_link",
            "expires_at": datetime.utcnow() + timedelta(minutes=15),
            "created_at": datetime.utcnow()
        })
        return token

    @staticmethod
    def verify_token(token: str, token_type: str) -> str:
        """Verify token and return user_id if valid"""
        doc = mongo.db.email_tokens.find_one({
            "token": token,
            "type": token_type,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        if doc:
            # Remove token after use
            mongo.db.email_tokens.delete_one({"_id": doc["_id"]})
            return doc["user_id"]
        return None


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
