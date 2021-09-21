from flask_login import UserMixin, current_user
from flask_principal import identity_loaded, UserNeed, RoleNeed
from .. import login, app, mongo
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    return generate_password_hash(password, method="pbkdf2:sha256:1000")


class User(UserMixin):
    def __init__(self, username: str, pwhash: str, email: str, roles: list[str]):
        self.username = username
        self.pwhash = pwhash
        self.email = email
        self.roles = roles

    def check_password(self, password):
        return check_password_hash(self.pwhash, password)

    @property
    def dict(self):
        return {"username": self.username,
                "pwhash": self.pwhash,
                "email": self.email,
                "roles": self.roles}

    @property
    def id(self):
        return self.username

    @staticmethod
    def get(username):
        doc = mongo.db.users.find_one({"username": username})
        if not doc:
            return None
        return User(doc["username"], doc["pwhash"], doc["email"], doc["roles"])


login.user_loader(User.get)


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # Add the UserNeed to the identity
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the User model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role))
