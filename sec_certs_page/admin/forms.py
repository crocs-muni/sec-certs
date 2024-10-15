from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SelectField, StringField, validators


class LoginForm(FlaskForm):
    username = StringField("username", [validators.DataRequired(), validators.Length(min=3, max=32)])
    password = PasswordField("password", [validators.DataRequired()])
    remember_me = BooleanField("remember_me", default=True)


class ConfigEditForm(FlaskForm):
    key = StringField("key", [validators.DataRequired()])
    value = StringField("value")
    type = SelectField(
        "type",
        [validators.DataRequired()],
        choices=[("string", "String"), ("int", "Int"), ("float", "Float"), ("boolean", "Boolean")],
        default="string",
    )
