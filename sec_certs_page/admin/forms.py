from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, SelectField, StringField, validators
from wtforms.fields import EmailField


class LoginForm(FlaskForm):
    username = StringField("username", [validators.DataRequired(), validators.Length(min=3, max=32)])
    password = PasswordField("password", [validators.DataRequired()])
    remember_me = BooleanField("remember_me", default=True)


class RegisterForm(FlaskForm):
    username = StringField("username", [
        validators.DataRequired(), 
        validators.Length(min=3, max=32),
        validators.Regexp('^[a-zA-Z0-9_]+$', message="Username must contain only letters, numbers and underscores")
    ])
    email = EmailField("email", [validators.DataRequired(), validators.Email()])
    password = PasswordField("password", [
        validators.DataRequired(), 
        validators.Length(min=8, message="Password must be at least 8 characters long")
    ])
    password_confirm = PasswordField("confirm_password", [
        validators.DataRequired(),
        validators.EqualTo('password', message='Passwords must match')
    ])


class PasswordResetRequestForm(FlaskForm):
    email = EmailField("email", [validators.DataRequired(), validators.Email()])


class PasswordResetForm(FlaskForm):
    password = PasswordField("password", [
        validators.DataRequired(), 
        validators.Length(min=8, message="Password must be at least 8 characters long")
    ])
    password_confirm = PasswordField("confirm_password", [
        validators.DataRequired(),
        validators.EqualTo('password', message='Passwords must match')
    ])


class ConfigEditForm(FlaskForm):
    key = StringField("key", [validators.DataRequired()])
    value = StringField("value")
    type = SelectField(
        "type",
        [validators.DataRequired()],
        choices=[("string", "String"), ("int", "Int"), ("float", "Float"), ("boolean", "Boolean")],
        default="string",
    )
