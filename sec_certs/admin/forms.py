from wtforms import validators, StringField, PasswordField, BooleanField
from flask_wtf import FlaskForm


class LoginForm(FlaskForm):
    username = StringField("username", [validators.DataRequired(), validators.Length(min=3, max=32)])
    password = PasswordField("password", [validators.DataRequired()])
    remember_me = BooleanField("remember_me", default=True)
