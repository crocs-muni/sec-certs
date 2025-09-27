import dramatiq
from flask import render_template, url_for

from .. import mail
from ..notifications import Message
from .models import User


def send_user_email(to_email, subject, template, context):
    """Send user-related emails."""
    msg = Message(
        subject=subject,
        recipients=[to_email],
        html=render_template(template, **context),
    )
    mail.send(msg)


@dramatiq.actor
def send_confirmation_email(username):
    user = User.get(username)
    token = User.generate_confirmation_token(username)
    confirmation_url = url_for("user.confirm_email", token=token, _external=True)
    send_user_email(
        user.email,
        "Confirm your email | sec-certs.org",
        "user/emails/confirm_email.html.jinja2",
        {"user": user, "confirmation_url": confirmation_url},
    )


@dramatiq.actor
def send_password_reset_email(username):
    user = User.get(username)
    token = User.generate_password_reset_token(username)
    reset_url = url_for("user.reset_password", token=token, _external=True)
    send_user_email(
        user.email,
        "Password reset | sec-certs.org",
        "user/emails/reset_password.html.jinja2",
        {"user": user, "reset_url": reset_url},
    )


@dramatiq.actor
def send_magic_link_email(username):
    user = User.get(username)
    token = User.generate_magic_link_token(username)
    login_url = url_for("user.magic_login", token=token, _external=True)

    send_user_email(
        user.email,
        "Login link | sec-certs.org",
        "user/emails/magic_link.html.jinja2",
        {"user": user, "login_url": login_url},
    )
