import logging
from datetime import datetime, timezone

import dramatiq
from flask import render_template, url_for
from periodiq import cron

from .. import mail, mongo
from ..common.mail import Message
from .models import User

logger = logging.getLogger(__name__)


def send_user_email(to_email, subject, template_html, template_txt, context):
    """Send user-related emails."""
    msg = Message(
        subject=subject,
        recipients=[to_email],
        html=render_template(template_html, **context),
        body=render_template(template_txt, **context),
    )
    mail.send(msg)


@dramatiq.actor
def send_confirmation_email(username):
    user = User.get(username)
    token = User.generate_confirmation_token(username)
    confirmation_url = url_for("user.confirm_email", token=token, _external=True)
    subject = "Confirm your email | sec-certs.org"

    send_user_email(
        user.email,
        subject,
        "user/email/confirm_email.html.jinja2",
        "user/email/confirm_email.txt.jinja2",
        {"user": user, "confirmation_url": confirmation_url, "subject": subject},
    )


@dramatiq.actor
def send_password_reset_email(username):
    user = User.get(username)
    token = User.generate_password_reset_token(username)
    reset_url = url_for("user.reset_password", token=token, _external=True)
    subject = "Password reset | sec-certs.org"

    send_user_email(
        user.email,
        subject,
        "user/email/reset_password.html.jinja2",
        "user/email/reset_password.txt.jinja2",
        {"user": user, "reset_url": reset_url, "subject": subject},
    )


@dramatiq.actor
def send_magic_link_email(username):
    user = User.get(username)
    token = User.generate_magic_link_token(username)
    login_url = url_for("user.magic_login", token=token, _external=True)
    subject = "Login link | sec-certs.org"

    send_user_email(
        user.email,
        subject,
        "user/email/magic_link.html.jinja2",
        "user/email/magic_link.txt.jinja2",
        {"user": user, "login_url": login_url, "subject": subject},
    )


@dramatiq.actor(periodic=cron("0 0 * * *"))
def clear_expired_tokens():
    deleted = mongo.db.email_tokens.delete_many({"expires_at": {"$lt": datetime.now(timezone.utc)}})
    logger.info(f"Deleted {deleted.deleted_count} expired email tokens.")
