from datetime import datetime, timedelta

import dramatiq
from flask import render_template, url_for

from .. import mail, mongo
from .utils import Message


@dramatiq.actor(max_retries=3, actor_name="send_confirmation_email", queue_name="notifications")
def send_confirmation_email(token):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"token": token}))
    if not subscription_requests:
        send_confirmation_email.logger.warning(f"Subscription requests for token = {token} not found, likely a race.")
        return
    email = subscription_requests[0]["email"]
    email_token = subscription_requests[0]["email_token"]
    html = render_template(
        "notifications/email/confirmation_email.html.jinja2",
        token=token,
        email_token=email_token,
    )
    plain = render_template(
        "notifications/email/confirmation_email.txt.jinja2",
        token=token,
        email_token=email_token,
    )
    msg = Message(
        "Confirmation request | sec-certs.org",
        recipients=[email],
        body=plain,
        html=html,
        extra_headers={"List-Unsubscribe": f"<{url_for('notify.unsubscribe', token=token, _external=True)}>"},
    )
    mail.send(msg)
    send_confirmation_email.logger.info(f"Sent confirmation email for token = {token}")


@dramatiq.actor(max_retries=3, actor_name="send_unsubscription_email", queue_name="notifications")
def send_unsubscription_email(email):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"email": email}))
    if not subscription_requests:
        send_unsubscription_email.logger.warning("Subscription requests not found, likely a race.")
        return
    email_token = subscription_requests[0]["email_token"]
    html = render_template("notifications/email/unsubscription_email.html.jinja2", email_token=email_token)
    plain = render_template("notifications/email/unsubscription_email.txt.jinja2", email_token=email_token)
    msg = Message("Unsubscription request | sec-certs.org", recipients=[email], body=plain, html=html)
    mail.send(msg)
    send_unsubscription_email.logger.info(f"Sent unsubscription email for email_token = {email_token}")


@dramatiq.actor(max_retries=3, actor_name="cleanup_subscriptions", queue_name="notifications")
def cleanup_subscriptions():  # pragma: no cover
    old = datetime.now() - timedelta(days=7)
    res = mongo.db.subs.delete_many({"confirmed": False, "timestamp": {"$lt": old}})
    cleanup_subscriptions.logger.info(f"Deleted {res.deleted_count} subscriptions older than 7 days.")


@dramatiq.actor
def send_user_email(to_email, subject, template, context):
    """Send user-related emails asynchronously."""
    from flask import current_app, render_template
    from .. import mail
    
    with current_app.app_context():
        msg = Message(
            subject=subject,
            recipients=[to_email],
            html=render_template(template, **context),
            sender=current_app.config["MAIL_DEFAULT_SENDER"]
        )
        mail.send(msg)
