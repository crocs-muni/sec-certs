import logging
from datetime import datetime, timedelta

import dramatiq
from flask import render_template, url_for
from flask_mail import Message

from .. import mail, mongo


@dramatiq.actor(max_retries=3, actor_name="send_confirmation_email")
def send_confirmation_email(token):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"token": token}))
    if not subscription_requests:
        send_confirmation_email.logger.warning(f"Subscription requests for token = {token} not found, likely a race.")
        return
    email = subscription_requests[0]["email"]
    email_token = subscription_requests[0]["email_token"]
    body = render_template(
        "notifications/email/confirmation_email.html.jinja2",
        token=token,
        email_token=email_token,
    )
    msg = Message(
        "Confirmation request | seccerts.org",
        recipients=[email],
        html=body,
        extra_headers={"List-Unsubscribe": f"<{url_for('notify.unsubscribe', token=token, _external=True)}>"},
    )
    mail.send(msg)
    send_confirmation_email.logger.info(f"Sent confirmation email for token = {token}")


@dramatiq.actor(max_retries=3, actor_name="send_unsubscription_email")
def send_unsubscription_email(email):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"email": email}))
    if not subscription_requests:
        send_unsubscription_email.logger.warning("Subscription requests not found, likely a race.")
        return
    email_token = subscription_requests[0]["email_token"]
    body = render_template("notifications/email/unsubscription_email.html.jinja2", email_token=email_token)
    msg = Message("Unsubscription request | seccerts.org", recipients=[email], html=body)
    mail.send(msg)
    send_unsubscription_email.logger.info(f"Sent unsubscription email for email_token = {email_token}")


@dramatiq.actor(max_retries=3, actor_name="cleanup_subscriptions")
def cleanup_subscriptions():  # pragma: no cover
    old = datetime.now() - timedelta(days=7)
    res = mongo.db.subs.delete_many({"confirmed": False, "timestamp": {"$lt": old}})
    cleanup_subscriptions.logger.info(f"Deleted {res.deleted_count} subscriptions older than 7 days.")
