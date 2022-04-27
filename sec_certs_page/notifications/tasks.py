from datetime import datetime, timedelta

from celery.utils.log import get_task_logger
from flask import render_template, url_for
from flask_mail import Message

from .. import celery, mail, mongo

logger = get_task_logger(__name__)


@celery.task(ignore_result=True)
def send_confirmation_email(token):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"token": token}))
    if not subscription_requests:
        logger.warning(f"Subscription requests for token = {token} not found, likely a race.")
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
    logger.info(f"Sent confirmation email for token = {token}")


@celery.task(ignore_result=True)
def send_unsubscription_email(email):  # pragma: no cover
    subscription_requests = list(mongo.db.subs.find({"email": email}))
    if not subscription_requests:
        logger.warning("Subscription requests not found, likely a race.")
        return
    email_token = subscription_requests[0]["email_token"]
    body = render_template("notifications/email/unsubscription_email.html.jinja2", email_token=email_token)
    msg = Message("Unsubscription request | seccerts.org", recipients=[email], html=body)
    mail.send(msg)
    logger.info(f"Sent unsubscription email for email_token = {email_token}")


@celery.task(ignore_result=True)
def cleanup_subscriptions():  # pragma: no cover
    old = datetime.now() - timedelta(days=7)
    res = mongo.db.subs.delete_many({"confirmed": False, "timestamp": {"$lt": old}})
    logger.info(f"Deleted {res.deleted_count} subscriptions older than 7 days.")
