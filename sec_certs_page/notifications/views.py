from datetime import datetime
from operator import itemgetter
from secrets import token_hex

from email_validator import EmailNotValidError, validate_email
from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from wtforms import Label

from .. import mongo
from ..common.views import captcha_required
from . import notifications
from .forms import ManageForm, SubscriptionForm, UnsubscribeForm
from .tasks import send_confirmation_email, send_unsubscription_email
from .utils import derive_token


@notifications.route("/subscribe/", methods=["POST"])
@captcha_required(json=True)
def subscribe():
    if not current_app.config["SUBSCRIPTIONS_ENABLED"]:
        return (
            jsonify(
                {
                    "error": "Notification subscriptions are currently disabled.",
                    "status": "NOK",
                }
            ),
            400,
        )
    data = request.json
    if set(data.keys()) != {"email", "selected", "updates", "captcha"}:
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    try:
        email = validate_email(data["email"])
    except EmailNotValidError:
        return jsonify({"error": "Invalid email address.", "status": "NOK"}), 400
    if data["updates"] not in ("vuln", "all"):
        return jsonify({"error": "Invalid update type.", "status": "NOK"}), 400
    for cert in data["selected"]:
        if set(cert.keys()) != {"name", "hashid", "type", "url"}:
            return jsonify({"error": "Invalid certificate data.", "status": "NOK"}), 400
        if cert["type"] not in ("fips", "cc"):
            return jsonify({"error": "Invalid certificate type.", "status": "NOK"}), 400
        if not mongo.db[cert["type"]].find_one({"_id": cert["hashid"]}):
            return jsonify({"error": "Certificate not found.", "status": "NOK"}), 400
        # TODO: Decide what to do with validation of cert name.
        del cert["url"]
    request_time = datetime.now()
    token = token_hex(16)
    email_token = derive_token("subscription_email", email.email, digest_size=16)
    subscriptions = [
        {
            "timestamp": request_time,
            "updates": data["updates"],
            "email": email.email,
            "token": token,
            "email_token": email_token,
            "certificate": cert,
            "confirmed": False,
        }
        for cert in data["selected"]
    ]
    mongo.db.subs.insert_many(subscriptions)
    send_confirmation_email.delay(token)
    return jsonify({"status": "OK"})


@notifications.route("/confirm/<string(length=32):token>")
def confirm(token: str):
    subscriptions = list(mongo.db.subs.find({"token": token}))
    if not subscriptions:
        return abort(404)
    all_confirmed = all(map(itemgetter("confirmed"), subscriptions))
    if all_confirmed:
        return render_template(
            "message.html.jinja2",
            heading="Already confirmed",
            lead="You have already confirmed this subscription request.",
        )
    email_toks = set(map(itemgetter("email_token"), subscriptions))
    if not len(email_toks) == 1:
        current_app.logger.error("More than one email_token for subscriptions.")
    mongo.db.subs.update_many({"token": token}, {"$set": {"confirmed": True}})
    return render_template("notifications/confirmed.html.jinja2", email_token=email_toks.pop())


@notifications.route("/manage/<string(length=32):email_token>", methods=["GET", "POST"])
def manage(email_token: str):
    subscriptions = list(mongo.db.subs.find({"email_token": email_token, "confirmed": True}))
    if not subscriptions:
        return abort(404)
    email = subscriptions[0]["email"]
    form = ManageForm()
    if request.method == "GET" or not form.validate_on_submit():
        for sub in subscriptions:
            sub_form = SubscriptionForm()
            sub_form.subscribe = True
            sub_form.certificate_hashid = sub["certificate"]["hashid"]
            sub_form.updates = sub["updates"]
            e = form.certificates.append_entry(sub_form)
            e.label = Label(e.id, sub["certificate"]["name"])
    else:
        subs = {sub["certificate"]["hashid"]: sub for sub in subscriptions}
        if set(map(lambda s: s.data["certificate_hashid"], form.certificates.entries)) != set(subs.keys()):
            return abort(400)
        with mongo.cx.start_session() as session:
            with session.start_transaction():
                for sub_form in form.certificates.entries:
                    sub = subs[sub_form.certificate_hashid.data]
                    if not sub_form.subscribe.data:
                        mongo.db.subs.delete_one({"_id": sub["_id"]}, session=session)
                    else:
                        mongo.db.subs.update_one(
                            {"_id": sub["_id"]},
                            {"$set": {"updates": sub_form.updates.data}},
                            session=session,
                        )
        flash("Your notification subscriptions were successfully updated.", "success")
        if all(not sub_form.subscribe.data for sub_form in form.certificates.entries):
            return redirect(url_for("index"))
        else:
            return redirect(url_for("notify.manage", email_token=email_token))
    return render_template(
        "notifications/manage.html.jinja2",
        form=form,
        email_token=email_token,
        email=email,
    )


@notifications.route("/unsubscribe/<string(length=32):token>")
def unsubscribe(token: str):
    res = mongo.db.subs.delete_many({"token": token})
    if res.deleted_count == 0:
        return abort(404)
    return render_template(
        "message.html.jinja2",
        heading="Unsubscribed",
        lead="You were successfully unsubscribed from your notification subscriptions.",
        text="Note that you may still have subscriptions active that you subscribed to at" "a different point in time.",
    )


@notifications.route("/unsubscribe/all/<string(length=32):email_token>")
def unsubscribe_all(email_token: str):
    res = mongo.db.subs.delete_many({"email_token": email_token})
    if res.deleted_count == 0:
        return abort(404)
    return render_template(
        "message.html.jinja2",
        heading="Unsubscribed",
        lead="You were successfully unsubscribed from all notification subscriptions.",
    )


@notifications.route("/unsubscribe/request/", methods=["GET", "POST"])
def unsubscribe_request():
    form = UnsubscribeForm()
    if request.method == "GET" or not form.validate_on_submit():
        return render_template("notifications/unsubscribe.html.jinja2", form=form)
    else:
        try:
            email = validate_email(form.email.data)
        except EmailNotValidError:
            return abort(400)
        subscriptions = list(mongo.db.subs.find({"email": email.email}))
        if subscriptions:  # Timing attack but I don't care.
            send_unsubscription_email.delay(email.email)
        return render_template(
            "message.html.jinja2",
            heading="Unsubscription request processed",
            lead="Your unsubscription request was processed, if there is a subscription active with "
            "the given email address, you will receive an email to confirm unsubscription.",
        )
