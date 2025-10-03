from datetime import datetime, timezone
from operator import itemgetter

from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from wtforms import Label

from .. import mongo
from . import notifications
from .forms import ManageForm, SubscriptionForm


@notifications.route("/subscribe/", methods=["POST"])
@login_required
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
        email = validate_email(data["email"], check_deliverability=False)
    except EmailNotValidError:
        return jsonify({"error": "Invalid email address.", "status": "NOK"}), 400
    if data["updates"] not in ("vuln", "all", "new"):
        return jsonify({"error": "Invalid update type.", "status": "NOK"}), 400
    if data["selected"]:
        if data["updates"] == "new":
            return (
                jsonify(
                    {
                        "error": "Invalid selection, certificates cannot be selected when subscribing to new certificate updates.",
                        "status": "NOK",
                    }
                ),
                400,
            )
        for cert in data["selected"]:
            if set(cert.keys()) != {"name", "hashid", "type", "url"}:
                return jsonify({"error": "Invalid certificate data.", "status": "NOK"}), 400
            if cert["type"] not in ("fips", "cc"):
                return jsonify({"error": "Invalid certificate type.", "status": "NOK"}), 400
            if not mongo.db[cert["type"]].find_one({"_id": cert["hashid"]}):
                return jsonify({"error": "Certificate not found.", "status": "NOK"}), 400
            if not isinstance(cert["name"], str):
                return jsonify({"error": "Certificate name not a string.", "status": "NOK"}), 400
            del cert["url"]
    if data["updates"] == "new":
        data["selected"] = [None]
    request_time = datetime.now()
    token = token_hex(16)
    email_token = derive_token("subscription_email", email.normalized, digest_size=16)
    subscriptions = [
        {
            "timestamp": request_time,
            "updates": data["updates"],
            "email": email.normalized,
            "token": token,
            "email_token": email_token,
            "certificate": cert,
            "confirmed": False,
        }
        for cert in data["selected"]
    ]
    mongo.db.subs.insert_many(subscriptions)
    send_confirmation_email.send(token)
    return jsonify({"status": "OK"})


# Removed confirmation endpoint - subscriptions no longer require email confirmation


@notifications.route("/manage", methods=["GET", "POST"])
@login_required
def manage():
    if not current_user.email_confirmed:
        flash("Please confirm your email to manage subscriptions.", "warning")
        return redirect(url_for("user.profile"))
    
    subscriptions = list(mongo.db.subs.find({"user_id": str(current_user.id)}))
    form = ManageForm()
    if request.method == "GET" or not form.validate_on_submit():
        for sub in subscriptions:
            if sub["certificate"]:
                sub_form = SubscriptionForm()
                sub_form.subscribe = True
                sub_form.certificate_hashid = sub["certificate"]["hashid"]
                sub_form.updates = sub["updates"]
                e = form.certificates.append_entry(sub_form)
                e.label = Label(e.id, sub["certificate"]["name"])
            elif sub["updates"] == "new":
                form.new.data = True
    else:
        subs = {sub["certificate"]["hashid"]: sub for sub in subscriptions if sub["certificate"]}
        if set(map(lambda s: s.data["certificate_hashid"], form.certificates.entries)) != set(subs.keys()):
            return abort(400)
        new_sub = next(iter(filter(lambda sub: sub["updates"] == "new", subscriptions)), None)
        with mongo.cx.start_session() as session:
            with session.start_transaction():
                # Handle the ordinary certificate subscriptions one by one.
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
                # Now handle the new certificate subscription.
                if form.new.data:
                    if new_sub:
                        # Do nothing, the user has a subscription and wants to keep it.
                        pass
                    else:
                        # We need to create a new sub
                        request_time = datetime.now(timezone.utc)
                        subscription = {
                            "timestamp": request_time,
                            "updates": "new",
                            "user_id": str(current_user.id),
                            "certificate": None,
                        }
                        mongo.db.subs.insert_one(subscription, session=session)
                else:
                    if new_sub:
                        # The user has a subscription and wants to delete it
                        mongo.db.subs.delete_one({"_id": new_sub["_id"]}, session=session)
                    else:
                        # Do nothing, the user doesn't have a subscription and does not want it
                        pass
        if all(not sub_form.subscribe.data for sub_form in form.certificates.entries) and not form.new.data:
            flash("Your notification subscriptions were successfully removed.", "success")
            return redirect(url_for("index"))
        else:
            flash("Your notification subscriptions were successfully updated.", "success")
            return redirect(url_for("notify.manage"))
    return render_template(
        "notifications/manage.html.jinja2",
        form=form,
        email=current_user.email,
    )


@notifications.route("/unsubscribe/all", methods=["POST"])
@login_required
def unsubscribe_all():
    res = mongo.db.subs.delete_many({"user_id": str(current_user.id)})
    if res.deleted_count == 0:
        flash("No subscriptions found to unsubscribe.", "info")
    else:
        flash("You were successfully unsubscribed from all notification subscriptions.", "success")
    return redirect(url_for("index"))
