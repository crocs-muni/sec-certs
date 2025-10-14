from datetime import datetime, timezone

from bson import ObjectId
from flask import abort, current_app, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from markupsafe import Markup
from wtforms import Label

from .. import mongo
from . import notifications
from .forms import ChangeSubscriptionForm, ManageForm, NewCertificateSubscriptionForm


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
    if not current_user.email_confirmed:
        return (
            jsonify(
                {
                    "error": "Please confirm your email to manage subscriptions.",
                    "status": "NOK",
                }
            ),
            400,
        )
    data = request.json
    if set(data.keys()) != {"cert", "updates"}:
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    if data["updates"] not in ("vuln", "all"):
        return jsonify({"error": "Invalid update type.", "status": "NOK"}), 400
    cert = data["cert"]
    if not isinstance(cert, dict):
        return jsonify({"error": "Invalid certificate data.", "status": "NOK"}), 400
    if set(cert.keys()) != {"name", "hashid", "type", "url"}:
        return jsonify({"error": "Invalid certificate data.", "status": "NOK"}), 400
    if cert["type"] not in ("fips", "cc", "pp"):
        return jsonify({"error": "Invalid certificate type.", "status": "NOK"}), 400
    if not mongo.db[cert["type"]].find_one({"_id": cert["hashid"]}):
        return jsonify({"error": "Certificate not found.", "status": "NOK"}), 400
    if not isinstance(cert["name"], str):
        return jsonify({"error": "Certificate name not a string.", "status": "NOK"}), 400
    del cert["url"]

    request_time = datetime.now(timezone.utc)
    # TODO: Maybe drop the name and url from the stored subscription?

    sub = {
        "timestamp": request_time,
        "username": current_user.username,
        "updates": data["updates"],
        "type": "changes",
        "certificate": cert,
    }
    mongo.db.subs.update_one(
        {"username": current_user.username, "type": "changes", "certificate.hashid": cert["hashid"]},
        {"$set": sub},
        upsert=True,
    )
    return jsonify({"status": "OK"})


@notifications.route("/subscribe/new/", methods=["POST"])
@login_required
def subscribe_new():
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
    if not current_user.email_confirmed:
        return (
            jsonify(
                {
                    "error": "Please confirm your email to manage subscriptions.",
                    "status": "NOK",
                }
            ),
            400,
        )
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    if set(data.keys()) != {"which"}:
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    if data["which"] not in ("cc", "fips", "pp"):
        return jsonify({"error": "Invalid certificate type.", "status": "NOK"}), 400
    request_time = datetime.now(timezone.utc)
    sub = {
        "timestamp": request_time,
        "username": current_user.username,
        "type": "new",
        "which": data["which"],
    }

    res = mongo.db.subs.update_one(
        {"username": current_user.username, "type": "new", "which": data["which"]}, {"$set": sub}, upsert=True
    )
    if res.matched_count > 0:
        return jsonify({"status": "OK", "message": "You were already subscribed to new certificate notifications."})
    else:
        return jsonify(
            {"status": "OK", "message": "You were successfully subscribed to new certificate notifications."}
        )


@notifications.route("/manage/", methods=["GET", "POST"])
@login_required
def manage():
    if not current_user.email_confirmed:
        flash("Please confirm your email to manage subscriptions.", "warning")
        return redirect(url_for("user.profile"))

    subscriptions = list(mongo.db.subs.find({"username": current_user.username}))
    form = ManageForm()
    if request.method == "GET" or not form.validate_on_submit():
        for sub in subscriptions:
            if sub["type"] == "changes":
                sub_form = ChangeSubscriptionForm()
                sub_form.subscribe = True
                sub_form.certificate_type = sub["certificate"]["type"]
                sub_form.certificate_hashid = sub["certificate"]["hashid"]
                sub_form.updates = sub["updates"]
                e = form.changes.append_entry(sub_form)
                link = url_for(f"{sub_form.certificate_type}.entry", hashid=sub["certificate"]["hashid"])
                e.label = Label(e.id, Markup(f'<a href="{link}">{sub["certificate"]["name"]}</a>'))
            elif sub["type"] == "new":
                sub_form = NewCertificateSubscriptionForm()
                sub_form.subscribe = True
                sub_form.which = sub["which"]
                e = form.new.append_entry(sub_form)
                e.label = Label(e.id, f"New {sub['which'].upper()} certificates")
        # Add entries for new certificate subscriptions if not already present.
        existing_new = {sub_form.which.data for sub_form in form.new.entries}
        for which in ("cc", "fips", "pp"):
            if which not in existing_new:
                sub_form = NewCertificateSubscriptionForm()
                sub_form.subscribe = False
                sub_form.which = which
                e = form.new.append_entry(sub_form)
                e.label = Label(e.id, f"New {which.upper()} certificates")
    else:
        changes_subs = {sub["certificate"]["hashid"]: sub for sub in subscriptions if sub["type"] == "changes"}
        for sub in changes_subs.values():
            if not mongo.db.subs.find_one({"_id": sub["_id"]}):
                return abort(400, description="Unknown certificate in subscription.")
            if not mongo.db[sub["certificate"]["type"]].find_one({"_id": sub["certificate"]["hashid"]}):
                return abort(400, description="Subscribed certificate not found.")
        new_subs = {sub["which"]: sub for sub in subscriptions if sub["type"] == "new"}
        with mongo.cx.start_session() as session:
            with session.start_transaction():
                # Handle the ordinary certificate subscriptions one by one.
                for sub_form in form.changes.entries:
                    sub = changes_subs.get(sub_form.certificate_hashid.data, None)
                    if not sub:
                        # This should never happen, as we only display existing subscriptions in the form.
                        return abort(400, description="Invalid form submission.")
                    if not sub_form.subscribe.data:
                        mongo.db.subs.delete_one({"_id": sub["_id"]}, session=session)
                    else:
                        mongo.db.subs.update_one(
                            {"_id": sub["_id"]},
                            {"$set": {"updates": sub_form.updates.data}},
                            session=session,
                        )
                # Now handle the new certificate subscription.
                for sub_form in form.new.entries:
                    new_sub = new_subs.get(sub_form.which.data, None)
                    if not new_sub and sub_form.subscribe.data:
                        request_time = datetime.now(timezone.utc)
                        sub = {
                            "timestamp": request_time,
                            "username": current_user.username,
                            "type": "new",
                            "which": sub_form.which.data,
                        }
                        mongo.db.subs.insert_one(sub, session=session)
                    if new_sub and not sub_form.subscribe.data:
                        mongo.db.subs.delete_one({"_id": new_sub["_id"]}, session=session)
                    else:
                        # Nothing to update for new certificate subscriptions.
                        pass
            flash("Your notification subscriptions were successfully updated.", "success")
            return redirect(url_for("notify.manage"))
    return render_template(
        "notifications/manage.html.jinja2",
        form=form,
    )


@notifications.route("/unsubscribe/", methods=["POST"])
@login_required
def unsubscribe():
    data = request.json
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    if set(data.keys()) != {"id"}:
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    if not ObjectId.is_valid(data["id"]):
        return jsonify({"error": "Invalid subscription ID.", "status": "NOK"}), 400

    res = mongo.db.subs.delete_one({"_id": ObjectId(data["id"]), "username": current_user.username})

    if res.deleted_count == 0:
        flash("No subscriptions found to unsubscribe.", "info")
    else:
        flash("You were successfully unsubscribed from the subscription.", "success")
    return redirect(url_for("index"))


@notifications.route("/unsubscribe/all/", methods=["POST"])
@login_required
def unsubscribe_all():
    res = mongo.db.subs.delete_many({"username": current_user.username})
    if res.deleted_count == 0:
        flash("No subscriptions found to unsubscribe.", "info")
    else:
        flash("You were successfully unsubscribed from all notification subscriptions.", "success")
    return redirect(url_for("index"))
