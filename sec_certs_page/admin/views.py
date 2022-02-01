import pymongo
from flask import current_app, flash, redirect, render_template, request, session, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_login import login_required, login_user, logout_user
from flask_principal import AnonymousIdentity, Identity, Permission, RoleNeed, identity_changed

from .. import mongo
from ..common.views import Pagination
from . import admin
from .forms import LoginForm
from .user import User

admin_permission = Permission(RoleNeed("admin"))


@admin.route("/")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".", "Admin")
def index():
    return render_template("admin/index.html.jinja2")


@admin.route("/updates")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates", "Updates")
def updates():
    cc_log = list(mongo.db.cc_log.find())
    for log_entry in cc_log:
        log_entry["stats"]["changed_ids"] = mongo.db.cc_diff.count_documents(
            {"run_id": log_entry["_id"], "type": "change"}
        )
    fips_log = list(mongo.db.fips_log.find())
    for log_entry in fips_log:
        if "stats" in log_entry:
            log_entry["stats"]["changed_ids"] = mongo.db.fips_diff.count_documents(
                {"run_id": log_entry["_id"], "type": "change"}
            )
    return render_template("admin/updates.html.jinja2", cc_log=cc_log, fips_log=fips_log)


@admin.route("/feedback")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".feedback", "Feedback")
def feedback():
    page = int(request.args.get("page", 1))
    entries = mongo.db.feedback.find({}).sort([("timestamp", pymongo.DESCENDING)])
    count = mongo.db.feedback.count_documents({})
    pagination = Pagination(
        page=page,
        per_page=10,
        search=False,
        found=count,
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("admin/feedback.html.jinja2", pagination=pagination, entries=entries)


@admin.route("/login", methods=["GET", "POST"])
@register_breadcrumb(admin, ".login", "Login")
def login():
    form = LoginForm()
    if form.is_submitted():
        if form.validate():
            user = User.get(form.username.data)
            if user and user.check_password(form.password.data):
                login_user(user, form.remember_me.data)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
                flash("You've been successfully logged in.", "info")
                if admin_permission.can():
                    return redirect(url_for(".index"))
                else:
                    return redirect(url_for("index"))
            else:
                flash("Bad.", "error")
    return render_template("admin/login.html.jinja2", form=form)


@admin.route("/logout")
@login_required
def logout():
    logout_user()
    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    flash("You've been successfully logged out.", "info")
    return redirect(url_for("index"))
