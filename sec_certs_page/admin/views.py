import pymongo
from flask import abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_breadcrumbs import register_breadcrumb
from flask_login import login_required, login_user, logout_user
from flask_principal import AnonymousIdentity, Identity, Permission, RoleNeed, identity_changed

from .. import mongo
from ..common.objformats import StorageFormat
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
    return render_template("admin/updates/index.html.jinja2")


@admin.route("/updates/cc")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates.cc", "CC Updates")
def updates_cc():
    page = int(request.args.get("page", 1))
    per_page = 20
    cc_log = list(mongo.db.cc_log.find().sort([("_id", pymongo.DESCENDING)])[(page - 1) * per_page : page * per_page])
    for log_entry in cc_log:
        if "stats" in log_entry:
            log_entry["stats"]["changed_ids"] = mongo.db.cc_diff.count_documents(
                {"run_id": log_entry["_id"], "type": "change"}
            )
    count = mongo.db.cc_log.count_documents({})
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=count,
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("admin/updates/log/cc.html.jinja2", cc_log=cc_log, pagination=pagination)


@admin.route("/updates/fips")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates.fips", "FIPS Updates")
def updates_fips():
    page = int(request.args.get("page", 1))
    per_page = 20
    fips_log = list(
        mongo.db.fips_log.find().sort([("_id", pymongo.DESCENDING)])[(page - 1) * per_page : page * per_page]
    )
    for log_entry in fips_log:
        if "stats" in log_entry:
            log_entry["stats"]["changed_ids"] = mongo.db.fips_diff.count_documents(
                {"run_id": log_entry["_id"], "type": "change"}
            )
    count = mongo.db.fips_log.count_documents({})
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=count,
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("admin/updates/log/fips.html.jinja2", fips_log=fips_log, pagination=pagination)


@admin.route("/update/<ObjectId:id>")
@login_required
@admin_permission.require()
@register_breadcrumb(
    admin,
    ".updates.update",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": request.view_args["id"]}],  # type: ignore
)
def update_run(id):
    cc_run = mongo.db.cc_log.find_one({"_id": id})
    if cc_run:
        cc_diffs = list(mongo.db.cc_diff.find({"run_id": id}))
        return render_template("admin/updates/run.html.jinja2", run=cc_run, diffs=cc_diffs, type="cc")
    fips_run = mongo.db.fips_log.find_one({"_id": id})
    if fips_run:
        fips_diffs = list(mongo.db.fips_diff.find({"run_id": id}))
        return render_template("admin/updates/run.html.jinja2", run=fips_run, diffs=fips_diffs, type="fips")
    return abort(404)


@admin.route("/update/diff/<ObjectId:id>")
@login_required
@admin_permission.require()
def update_diff(id):
    cc_diff = mongo.db.cc_diff.find_one({"_id": id})
    if cc_diff:
        cc_run = mongo.db.cc_log.find_one({"_id": cc_diff["run_id"]})
        json = StorageFormat(cc_diff).to_json_mapping()
        return render_template("admin/updates/diff.html.jinja2", diff=cc_diff, json=json, run=cc_run, type="cc")
    fips_diff = mongo.db.fips_diff.find_one({"_id": id})
    if fips_diff:
        fips_run = mongo.db.fips_log.find_one({"_id": fips_diff["run_id"]})
        json = StorageFormat(fips_diff).to_json_mapping()
        return render_template("admin/updates/diff.html.jinja2", diff=fips_diff, json=json, run=fips_run, type="fips")
    return abort(404)


@admin.route("/feedback")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".feedback", "Feedback")
def feedback():
    page = int(request.args.get("page", 1))
    per_page = 20
    entries = mongo.db.feedback.find({}).sort([("timestamp", pymongo.DESCENDING)])[
        (page - 1) * per_page : page * per_page
    ]
    count = mongo.db.feedback.count_documents({})
    pagination = Pagination(
        page=page,
        per_page=per_page,
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
