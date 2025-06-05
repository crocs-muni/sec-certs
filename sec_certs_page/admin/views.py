import json

import pymongo
from flask import abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import login_required, login_user, logout_user
from flask_principal import AnonymousIdentity, Identity, identity_changed

from .. import mongo, redis, runtime_config
from ..common.objformats import StorageFormat
from ..common.permissions import admin_permission
from ..common.views import Pagination, register_breadcrumb
from . import admin
from .forms import ConfigEditForm, LoginForm
from .user import User

collections = [
    ("cc", mongo.db.cc_log, mongo.db.cc_diff),
    ("fips", mongo.db.fips_log, mongo.db.fips_diff),
    ("pp", mongo.db.pp_log, mongo.db.pp_diff),
]


@admin.route("/")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".", "Admin")
def index():
    return render_template("admin/index.html.jinja2")


@admin.route("/tasks")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".tasks", "Tasks")
def tasks():
    tids = redis.smembers("tasks")
    current_tasks = []
    for tid in tids:
        task = redis.get(tid)
        if task:
            current_tasks.append(json.loads(task))
    return render_template("admin/tasks.html.jinja2", tasks=current_tasks)


@admin.route("/candeploy")
def candeploy():
    tids = redis.smembers("tasks")
    current_tasks = []
    for tid in tids:
        task = redis.get(tid)
        if task:
            current_tasks.append(json.loads(task))
    if current_tasks:
        return "Nope: " + ", ".join(task["name"] for task in current_tasks), 409
    else:
        return "OK", 200


@admin.route("/updates")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates", "Updates")
def updates():
    return render_template("admin/updates/index.html.jinja2")


def updates_one(template, type, log_coll, diff_coll):
    page = int(request.args.get("page", 1))
    per_page = current_app.config["SEARCH_ITEMS_PER_PAGE"]
    log = list(log_coll.find().sort([("start_time", pymongo.DESCENDING)])[(page - 1) * per_page : page * per_page])
    for log_entry in log:
        if "stats" in log_entry and "changed_ids" not in log_entry["stats"]:
            log_entry["stats"]["changed_ids"] = diff_coll.count_documents(
                {"run_id": log_entry["_id"], "type": "change"}
            )
    count = log_coll.count_documents({})
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=count,
        total=count,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template(template, log=log, pagination=pagination)


@admin.route("/updates/cc")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates.cc", "CC Updates")
def updates_cc():
    return updates_one("admin/updates/log/cc.html.jinja2", "cc", mongo.db.cc_log, mongo.db.cc_diff)


@admin.route("/updates/fips")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates.fips", "FIPS Updates")
def updates_fips():
    return updates_one("admin/updates/log/fips.html.jinja2", "fips", mongo.db.fips_log, mongo.db.fips_diff)


@admin.route("/updates/pp")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".updates.pp", "PP Updates")
def updates_pp():
    return updates_one("admin/updates/log/pp.html.jinja2", "pp", mongo.db.pp_log, mongo.db.pp_diff)


@admin.route("/update/<ObjectId:id>")
@login_required
@admin_permission.require()
@register_breadcrumb(
    admin,
    ".updates.update",
    "",
    dynamic_list_constructor=lambda *args, **kwargs: [{"text": str(request.view_args["id"])}],  # type: ignore
)
def update_run(id):
    for type, log_coll, diff_coll in collections:
        run = log_coll.find_one({"_id": id})
        if run:
            diffs = list(diff_coll.find({"run_id": id}))
            return render_template("admin/updates/run.html.jinja2", run=run, diffs=diffs, type=type)
    return abort(404)


@admin.route("/update/diff/<ObjectId:id>")
@login_required
@admin_permission.require()
def update_diff(id):
    for type, log_coll, diff_coll in collections:
        diff = diff_coll.find_one({"_id": id})
        if diff:
            run = log_coll.find_one({"_id": diff["run_id"]})
            json = StorageFormat(diff).to_json_mapping()
            return render_template("admin/updates/diff.html.jinja2", diff=diff, json=json, run=run, type=type)
    return abort(404)


@admin.route("/config")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".config", "Config")
def config():
    config_data = dict(current_app.config)
    config_text = "\n".join(
        (
            f"{key} = {value!r}"
            if ("SECRET" not in key) and ("AUTH" not in key) and ("PASSWORD" not in key)
            else f"{key} = ...hidden..."
        )
        for key, value in config_data.items()
    )
    runtime_config_data = dict(runtime_config)
    runtime_config_text = "\n".join(
        (
            f"{key} = {value!r}"
            if ("SECRET" not in key) and ("AUTH" not in key) and ("PASSWORD" not in key)
            else f"{key} = ...hidden..."
        )
        for key, value in runtime_config_data.items()
    )
    return render_template(
        "admin/config/index.html.jinja2", config_text=config_text, runtime_config_text=runtime_config_text
    )


@admin.route("/config/edit", methods=["GET", "POST", "DELETE"])
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".config.edit", "Edit")
def config_edit():
    form = ConfigEditForm()
    if form.is_submitted():
        if request.method == "DELETE":
            if form.key.data in runtime_config:
                del runtime_config[form.key.data]
                return redirect(url_for("admin.config"), code=303)
            else:
                flash(f"Key {form.key.data} does not exist and can not be deleted.", "error")
                return render_template("admin/config/edit.html.jinja2", form=form)
        elif request.method == "POST" and form.validate():
            if form.type.data == "string":
                runtime_config[form.key.data] = str(form.value.data)
            elif form.type.data == "int":
                try:
                    runtime_config[form.key.data] = int(form.value.data)
                except ValueError:
                    flash("Bad value format for int.", "error")
                    return render_template("admin/config/edit.html.jinja2", form=form)
            elif form.type.data == "float":
                try:
                    runtime_config[form.key.data] = float(form.value.data)
                except ValueError:
                    flash("Bad value format for float.", "error")
                    return render_template("admin/config/edit.html.jinja2", form=form)
            elif form.type.data == "boolean":
                try:
                    if form.value.data in ("true", "True", "T", "t", "1"):
                        runtime_config[form.key.data] = True
                    elif form.value.data in ("false", "False", "F", "f", 0):
                        runtime_config[form.key.data] = False
                    else:
                        raise ValueError
                except ValueError:
                    flash("Bad value format for boolean.", "error")
                    return render_template("admin/config/edit.html.jinja2", form=form)
            return redirect(url_for("admin.config"))
        else:
            return render_template("admin/config/edit.html.jinja2", form=form)
    else:
        form.key.data = request.args.get("key")
        form.value.data = request.args.get("value")
        return render_template("admin/config/edit.html.jinja2", form=form)


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
