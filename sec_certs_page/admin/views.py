import json

import pymongo
from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import login_required

from .. import mongo, redis, runtime_config
from ..common.objformats import StorageFormat
from ..common.permissions import admin_permission
from ..common.views import Pagination, register_breadcrumb
from ..user.models import User
from . import admin
from .forms import ConfigEditForm, UserEditForm

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


@admin.route("/users")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".users", "Users")
def users():
    page = int(request.args.get("page", 1))
    per_page = current_app.config.get("SEARCH_ITEMS_PER_PAGE", 25)
    # find users sorted by creation time if available, otherwise by username
    users_cursor = mongo.db.users.find({}).sort([("created_at", pymongo.DESCENDING), ("username", pymongo.ASCENDING)])
    total = mongo.db.users.count_documents({})
    users_list = list(users_cursor[(page - 1) * per_page : page * per_page])
    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=total,
        total=total,
        css_framework="bootstrap5",
        alignment="center",
    )
    return render_template("admin/users/list.html.jinja2", users=users_list, pagination=pagination)


@admin.route("/user/<username>", methods=["GET", "POST"])
@login_required
@admin_permission.require()
@register_breadcrumb(
    admin,
    ".users.user",
    "User",
    dynamic_list_constructor=lambda *a, **k: [{"text": str(request.view_args.get("username"))}],
)
def edit_user(username):
    user_doc = mongo.db.users.find_one({"username": username})
    if not user_doc:
        return abort(404)
    form = UserEditForm()
    # Determine available roles from configuration or known list; fall back to common roles
    available_roles = User.ROLES
    form.roles.choices = [(r, r) for r in available_roles]
    if form.validate_on_submit():
        # roles comes as list of strings
        new_roles = list(form.roles.data)
        mongo.db.users.update_one({"username": username}, {"$set": {"roles": new_roles}})
        flash("Roles updated.", "success")
        return redirect(url_for("admin.users"))
    # prepopulate form
    form.roles.data = user_doc.get("roles", [])
    return render_template("admin/users/edit.html.jinja2", user=user_doc, form=form)


@admin.route("/accounting")
@login_required
@admin_permission.require()
@register_breadcrumb(admin, ".accounting", "Accounting")
def accounting():
    page = int(request.args.get("page", 1))
    per_page = current_app.config.get("SEARCH_ITEMS_PER_PAGE", 25)
    username_filter = request.args.get("username")
    endpoint_filter = request.args.get("endpoint")

    # Validate filters to prevent injection attacks
    if username_filter is not None and not isinstance(username_filter, str):
        username_filter = None
    if endpoint_filter is not None and not isinstance(endpoint_filter, str):
        endpoint_filter = None

    # Build query based on filters
    query = {}
    if username_filter:
        query["username"] = username_filter
    if endpoint_filter:
        query["endpoint"] = endpoint_filter

    # Get accounting logs sorted by period (most recent first)
    logs_cursor = mongo.db.accounting.find(query).sort([("period", pymongo.DESCENDING)])
    total = mongo.db.accounting.count_documents(query)
    logs_list = list(logs_cursor[(page - 1) * per_page : page * per_page])

    # Get distinct usernames and endpoints for filter dropdowns
    distinct_usernames = sorted(
        [u for u in mongo.db.accounting.distinct("username") if u is not None], key=lambda x: x.lower()
    )
    distinct_endpoints = sorted(mongo.db.accounting.distinct("endpoint"))

    pagination = Pagination(
        page=page,
        per_page=per_page,
        search=False,
        found=total,
        total=total,
        css_framework="bootstrap5",
        alignment="center",
    )

    return render_template(
        "admin/accounting.html.jinja2",
        logs=logs_list,
        pagination=pagination,
        distinct_usernames=distinct_usernames,
        distinct_endpoints=distinct_endpoints,
        username_filter=username_filter,
        endpoint_filter=endpoint_filter,
    )
