import json

import pymongo
from flask import abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import login_required, login_user, logout_user, current_user
from flask_principal import AnonymousIdentity, Identity, identity_changed
from flask_mail import Message

from .. import mongo, redis, runtime_config, mail
from ..common.objformats import StorageFormat
from ..common.permissions import admin_permission
from ..common.views import Pagination, register_breadcrumb
from . import admin
from .forms import ConfigEditForm, LoginForm, RegisterForm, PasswordResetRequestForm, PasswordResetForm, MagicLinkForm
from .user import User

# OAuth support (optional - only if GitHub OAuth is configured)
try:
    from flask_dance.contrib.github import make_github_blueprint, github
    from flask_dance.consumer.storage.sqla import OAuthConsumerMixin, SQLAlchemyStorage
    from flask_dance.consumer import oauth_authorized
    oauth_available = True
except ImportError:
    oauth_available = False

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


@admin.route("/register", methods=["GET", "POST"])
@register_breadcrumb(admin, ".register", "Register")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if user already exists
        if User.get(form.username.data) or User.get_by_email(form.email.data):
            flash("Username or email already exists.", "error")
            return render_template("admin/register.html.jinja2", form=form)
        
        # Create user
        user = User.create(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            roles=[]
        )
        
        if user:
            # Send confirmation email
            token = User.generate_confirmation_token(user.username)
            confirmation_url = url_for('admin.confirm_email', token=token, _external=True)
            
            msg = Message(
                subject="Confirm your email - sec-certs",
                recipients=[user.email],
                html=render_template("admin/emails/confirm_email.html.jinja2", 
                                   user=user, confirmation_url=confirmation_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            try:
                mail.send(msg)
                flash("Registration successful! Please check your email to confirm your account.", "success")
                return redirect(url_for("admin.login"))
            except Exception as e:
                flash("Registration successful but email could not be sent. Please contact support.", "warning")
                return redirect(url_for("admin.login"))
        else:
            flash("Registration failed. Please try again.", "error")
    
    return render_template("admin/register.html.jinja2", form=form)


@admin.route("/confirm-email/<token>")
def confirm_email(token):
    user_id = User.verify_token(token, 'email_confirmation')
    if user_id:
        user = User.get(user_id)
        if user:
            user.confirm_email()
            flash("Email confirmed successfully! You can now log in.", "success")
        else:
            flash("Invalid confirmation link.", "error")
    else:
        flash("Invalid or expired confirmation link.", "error")
    
    return redirect(url_for("admin.login"))


@admin.route("/forgot-password", methods=["GET", "POST"])
@register_breadcrumb(admin, ".forgot_password", "Forgot Password")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user:
            token = User.generate_password_reset_token(user.username)
            reset_url = url_for('admin.reset_password', token=token, _external=True)
            
            msg = Message(
                subject="Password Reset - sec-certs",
                recipients=[user.email],
                html=render_template("admin/emails/reset_password.html.jinja2", 
                                   user=user, reset_url=reset_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            try:
                mail.send(msg)
            except Exception as e:
                pass  # Don't reveal if email exists
        
        flash("If the email exists in our system, you will receive password reset instructions.", "info")
        return redirect(url_for("admin.login"))
    
    return render_template("admin/forgot_password.html.jinja2", form=form)


@admin.route("/reset-password/<token>", methods=["GET", "POST"])
@register_breadcrumb(admin, ".reset_password", "Reset Password")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    user_id = User.verify_token(token, 'password_reset')
    if not user_id:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("admin.forgot_password"))
    
    user = User.get(user_id)
    if not user:
        flash("Invalid reset link.", "error")
        return redirect(url_for("admin.forgot_password"))
    
    form = PasswordResetForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        flash("Password reset successfully! You can now log in.", "success")
        return redirect(url_for("admin.login"))
    
    return render_template("admin/reset_password.html.jinja2", form=form, token=token)


@admin.route("/magic-link", methods=["GET", "POST"])
@register_breadcrumb(admin, ".magic_link", "Email Login")
def magic_link():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = MagicLinkForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and user.email_confirmed:
            token = User.generate_magic_link_token(user.username)
            login_url = url_for('admin.magic_login', token=token, _external=True)
            
            msg = Message(
                subject="Login Link - sec-certs",
                recipients=[user.email],
                html=render_template("admin/emails/magic_link.html.jinja2", 
                                   user=user, login_url=login_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            try:
                mail.send(msg)
            except Exception as e:
                pass  # Don't reveal if email exists
        
        flash("If the email exists and is confirmed, you will receive a login link.", "info")
        return redirect(url_for("admin.login"))
    
    return render_template("admin/magic_link.html.jinja2", form=form)


@admin.route("/magic-login/<token>")
def magic_login(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    user_id = User.verify_token(token, 'magic_link')
    if user_id:
        user = User.get(user_id)
        if user and user.email_confirmed:
            login_user(user, remember=True)
            identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
            flash("You've been successfully logged in via email link.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid login link.", "error")
    else:
        flash("Invalid or expired login link.", "error")
    
    return redirect(url_for("admin.login"))


@admin.route("/profile")
@login_required
@register_breadcrumb(admin, ".profile", "Profile")
def profile():
    return render_template("admin/profile.html.jinja2", user=current_user)


@admin.route("/subscriptions")
@login_required
@register_breadcrumb(admin, ".subscriptions", "Subscriptions")
def subscriptions():
    """User subscription management page"""
    # Get user's subscriptions from the notification system
    user_subscriptions = list(mongo.db.subs.find({
        "email": current_user.email,
        "confirmed": True
    }))
    
    # Group subscriptions by type
    cert_subscriptions = [sub for sub in user_subscriptions if sub.get("certificate")]
    new_cert_subscription = next((sub for sub in user_subscriptions if sub.get("updates") == "new"), None)
    
    return render_template("admin/subscriptions.html.jinja2", 
                         cert_subscriptions=cert_subscriptions,
                         new_cert_subscription=new_cert_subscription)


@admin.route("/subscriptions/quick-subscribe", methods=["POST"])
@login_required
def quick_subscribe():
    """Quick subscription for logged-in users without email confirmation"""
    from datetime import datetime
    from secrets import token_hex
    from ..notifications.utils import derive_token
    
    data = request.json
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid data.", "status": "NOK"}), 400
    
    # Validate required fields
    required_fields = {"selected", "updates"}
    if not required_fields.issubset(data.keys()):
        return jsonify({"error": "Missing required fields.", "status": "NOK"}), 400
    
    if data["updates"] not in ("vuln", "all", "new"):
        return jsonify({"error": "Invalid update type.", "status": "NOK"}), 400
    
    # Validate certificates if provided
    if data["selected"] and data["updates"] != "new":
        for cert in data["selected"]:
            if set(cert.keys()) != {"name", "hashid", "type", "url"}:
                return jsonify({"error": "Invalid certificate data.", "status": "NOK"}), 400
            if cert["type"] not in ("fips", "cc"):
                return jsonify({"error": "Invalid certificate type.", "status": "NOK"}), 400
            if not mongo.db[cert["type"]].find_one({"_id": cert["hashid"]}):
                return jsonify({"error": "Certificate not found.", "status": "NOK"}), 400
            del cert["url"]  # Remove URL before storing
    
    if data["updates"] == "new":
        data["selected"] = [None]
    
    request_time = datetime.now()
    token = token_hex(16)
    email_token = derive_token("subscription_email", current_user.email, digest_size=16)
    
    subscriptions = [
        {
            "timestamp": request_time,
            "updates": data["updates"],
            "email": current_user.email,
            "token": token,
            "email_token": email_token,
            "certificate": cert,
            "confirmed": True,  # Auto-confirm for logged-in users
        }
        for cert in data["selected"]
    ]
    
    # Check for existing subscriptions to avoid duplicates
    existing_subs = []
    for sub in subscriptions:
        if sub["certificate"]:
            existing = mongo.db.subs.find_one({
                "email": current_user.email,
                "certificate.hashid": sub["certificate"]["hashid"],
                "confirmed": True
            })
            if not existing:
                existing_subs.append(sub)
        else:  # New certificate subscription
            existing = mongo.db.subs.find_one({
                "email": current_user.email,
                "updates": "new",
                "confirmed": True
            })
            if not existing:
                existing_subs.append(sub)
    
    if existing_subs:
        mongo.db.subs.insert_many(existing_subs)
        return jsonify({"status": "OK", "message": f"Added {len(existing_subs)} new subscriptions."})
    else:
        return jsonify({"status": "OK", "message": "No new subscriptions added (already subscribed)."})


@admin.route("/subscriptions/unsubscribe/<string:subscription_id>", methods=["POST"])
@login_required
def unsubscribe(subscription_id):
    """Remove a specific subscription"""
    from bson import ObjectId
    
    try:
        obj_id = ObjectId(subscription_id)
    except:
        return jsonify({"error": "Invalid subscription ID.", "status": "NOK"}), 400
    
    # Find and delete the subscription, but only if it belongs to the current user
    result = mongo.db.subs.delete_one({
        "_id": obj_id,
        "email": current_user.email
    })
    
    if result.deleted_count > 0:
        return jsonify({"status": "OK", "message": "Subscription removed successfully."})
    else:
        return jsonify({"error": "Subscription not found or not owned by user.", "status": "NOK"}), 404


# GitHub OAuth routes (only available if Flask-Dance is installed and configured)
if oauth_available:
    @admin.route("/auth/github")
    def github_login():
        """Initiate GitHub OAuth login"""
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        
        if not current_app.config.get('GITHUB_OAUTH_CLIENT_ID'):
            flash("GitHub OAuth is not configured.", "error")
            return redirect(url_for("admin.login"))
        
        return redirect(url_for("github.login"))
    
    
    @admin.route("/auth/github/callback")
    def github_callback():
        """Handle GitHub OAuth callback"""
        if not github.authorized:
            flash("Authorization failed.", "error")
            return redirect(url_for("admin.login"))
        
        try:
            resp = github.get("/user")
            if not resp.ok:
                flash("Failed to fetch user info from GitHub.", "error")
                return redirect(url_for("admin.login"))
            
            github_info = resp.json()
            github_id = str(github_info["id"])
            github_username = github_info["login"]
            github_email = github_info.get("email")
            
            if not github_email:
                # Try to get email from user's public emails
                email_resp = github.get("/user/emails")
                if email_resp.ok:
                    emails = email_resp.json()
                    primary_email = next((e for e in emails if e["primary"]), None)
                    if primary_email:
                        github_email = primary_email["email"]
            
            if not github_email:
                flash("GitHub account must have a public email address.", "error")
                return redirect(url_for("admin.login"))
            
            # Check if user already exists with this GitHub ID
            user = User.get_by_github_id(github_id)
            if user:
                login_user(user, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
                flash(f"Welcome back, {user.username}!", "success")
                return redirect(url_for("index"))
            
            # Check if user exists with this email
            user = User.get_by_email(github_email)
            if user:
                # Link the GitHub account to existing user
                user.link_github(github_id)
                user.confirm_email()  # Auto-confirm email for OAuth users
                login_user(user, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
                flash(f"GitHub account linked successfully! Welcome back, {user.username}!", "success")
                return redirect(url_for("index"))
            
            # Create new user account
            # Make sure username is unique
            username = github_username
            counter = 1
            while User.get(username):
                username = f"{github_username}{counter}"
                counter += 1
            
            user = User.create(
                username=username,
                email=github_email,
                password=None,  # No password for OAuth users
                roles=[],
                github_id=github_id
            )
            
            if user:
                login_user(user, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))
                flash(f"Account created successfully! Welcome, {user.username}!", "success")
                return redirect(url_for("index"))
            else:
                flash("Failed to create account. Please try again.", "error")
                return redirect(url_for("admin.login"))
                
        except Exception as e:
            current_app.logger.error(f"GitHub OAuth error: {e}")
            flash("Authentication failed. Please try again.", "error")
            return redirect(url_for("admin.login"))
else:
    @admin.route("/auth/github")
    def github_login():
        flash("GitHub OAuth is not available. Please install Flask-Dance.", "error")
        return redirect(url_for("admin.login"))


@admin.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    # Remove user from database
    mongo.db.users.delete_one({"username": current_user.username})
    
    # Also clean up any related data
    mongo.db.email_tokens.delete_many({"user_id": current_user.username})
    
    logout_user()
    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    
    flash("Your account has been deleted successfully.", "info")
    return redirect(url_for("index"))


@admin.route("/chat-invite")
@login_required
@admin_permission.require()
def chat_invite():
    """Admin page to create chat auth links and view existing ones."""
    # Find all chat auth links in redis
    # Keys are like "chat_auth_token:{token}"
    keys = redis.keys("chat_auth_token:*")
    chat_links = []
    for key in keys:
        token = (
            key.decode().split("chat_auth_token:")[-1] if isinstance(key, bytes) else key.split("chat_auth_token:")[-1]
        )
        # Get chat duration (value) and link expiry (ttl)
        chat_duration = redis.get(key)
        try:
            chat_duration = int(chat_duration)
        except Exception:
            chat_duration = None
        ttl = redis.ttl(key)
        # Compose the link
        link = url_for("chat.consume_auth_link", token=token, _external=True)
        chat_links.append(
            {
                "token": token,
                "link": link,
                "chat_duration": chat_duration,
                "ttl": ttl,
            }
        )
    return render_template("admin/chat_invite.jinja2", chat_links=chat_links)
