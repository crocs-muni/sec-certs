from datetime import datetime, timezone
from secrets import token_hex

from flask import abort, current_app, flash, redirect, render_template, request, session, url_for, jsonify
from flask_login import login_required, login_user, logout_user, current_user
from flask_principal import AnonymousIdentity, Identity, identity_changed
from flask_mail import Message

from .. import mongo, mail
from ..common.views import register_breadcrumb
from ..common.permissions import admin_permission
from ..notifications.utils import derive_token
from . import user
from .forms import LoginForm, RegisterForm, PasswordResetRequestForm, PasswordResetForm, MagicLinkForm, ChangePasswordForm
from .models import User
from flask_dance.contrib.github import github

class UserExistsError(Exception):
    """Raised when a user with the same username or email already exists."""
    pass


@user.route("/login", methods=["GET", "POST"])
@register_breadcrumb(user, ".login", "Login")
def login():
    form = LoginForm()
    if form.is_submitted():
        if form.validate():
            user_obj = User.get(form.username.data)
            if user_obj and user_obj.check_password(form.password.data):
                login_user(user_obj, form.remember_me.data)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash("You've been successfully logged in.", "info")
                if admin_permission.can():
                    return redirect(url_for("admin.index"))
                else:
                    return redirect(url_for("index"))
            else:
                flash("Bad.", "error")
    return render_template("user/login.html.jinja2", form=form)


@user.route("/logout")
@login_required
def logout():
    logout_user()
    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    flash("You've been successfully logged out.", "info")
    return redirect(url_for("index"))


@user.route("/register", methods=["GET", "POST"])
@register_breadcrumb(user, ".register", "Register")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Create user
        try:
            new_user = User.create(
                username=form.username.data,
                email=form.email.data,
                password=form.password.data,
                roles=[]
            )
            # Send confirmation email
            token = User.generate_confirmation_token(new_user.username)
            confirmation_url = url_for('user.confirm_email', token=token, _external=True)
            
            msg = Message(
                subject="Confirm your email - sec-certs",
                recipients=[new_user.email],
                html=render_template("user/emails/confirm_email.html.jinja2", 
                                   user=new_user, confirmation_url=confirmation_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            # Send confirmation email asynchronously
            from sec_certs_page.notifications.tasks import send_user_email
            send_user_email.send(
                new_user.email,
                "Confirm Your Account",
                "user/emails/confirm_email.html.jinja2",
                {"user": new_user, "token": User.generate_confirmation_token(new_user.username)}
            )
            flash("Registration successful! Please check your email to confirm your account.", "success")
            return redirect(url_for("user.login"))
        except UserExistsError:
            flash("A user with that username or email already exists.", "error")
        except Exception as e:
            current_app.logger.error(f"Registration failed: {e}")
            raise
    
    return render_template("user/register.html.jinja2", form=form)


@user.route("/confirm-email/<token>")
def confirm_email(token):
    user_id = User.verify_token(token, 'email_confirmation')
    if user_id:
        user_obj = User.get(user_id)
        if user_obj:
            user_obj.confirm_email()
            flash("Email confirmed successfully! You can now log in.", "success")
        else:
            flash("Invalid confirmation link.", "error")
    else:
        flash("Invalid or expired confirmation link.", "error")
    
    return redirect(url_for("user.login"))


@user.route("/forgot-password", methods=["GET", "POST"])
@register_breadcrumb(user, ".forgot_password", "Forgot Password")
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user_obj = User.get_by_email(form.email.data)
        if user_obj:
            token = User.generate_password_reset_token(user_obj.username)
            reset_url = url_for('user.reset_password', token=token, _external=True)
            
            msg = Message(
                subject="Password Reset - sec-certs",
                recipients=[user_obj.email],
                html=render_template("user/emails/reset_password.html.jinja2", 
                                   user=user_obj, reset_url=reset_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            try:
                mail.send(msg)
            except Exception as e:
                pass  # Don't reveal if email exists
        
        flash("If the email exists in our system, you will receive password reset instructions.", "info")
        return redirect(url_for("user.login"))
    
    return render_template("user/forgot_password.html.jinja2", form=form)


@user.route("/reset-password/<token>", methods=["GET", "POST"])
@register_breadcrumb(user, ".reset_password", "Reset Password")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    user_id = User.verify_token(token, 'password_reset')
    if not user_id:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("user.forgot_password"))
    
    user_obj = User.get(user_id)
    if not user_obj:
        flash("Invalid reset link.", "error")
        return redirect(url_for("user.forgot_password"))
    
    form = PasswordResetForm()
    if form.validate_on_submit():
        user_obj.set_password(form.password.data)
        flash("Password reset successfully! You can now log in.", "success")
        return redirect(url_for("user.login"))
    
    return render_template("user/reset_password.html.jinja2", form=form, token=token)


@user.route("/magic-link", methods=["GET", "POST"])
@register_breadcrumb(user, ".magic_link", "Email Login")
def magic_link():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    form = MagicLinkForm()
    if form.validate_on_submit():
        user_obj = User.get_by_email(form.email.data)
        if user_obj and user_obj.email_confirmed:
            token = User.generate_magic_link_token(user_obj.username)
            login_url = url_for('user.magic_login', token=token, _external=True)
            
            msg = Message(
                subject="Login Link - sec-certs",
                recipients=[user_obj.email],
                html=render_template("user/emails/magic_link.html.jinja2", 
                                   user=user_obj, login_url=login_url),
                sender=current_app.config.get('MAIL_DEFAULT_SENDER')
            )
            
            try:
                mail.send(msg)
            except Exception as e:
                pass  # Don't reveal if email exists
        
        flash("If the email exists and is confirmed, you will receive a login link.", "info")
        return redirect(url_for("user.login"))
    
    return render_template("user/magic_link.html.jinja2", form=form)


@user.route("/magic-login/<token>")
def magic_login(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    user_id = User.verify_token(token, 'magic_link')
    if user_id:
        user_obj = User.get(user_id)
        if user_obj and user_obj.email_confirmed:
            login_user(user_obj, remember=True)
            identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
            flash("You've been successfully logged in via email link.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid login link.", "error")
    else:
        flash("Invalid or expired login link.", "error")
    
    return redirect(url_for("user.login"))


@user.route("/profile")
@login_required
@register_breadcrumb(user, ".profile", "Profile")
def profile():
    return render_template("user/profile.html.jinja2", user=current_user)


@user.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if current_user.check_password(form.current_password.data):
            current_user.set_password(form.new_password.data)
            flash("Password changed successfully.", "success")
            return redirect(url_for("user.profile"))
        else:
            flash("Current password is incorrect.", "error")
    
    return render_template("user/change_password.html.jinja2", form=form)


@user.route("/subscriptions")
@login_required
@register_breadcrumb(user, ".subscriptions", "Subscriptions") 
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
    
    return render_template("user/subscriptions.html.jinja2", 
                         cert_subscriptions=cert_subscriptions,
                         new_cert_subscription=new_cert_subscription)


@user.route("/subscriptions/quick-subscribe", methods=["POST"])
@login_required
def quick_subscribe():
    """Quick subscription for logged-in users without email confirmation"""
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


@user.route("/subscriptions/unsubscribe/<string:subscription_id>", methods=["POST"])
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


@user.route("/delete-account", methods=["POST"])
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


# GitHub OAuth routes (only available if Flask-Dance is installed and configured)
if oauth_available:
    @user.route("/auth/github")
    def github_login():
        """Initiate GitHub OAuth login"""
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        
        if not current_app.config.get('GITHUB_OAUTH_ENABLED', False):
            flash("GitHub OAuth is not enabled.", "error")
            return redirect(url_for("user.login"))
        
        return redirect(url_for("github.login"))
    
    
    @user.route("/auth/github/callback")
    def github_callback():
        """Handle GitHub OAuth callback"""
        if not github.authorized:
            flash("Authorization failed.", "error")
            return redirect(url_for("user.login"))
        
        try:
            resp = github.get("/user")
            if not resp.ok:
                flash("Failed to fetch user info from GitHub.", "error")
                return redirect(url_for("user.login"))
            
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
                return redirect(url_for("user.login"))
            
            # Check if user already exists with this GitHub ID
            user_obj = User.get_by_github_id(github_id)
            if user_obj:
                login_user(user_obj, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash(f"Welcome back, {user_obj.username}!", "success")
                return redirect(url_for("index"))
            
            # Check if user exists with this email
            user_obj = User.get_by_email(github_email)
            if user_obj:
                # Link the GitHub account to existing user
                user_obj.link_github(github_id)
                user_obj.confirm_email()  # Auto-confirm email for OAuth users
                login_user(user_obj, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash(f"GitHub account linked successfully! Welcome back, {user_obj.username}!", "success")
                return redirect(url_for("index"))
            
            # Create new user account
            # Make sure username is unique
            username = github_username
            counter = 1
            while User.get(username):
                username = f"{github_username}{counter}"
                counter += 1
            
            try:
                user_obj = User.create(
                    username=username,
                    email=github_email,
                    password=None,  # No password for OAuth users
                    roles=[],
                    github_id=github_id
                )
                
                login_user(user_obj, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash(f"Account created successfully! Welcome, {user_obj.username}!", "success")
                return redirect(url_for("index"))
            except ValueError as e:
                flash("Failed to create account. Please try again.", "error")
                return redirect(url_for("user.login"))
                
        except Exception as e:
            current_app.logger.error(f"GitHub OAuth error: {e}")
            flash("Authentication failed. Please try again.", "error")
            return redirect(url_for("user.login"))
else:
    @user.route("/auth/github")
    def github_login():
        flash("GitHub OAuth is not available. Please install Flask-Dance.", "error")
        return redirect(url_for("user.login"))