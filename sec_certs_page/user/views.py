from datetime import datetime, timezone
from secrets import token_hex

from bson import ObjectId
from flask import abort, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_dance.contrib.github import github
from flask_login import current_user, login_required, login_user, logout_user
from flask_principal import AnonymousIdentity, Identity, identity_changed

from .. import app, mongo
from ..common.permissions import admin_permission
from ..common.views import check_captcha, register_breadcrumb
from . import user
from .forms import LoginForm, MagicLinkForm, PasswordResetForm, PasswordResetRequestForm, RegisterForm
from .models import User, UserExistsError
from .tasks import send_confirmation_email, send_magic_link_email, send_password_reset_email


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
        if not check_captcha(form.turnstile.data, request.remote_addr):
            flash("CAPTCHA validation failed. Please try again.", "error")
            return render_template("user/register.html.jinja2", form=form), 400
        # Create user
        try:
            new_user = User.create(username=form.username.data, email=form.email.data, password=form.password.data)
            send_confirmation_email.send(new_user.username)
            flash("Registration successful! Please check your email to confirm your account.", "success")
            return redirect(url_for("user.login"))
        except UserExistsError:
            flash("A user with that username or email already exists.", "error")
        except Exception:
            raise

    return render_template("user/register.html.jinja2", form=form)


@user.route("/confirm-email/<token>")
def confirm_email(token):
    user = User.verify_token(token, "email_confirmation")
    if user:
        user.confirm_email()
        user.consume_token(token, "email_confirmation")
        flash("Email confirmed successfully! You can now log in.", "success")
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
        user = User.get_by_email(form.email.data)
        if user:
            send_password_reset_email.send(user.username)
        flash("If the email exists in our system, you will receive password reset instructions.", "info")
        return redirect(url_for("user.login"))

    return render_template("user/forgot_password.html.jinja2", form=form)


@user.route("/change-password")
@login_required
@register_breadcrumb(user, ".change_password", "Change Password")
def change_password():
    send_password_reset_email.send(current_user.username)

    flash("You will receive password reset instructions.", "info")
    return redirect(url_for("index"))


@user.route("/reset-password/<token>", methods=["GET", "POST"])
@register_breadcrumb(user, ".reset_password", "Reset Password")
def reset_password(token):
    user = User.verify_token(token, "password_reset")
    if not user:
        flash("Invalid or expired reset link.", "error")
        return redirect(url_for("user.forgot_password"))

    if current_user.is_authenticated:
        if current_user.username != user.username:
            flash("Invalid or expired reset link.", "error")
            return redirect(url_for("user.forgot_password"))

    form = PasswordResetForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        flash("Password reset successfully! You can now log in.", "success")
        user.consume_token(token, "password_reset")
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
            send_magic_link_email.send(user_obj.username)
        flash("If the email exists and is confirmed, you will receive a login link.", "info")
        return redirect(url_for("user.login"))

    return render_template("user/magic_link.html.jinja2", form=form)


@user.route("/magic-login/<token>")
def magic_login(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    user_obj = User.verify_token(token, "magic_link")
    if user_obj and user_obj.email_confirmed:
        login_user(user_obj, remember=True)
        identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
        flash("You've been successfully logged in via email link.", "success")
        return redirect(url_for("index"))
    else:
        flash("Invalid or expired login link.", "error")

    return redirect(url_for("user.login"))


@user.route("/profile")
@login_required
@register_breadcrumb(user, ".profile", "Profile")
def profile():
    return render_template("user/profile.html.jinja2", user=current_user)


@user.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    # Remove user from database
    current_user.delete()

    # Also clean up any related data
    current_user.clear_tokens()

    logout_user()
    for key in ("identity.name", "identity.auth_type"):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())

    flash("Your account has been deleted successfully.", "info")
    return redirect(url_for("index"))


# GitHub OAuth routes
if app.config["GITHUB_OAUTH_ENABLED"]:

    @user.route("/auth/github")
    def github_login():
        """Initiate GitHub OAuth login"""
        if current_user.is_authenticated:
            return redirect(url_for("index"))

        if not current_app.config.get("GITHUB_OAUTH_ENABLED", False):
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
            verified_emails = [github_email] if github_email else []

            # Try to get email from user's public emails
            email_resp = github.get("/user/emails")
            if email_resp.ok:
                emails = email_resp.json()
                verified_emails.extend([e["email"] for e in emails if e.get("verified")])
                if github_email is None:
                    github_email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)

            if not github_email:
                flash("GitHub account must have at least one verified email address.", "error")
                return redirect(url_for("user.login"))

            # Check if user already exists with this GitHub ID
            user_obj = User.get_by_github_id(github_id)
            if user_obj:
                login_user(user_obj, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash(f"Welcome back, {user_obj.username}!", "success")
                return redirect(url_for("index"))

            # Check if user exists with some email
            for email in verified_emails:
                user_obj = User.get_by_email(email)
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
                    roles=User.DEFAULT_ROLES,
                    github_id=github_id,
                )

                login_user(user_obj, remember=True)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user_obj.id))
                flash(f"Account created successfully! Welcome, {user_obj.username}!", "success")
                return redirect(url_for("index"))
            except ValueError as e:
                flash("Failed to create account. Please try again.", "error")
                return redirect(url_for("user.login"))

        except Exception as e:
            flash("Authentication failed. Please try again.", "error")
            return redirect(url_for("user.login"))

else:

    @user.route("/auth/github")
    def github_login():
        flash("GitHub OAuth is not available. Please install Flask-Dance.", "error")
        return redirect(url_for("user.login"))
