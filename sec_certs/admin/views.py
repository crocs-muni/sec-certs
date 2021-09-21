from flask import render_template, current_app, flash, redirect, url_for
from flask_login import login_user, logout_user, login_required
from flask_principal import identity_changed, Identity
from flask_breadcrumbs import register_breadcrumb

from . import admin
from .forms import LoginForm
from .user import User


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
                return redirect(url_for("index"))
            else:
                flash("Bad.", "error")
    return render_template("admin/login.html.jinja2", form=form)


@admin.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You've been successfully logged out.", "info")
    return redirect(url_for("index"))
