from datetime import datetime, timezone

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import select
from urllib.parse import unquote, urlsplit

from phishing_app.extensions import db, limiter
from phishing_app.forms import LoginForm, RegistrationForm
from phishing_app.models import AuditLog, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if db.session.scalar(select(User.id).where(User.email == email)) is not None:
            flash("An account already exists for that email address.", "error")
        else:
            user = User(full_name=form.full_name.data.strip(), email=email)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.flush()
            db.session.add(AuditLog(actor_id=user.id, action="account.registered", metadata_json={}))
            db.session.commit()
            login_user(user)
            flash("Your account is ready.", "success")
            return redirect(url_for("main.dashboard"))
    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = db.session.scalar(select(User).where(User.email == email))
        if user is None or not user.is_active or not user.check_password(form.password.data):
            flash("Email or password is incorrect.", "error")
        else:
            user.last_login_at = datetime.now(timezone.utc)
            db.session.add(AuditLog(actor_id=user.id, action="account.login", metadata_json={}))
            db.session.commit()
            login_user(user, remember=form.remember.data, fresh=True)
            target = request.args.get("next", "")
            path = unquote(urlsplit(target).path)
            if urlsplit(target).scheme or urlsplit(target).netloc or not path.startswith("/") or path.startswith("//") or "\\" in path:
                target = url_for("main.dashboard")
            return redirect(target)
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    db.session.add(AuditLog(actor_id=current_user.id, action="account.logout", metadata_json={}))
    db.session.commit()
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))
