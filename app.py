import os
import random
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "yerel-gelistirme-anahtari")
database_url = os.environ.get("DATABASE_URL", "sqlite:///kitap.db")

if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

ADMIN_EMAIL = "tfyebirligiedittvshorts@gmail.com"
SENDER_EMAIL = os.environ.get("MAIL_USERNAME", "bbagimliolmaozgurol@gmail.com")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    display_name = db.Column(db.String(80), default="Okuyucu")
    profile_photo = db.Column(db.String(500), default="")
    password_hash = db.Column(db.String(300), nullable=True)
    is_authorized = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False)
    code_hash = db.Column(db.String(300), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


class SupportTicket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    subject = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")


class SupportMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("support_ticket.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.String(2000), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User")


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def is_admin():
    user = current_user()
    return bool(user and user.email.lower() == ADMIN_EMAIL.lower())


def can_manage_support():
    user = current_user()
    return bool(user and (is_admin() or user.is_authorized))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not is_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def send_email(to, subject, body):
    host = os.environ.get("MAIL_SERVER")
    username = os.environ.get("MAIL_USERNAME")
    password = os.environ.get("MAIL_PASSWORD")

    if not all([host, username, password]):
        raise RuntimeError("E-posta ayarları henüz yapılmadı.")

    message = EmailMessage()
    message["From"] = username
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(host, int(os.environ.get("MAIL_PORT", "587"))) as server:
        server.starttls()
        server.login(username, password)
        server.send_message(message)


@app.context_processor
def inject_user():
    return {
        "user": current_user(),
        "admin": is_admin(),
        "support_manager": can_manage_support()
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/giris", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("home"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email or "@" not in email:
            flash("Geçerli bir e-posta adresi gir.")
            return redirect(url_for("login"))

        code = str(random.randint(100000, 999999))

        LoginCode.query.filter_by(email=email).delete()
        record = LoginCode(
            email=email,
            code_hash=generate_password_hash(code),
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(record)
        db.session.commit()

        try:
            send_email(
                email,
                "Giriş doğrulama kodun",
                f"Giriş kodun: {code}\nBu kod 5 dakika geçerlidir."
            )
        except Exception:
            db.session.delete(record)
            db.session.commit()
            flash("E-posta gönderilemedi. Sistem ayarları kontrol edilmeli.")
            return redirect(url_for("login"))

        session["pending_email"] = email
        flash("Doğrulama kodu e-posta adresine gönderildi.")
        return redirect(url_for("verify"))

    return render_template("login.html")


@app.route("/kod", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email")

    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        record = LoginCode.query.filter_by(email=email).first()

        if (
            not record
            or record.expires_at < datetime.utcnow()
            or not check_password_hash(record.code_hash, code)
        ):
            flash("Kod hatalı veya süresi dolmuş.")
            return redirect(url_for("verify"))

        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(email=email)
            db.session.add(user)
            db.session.flush()

        db.session.delete(record)
        db.session.commit()

        session.clear()
        session["user_id"] = user.id
        session.permanent = True

        return redirect(url_for("home"))

    return render_template("verify.html")


@app.route("/cikis")
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/profil", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()

    if request.method == "POST":
        name = request.form.get("display_name", "").strip()
        photo = request.form.get("profile_photo", "").strip()

        if name:
            user.display_name = name[:80]

        user.profile_photo = photo[:500]
        db.session.commit()

        flash("Profil güncellendi.")
        return redirect(url_for("profile"))

    return render_template("profile.html")


@app.route("/destek", methods=["GET", "POST"])
@login_required
def support():
    if not can_manage_support():
        abort(403)

    if request.method == "POST":
        subject = request.form.get("subject", "").strip()

        if subject:
            ticket = SupportTicket(
                user_id=current_user().id,
                subject=subject[:150]
            )
            db.session.add(ticket)
            db.session.commit()
            return redirect(url_for("ticket", ticket_id=ticket.id))

    tickets = SupportTicket.query.filter_by(status="open").order_by(
        SupportTicket.created_at.desc()
    ).all()

    return render_template("support.html", tickets=tickets)


@app.route("/destek/<int:ticket_id>", methods=["GET", "POST"])
@login_required
def ticket(ticket_id):
    ticket_item = db.session.get(SupportTicket, ticket_id)

    if not ticket_item:
        abort(404)

    user = current_user()
    allowed = (
        ticket_item.user_id == user.id
        or is_admin()
        or user.is_authorized
    )

    if not allowed:
        abort(403)

    if request.method == "POST":
        message = request.form.get("message", "").strip()

        if message and ticket_item.status == "open":
            db.session.add(SupportMessage(
                ticket_id=ticket_id,
                user_id=user.id,
                message=message[:2000]
            ))
            db.session.commit()

        return redirect(url_for("ticket", ticket_id=ticket_id))

    messages = SupportMessage.query.filter_by(
        ticket_id=ticket_id
    ).order_by(SupportMessage.created_at.asc()).all()

    return render_template(
        "ticket.html",
        ticket=ticket_item,
        messages=messages
    )


@app.route("/destek/<int:ticket_id>/kapat", methods=["POST"])
@login_required
def close_ticket(ticket_id):
    ticket_item = db.session.get(SupportTicket, ticket_id)

    if not ticket_item:
        abort(404)

    user = current_user()

    if not (
        ticket_item.user_id == user.id
        or is_admin()
        or user.is_authorized
    ):
        abort(403)

    ticket_item.status = "closed"
    db.session.commit()

    return redirect(url_for("support"))


@app.route("/yonetim", methods=["GET", "POST"])
@admin_required
def admin_panel():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "yetki":
            user_id = request.form.get("user_id", type=int)
            target = db.session.get(User, user_id)

            if target and target.email.lower() != ADMIN_EMAIL.lower():
                target.is_authorized = request.form.get("enabled") == "1"
                db.session.commit()

        elif action == "duyuru":
            subject = request.form.get("subject", "").strip()
            body = request.form.get("body", "").strip()

            if subject and body:
                recipients = User.query.with_entities(User.email).all()

                for recipient in recipients:
                    try:
                        send_email(recipient[0], subject, body)
                    except Exception:
                        app.logger.exception("Duyuru gönderilemedi: %s", recipient[0])

                flash("Duyuru gönderim işlemi tamamlandı.")

        return redirect(url_for("admin_panel"))

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin.html", users=users)


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", message="Bu sayfaya erişim iznin yok."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", message="Sayfa bulunamadı."), 404


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
