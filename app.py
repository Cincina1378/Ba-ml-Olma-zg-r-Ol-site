import os
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

database_url = os.environ.get("DATABASE_URL", "sqlite:///site.db")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)

db = SQLAlchemy(app)

ADMIN_EMAIL = "tfyebirligiedittvshorts@gmail.com"
SENDER_EMAIL = "bbagimliolmaozgurol@gmail.com"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    display_name = db.Column(db.String(100), default="Üye")
    profile_photo = db.Column(db.String(1000), default="")
    authorized = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LoginCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(20), default="open")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TicketMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey("ticket.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def send_email(to, subject, body):
    username = os.environ.get("MAIL_USERNAME", SENDER_EMAIL)
    password = os.environ.get("MAIL_PASSWORD")
    server = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    port = int(os.environ.get("MAIL_PORT", "587"))

    if not password:
        raise RuntimeError("MAIL_PASSWORD ayarlanmamış.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = username
    message["To"] = to
    message.set_content(body)

    with smtplib.SMTP(server, port) as smtp:
        smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(message)


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.session.get(User, user_id)


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def authorized_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or (user.email != ADMIN_EMAIL and not user.authorized):
            flash("Bu sayfaya erişim yetkiniz yok.")
            return redirect(url_for("index"))
        return function(*args, **kwargs)
    return wrapper


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user.email != ADMIN_EMAIL:
            flash("Yönetici erişimi gerekli.")
            return redirect(url_for("index"))
        return function(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/giris", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email or "@" not in email:
            flash("Geçerli bir e-posta adresi girin.")
            return redirect(url_for("login"))

        code = f"{secrets.randbelow(1000000):06d}"

        LoginCode.query.filter_by(email=email).delete()
        login_code = LoginCode(
            email=email,
            code_hash=generate_password_hash(code),
            expires_at=datetime.utcnow() + timedelta(minutes=5)
        )
        db.session.add(login_code)
        db.session.commit()

        try:
            send_email(
                email,
                "Bağımlı Olma Özgür Ol! - Giriş kodu",
                f"Giriş kodunuz: {code}\nBu kod 5 dakika geçerlidir."
            )
        except Exception:
            db.session.delete(login_code)
            db.session.commit()
            flash("E-posta gönderilemedi. Ayarları kontrol edin.")
            return redirect(url_for("login"))

        session["pending_email"] = email
        return redirect(url_for("verify"))

    return render_template("login.html")


@app.route("/dogrula", methods=["GET", "POST"])
def verify():
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        login_code = LoginCode.query.filter_by(email=email).first()

        if (
            not login_code
            or login_code.expires_at < datetime.utcnow()
            or not check_password_hash(login_code.code_hash, code)
        ):
            flash("Kod hatalı veya süresi dolmuş.")
            return redirect(url_for("verify"))

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            db.session.add(user)

        db.session.delete(login_code)
        db.session.commit()

        session.clear()
        session.permanent = True
        session["user_id"] = user.id

        return redirect(url_for("index"))

    return render_template("verify.html")


@app.route("/cikis")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/profil", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()

    if request.method == "POST":
        display_name = request.form.get("display_name", "").strip()
        photo_url = request.form.get("profile_photo", "").strip()

        if display_name:
            user.display_name = display_name[:100]

        user.profile_photo = photo_url[:1000]
        db.session.commit()
        flash("Profil güncellendi.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


@app.route("/kitap/<int:book_id>")
def book(book_id):
    return render_template("book.html", book_id=book_id)


@app.route("/yonetim")
@admin_required
def admin():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin.html", users=users)


@app.route("/yonetim/yetki/<int:user_id>", methods=["POST"])
@admin_required
def change_authority(user_id):
    user = db.session.get(User, user_id)

    if not user:
        flash("Kullanıcı bulunamadı.")
        return redirect(url_for("admin"))

    if user.email == ADMIN_EMAIL:
        flash("Ana yöneticinin yetkisi değiştirilemez.")
        return redirect(url_for("admin"))

    user.authorized = not user.authorized
    db.session.commit()
    flash("Yetki güncellendi.")
    return redirect(url_for("admin"))


@app.route("/yonetim/duyuru", methods=["POST"])
@admin_required
def bulk_email():
    subject = request.form.get("subject", "").strip()
    body = request.form.get("message", "").strip()

    if not subject or not body:
        flash("Başlık ve mesaj gerekli.")
        return redirect(url_for("admin"))

    users = User.query.all()
    sent = 0

    for user in users:
        try:
            send_email(user.email, subject, body)
            sent += 1
        except Exception:
            continue

    flash(f"{sent} kişiye e-posta gönderildi.")
    return redirect(url_for("admin"))


@app.route("/destek")
@authorized_required
def support():
    tickets = Ticket.query.order_by(Ticket.created_at.desc()).all()
    return render_template("support.html", tickets=tickets)


@app.route("/destek/yeni", methods=["POST"])
@authorized_required
def create_ticket():
    title = request.form.get("title", "").strip()

    if not title:
        flash("Destek başlığı gerekli.")
        return redirect(url_for("support"))

    ticket = Ticket(user_id=current_user().id, title=title[:150])
    db.session.add(ticket)
    db.session.commit()

    return redirect(url_for("ticket", ticket_id=ticket.id))


@app.route("/destek/<int:ticket_id>")
@authorized_required
def ticket(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)

    if not ticket:
        return "Destek bulunamadı.", 404

    user = current_user()
    if user.email != ADMIN_EMAIL and ticket.user_id != user.id:
        return "Bu desteğe erişim izniniz yok.", 403

    messages = TicketMessage.query.filter_by(
        ticket_id=ticket.id
    ).order_by(TicketMessage.created_at.asc()).all()

    return render_template("ticket.html", ticket=ticket, messages=messages)


@app.route("/destek/<int:ticket_id>/mesaj", methods=["POST"])
@authorized_required
def send_ticket_message(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)

    if not ticket:
        return "Destek bulunamadı.", 404

    user = current_user()
    if user.email != ADMIN_EMAIL and ticket.user_id != user.id:
        return "Bu desteğe erişim izniniz yok.", 403

    if ticket.status != "open":
        flash("Bu destek görüşmesi kapatılmış.")
        return redirect(url_for("ticket", ticket_id=ticket.id))

    message = request.form.get("message", "").strip()

    if message:
        db.session.add(TicketMessage(
            ticket_id=ticket.id,
            user_id=user.id,
            message=message[:5000]
        ))
        db.session.commit()

    return redirect(url_for("ticket", ticket_id=ticket.id))


@app.route("/destek/<int:ticket_id>/kapat", methods=["POST"])
@authorized_required
def close_ticket(ticket_id):
    ticket = db.session.get(Ticket, ticket_id)

    if not ticket:
        return "Destek bulunamadı.", 404

    user = current_user()
    if user.email != ADMIN_EMAIL and ticket.user_id != user.id:
        return "Bu desteğe erişim izniniz yok.", 403

    ticket.status = "closed"
    db.session.commit()

    return redirect(url_for("support"))


@app.errorhandler(404)
def not_found(error):
    return "Sayfa bulunamadı.", 404


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
