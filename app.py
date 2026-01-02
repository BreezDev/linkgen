import os
import hashlib
import secrets
from datetime import datetime, timedelta

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "linkgen.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "storage")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def _get_max_upload_bytes(default_mb: int = 5120) -> int:
    try:
        return int(os.getenv("MAX_UPLOAD_MB", str(default_mb))) * 1024 * 1024
    except ValueError:
        return default_mb * 1024 * 1024


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = _get_max_upload_bytes()

ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
if not ADMIN_PASSWORD_HASH:
    fallback_password = ADMIN_PASSWORD or "admin-change-me"
    ADMIN_PASSWORD_HASH = generate_password_hash(fallback_password)


db = SQLAlchemy(app)

_db_initialized = False


def _ensure_database_initialized():
    global _db_initialized
    if _db_initialized:
        return
    with app.app_context():
        db.create_all()
    _db_initialized = True


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    display_name = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)


class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    token_hash = db.Column(db.String(255), nullable=False, unique=True, index=True)
    status = db.Column(db.String(50), default="unused", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    used_at = db.Column(db.DateTime)
    customer_email = db.Column(db.String(255))
    order_id = db.Column(db.String(255))
    used_ip = db.Column(db.String(255))
    used_user_agent = db.Column(db.Text)

    file = db.relationship("File")

    @property
    def is_expired(self):
        return self.expires_at is not None and datetime.utcnow() > self.expires_at


@app.before_request
def load_globals():
    _ensure_database_initialized()
    g.is_admin = session.get("is_admin", False)


@app.route("/")
def landing():
    return render_template("landing.html")


@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    print("Database initialized at", DB_PATH)


def require_admin():
    if not session.get("is_admin"):
        return redirect(url_for("login", next=request.path))
    return None


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["is_admin"] = True
            flash("Logged in successfully.", "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        flash("Invalid password", "danger")
    return render_template("login.html")


@app.route("/admin/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/admin")
def dashboard():
    redirect_resp = require_admin()
    if redirect_resp:
        return redirect_resp

    files = File.query.order_by(File.uploaded_at.desc()).all()
    links = DownloadLink.query.order_by(DownloadLink.created_at.desc()).limit(20).all()
    stats = {
        "files": File.query.count(),
        "links_total": DownloadLink.query.count(),
        "links_unused": DownloadLink.query.filter_by(status="unused").count(),
        "links_used": DownloadLink.query.filter_by(status="used").count(),
        "links_revoked": DownloadLink.query.filter_by(status="revoked").count(),
    }
    max_upload_bytes = app.config.get("MAX_CONTENT_LENGTH", 0)
    max_upload_mb = max_upload_bytes // (1024 * 1024) if max_upload_bytes else 0
    max_upload_gb = round(max_upload_bytes / (1024 * 1024 * 1024), 2) if max_upload_bytes else 0
    return render_template(
        "dashboard.html",
        files=files,
        links=links,
        stats=stats,
        max_upload_mb=max_upload_mb,
        max_upload_gb=max_upload_gb,
    )


@app.route("/admin/files/upload", methods=["POST"])
def upload_file():
    redirect_resp = require_admin()
    if redirect_resp:
        return redirect_resp

    upload = request.files.get("file")
    display_name = request.form.get("display_name") or (upload.filename if upload else "") or "Untitled"
    notes = request.form.get("notes")
    upload_mode = request.form.get("upload_mode", "file")
    content_input = request.form.get("content_input", "").strip()

    if upload_mode == "text":
        if not content_input:
            flash("Please paste a link or some text to save.", "danger")
            return redirect(url_for("dashboard"))
        safe_name = secure_filename(display_name) if display_name else "content"
        filename = f"{safe_name or 'content'}-{int(datetime.utcnow().timestamp())}.txt"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content_input)
        size_bytes = os.path.getsize(filepath)
        original_filename = filename
    else:
        if not upload or upload.filename == "":
            flash("Please select a ZIP file to upload.", "danger")
            return redirect(url_for("dashboard"))
        filename = secure_filename(upload.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        upload.save(filepath)
        size_bytes = os.path.getsize(filepath)
        original_filename = filename

    record = File(
        display_name=display_name,
        original_filename=original_filename,
        storage_path=filepath,
        size_bytes=size_bytes,
        notes=notes,
    )
    db.session.add(record)
    db.session.commit()
    flash("File uploaded.", "success")
    return redirect(url_for("dashboard"))


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


@app.route("/admin/links/generate", methods=["POST"])
def generate_links():
    redirect_resp = require_admin()
    if redirect_resp:
        return redirect_resp

    file_id = request.form.get("file_id")
    try:
        count = int(request.form.get("count") or 1)
    except ValueError:
        flash("Please enter a valid link count.", "danger")
        return redirect(url_for("dashboard"))
    expires_days = request.form.get("expires_days")
    customer_emails = [e.strip() for e in request.form.get("customer_emails", "").splitlines() if e.strip()]
    order_prefix = request.form.get("order_prefix", "").strip() or None

    if not file_id:
        flash("Please select a file.", "danger")
        return redirect(url_for("dashboard"))

    selected_file = File.query.get(int(file_id))
    if not selected_file:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    expires_at = None
    if expires_days:
        try:
            expires_at = datetime.utcnow() + timedelta(days=int(expires_days))
        except ValueError:
            flash("Invalid expiration days.", "danger")
            return redirect(url_for("dashboard"))

    links = []
    total_links = max(len(customer_emails), count)
    for i in range(total_links):
        token = _generate_token()
        token_hash = _hash_token(token)
        email = customer_emails[i] if i < len(customer_emails) else None
        order_id = f"{order_prefix}{i+1}" if order_prefix else None
        link = DownloadLink(
            file=selected_file,
            token_hash=token_hash,
            status="unused",
            expires_at=expires_at,
            customer_email=email,
            order_id=order_id,
        )
        db.session.add(link)
        links.append((link, token))
    db.session.commit()

    return render_template("generated_links.html", links=links, file=selected_file)


@app.route("/admin/links")
def admin_links():
    redirect_resp = require_admin()
    if redirect_resp:
        return redirect_resp

    email = request.args.get("email")
    order_id = request.args.get("order_id")
    query = DownloadLink.query.order_by(DownloadLink.created_at.desc())
    if email:
        query = query.filter(DownloadLink.customer_email.ilike(f"%{email}%"))
    if order_id:
        query = query.filter(DownloadLink.order_id.ilike(f"%{order_id}%"))
    links = query.limit(200).all()
    return render_template("links.html", links=links)


@app.route("/admin/links/<int:link_id>/revoke", methods=["POST"])
def revoke_link(link_id):
    redirect_resp = require_admin()
    if redirect_resp:
        return redirect_resp

    link = DownloadLink.query.get_or_404(link_id)
    link.status = "revoked"
    db.session.commit()
    flash("Link revoked.", "info")
    return redirect(request.referrer or url_for("admin_links"))


@app.route("/dl/<token>")
def download_page(token):
    token_hash = _hash_token(token)
    link = DownloadLink.query.filter_by(token_hash=token_hash).first()
    if not link:
        abort(404)

    file = link.file
    if link.status == "revoked":
        return render_template("error.html", message="This link is no longer available."), 410
    if link.is_expired:
        return render_template("error.html", message="Link expired. Contact support."), 410
    if link.status == "used":
        return render_template("error.html", message="This link has already been used."), 410

    return render_template("download.html", link=link, file=file, token=token)


@app.route("/dl/<token>/download", methods=["POST"])
def perform_download(token):
    token_hash = _hash_token(token)
    link = DownloadLink.query.filter_by(token_hash=token_hash).first()
    if not link:
        abort(404)

    if link.status in {"used", "revoked"}:
        return render_template("error.html", message="This link has already been used."), 410
    if link.is_expired:
        return render_template("error.html", message="Link expired. Contact support."), 410

    updated = DownloadLink.query.filter_by(token_hash=token_hash, status="unused").update(
        {
            "status": "used",
            "used_at": datetime.utcnow(),
            "used_ip": request.remote_addr,
            "used_user_agent": request.headers.get("User-Agent"),
        },
        synchronize_session=False,
    )
    if updated == 0:
        db.session.rollback()
        return render_template("error.html", message="This link has already been used."), 410
    db.session.commit()

    file = link.file
    if not os.path.exists(file.storage_path):
        return render_template("error.html", message="File unavailable. Please contact support."), 410

    return send_file(
        file.storage_path,
        as_attachment=True,
        download_name=file.original_filename,
    )


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="Not found."), 404


@app.errorhandler(413)
def payload_too_large(_):
    max_bytes = app.config.get("MAX_CONTENT_LENGTH", 0)
    max_mb = max_bytes // (1024 * 1024)
    max_gb = round(max_bytes / (1024 * 1024 * 1024), 2) if max_bytes else 0
    message = "File too large. Please upload a smaller file"
    if max_mb:
        message += f" (limit: {max_mb} MB / {max_gb} GB)."
    else:
        message += "."
    return render_template("error.html", message=message), 413


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
