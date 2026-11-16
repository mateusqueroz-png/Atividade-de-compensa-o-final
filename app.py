import os
import re
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from dotenv import load_dotenv
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)
app.config.update(
    # Segredo vem do ambiente (.env), nunca do código.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    DATABASE=os.path.join(app.instance_path, "app.db"),
    SESSION_COOKIE_HTTPONLY=True,          # JavaScript não lê o cookie
    SESSION_COOKIE_SAMESITE="Lax",         # reduz risco de CSRF
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)  # exige token CSRF em todo POST


# ---------- banco de dados ----------
def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        with app.open_resource("schema.sql") as f:
            g.db.executescript(f.read().decode())
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- cabeçalhos de segurança ----------
@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; object-src 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    if request.endpoint != "static":
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(413)
@app.errorhandler(500)
def erro(e):
    # Mensagem genérica: nunca mostra detalhes internos.
    code = getattr(e, "code", 500)
    return render_template("erro.html", code=code), code


# ---------- cadastro ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        error = None
        if not 2 <= len(name) <= 80:
            error = "O nome deve ter entre 2 e 80 caracteres."
        elif len(email) > 254 or not EMAIL_RE.match(email):
            error = "E-mail inválido."
        elif not 8 <= len(password) <= 128:
            error = "A senha deve ter entre 8 e 128 caracteres."
        elif not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
            error = "A senha deve ter letras e números."

        if error is None:
            try:
                get_db().execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, generate_password_hash(password)))  # senha NUNCA em texto puro
                get_db().commit()
                flash("Conta criada! Faça login.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                # Mensagem genérica: não revela se o e-mail já existe.
                error = "Não foi possível criar a conta com esses dados."
        flash(error, "erro")
    return render_template("register.html")
