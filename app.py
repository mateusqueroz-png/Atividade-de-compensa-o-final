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


# ---------- login / logout ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()                 # evita session fixation
            session.permanent = True        # expira em 30 min
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("index"))
        flash("E-mail ou senha inválidos.", "erro")  # mesma mensagem para qualquer falha
    return render_template("login.html")


@app.route("/logout", methods=["POST"])  # só POST (com token CSRF)
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- tarefas ----------
def get_my_task(task_id):
    """Busca a tarefa SOMENTE se for do usuário logado (evita acessar tarefa alheia)."""
    task = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"])).fetchone()
    if task is None:
        abort(404)
    return task


@app.route("/")
@login_required
def index():
    tasks = get_db().execute(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY done, id DESC",
        (session["user_id"],)).fetchall()
    return render_template("tasks.html", tasks=tasks)


def read_task_form():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    if not 1 <= len(title) <= 120:
        return None, None, "O título deve ter entre 1 e 120 caracteres."
    if len(description) > 500:
        return None, None, "A descrição pode ter no máximo 500 caracteres."
    return title, description, None


@app.route("/tasks/new", methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        title, description, error = read_task_form()
        if error is None:
            # user_id vem da sessão, nunca do formulário
            get_db().execute("INSERT INTO tasks (user_id, title, description) VALUES (?, ?, ?)",
                             (session["user_id"], title, description))
            get_db().commit()
            return redirect(url_for("index"))
        flash(error, "erro")
    return render_template("form.html", task=None)


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit(task_id):
    task = get_my_task(task_id)
    if request.method == "POST":
        title, description, error = read_task_form()
        if error is None:
            get_db().execute("UPDATE tasks SET title = ?, description = ? WHERE id = ? AND user_id = ?",
                             (title, description, task_id, session["user_id"]))
            get_db().commit()
            return redirect(url_for("index"))
        flash(error, "erro")
    return render_template("form.html", task=task)


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@login_required
def toggle(task_id):
    get_my_task(task_id)
    get_db().execute("UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?",
                     (task_id, session["user_id"]))
    get_db().commit()
    return redirect(url_for("index"))


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete(task_id):
    get_my_task(task_id)
    get_db().execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, session["user_id"]))
    get_db().commit()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
