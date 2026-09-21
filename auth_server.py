#!/usr/bin/env python3
"""
BadAS - a deliberately vulnerable authentication service.

WARNING
-------
This program is insecure by design. It exists so that reviewers can practise
finding common authentication and web-application flaws. Every shortcut in
this file is intentional and is catalogued in docs/VULNERABILITIES.md.

Do not deploy this. Do not expose it to an untrusted network. Do not copy any
of it into real software. Run it on 127.0.0.1 only.
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import time
import urllib.request
from datetime import datetime

from flask import Flask, Response, g, jsonify, redirect, render_template_string, request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("BADAS_DB", os.path.join(BASE_DIR, "badas.db"))
LOG_PATH = os.environ.get("BADAS_LOG", os.path.join(BASE_DIR, "badas.log"))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

SESSION_COOKIE = "session_id"
SECRET_KEY = "badas-session-secret"
JWT_SECRET = "badas-jwt-secret"
DEFAULT_ADMIN_PASSWORD = "password"

# In-memory session store for the single server process.
SESSIONS = {}

SEED_USERS = [
    ("root", DEFAULT_ADMIN_PASSWORD, "root@badas.local", "admin", "APIKEY-ROOT-0001"),
    ("alice", "alice123", "alice@badas.local", "user", "APIKEY-ALICE-0002"),
    ("bob", "hunter2", "bob@badas.local", "user", "APIKEY-BOB-0003"),
    ("dave", "dave", "dave@badas.local", "user", "APIKEY-DAVE-0004"),
]

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("badas")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def query_one(sql, params=()):
    connection = db()
    try:
        return connection.execute(sql, params).fetchone()
    finally:
        connection.close()


def query_all(sql, params=()):
    connection = db()
    try:
        return connection.execute(sql, params).fetchall()
    finally:
        connection.close()


def run_sql(sql, params=()):
    connection = db()
    try:
        connection.execute(sql, params)
        connection.commit()
    finally:
        connection.close()


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    connection = db()
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_md5 TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            api_key TEXT,
            reset_token TEXT,
            created_at TEXT
        )
        """
    )
    count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        for username, password, email, role, api_key in SEED_USERS:
            connection.execute(
                """
                INSERT INTO users
                    (username, password_md5, email, role, api_key, reset_token, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (username, md5(password), email, role, api_key, md5(username), datetime.utcnow().isoformat()),
            )
    connection.commit()
    connection.close()

    welcome = os.path.join(UPLOAD_DIR, "welcome.txt")
    if not os.path.exists(welcome):
        with open(welcome, "w", encoding="utf-8") as handle:
            handle.write("Welcome to BadAS.\nThere is nothing interesting in this file.\n")


# ---------------------------------------------------------------------------
# Tokens and sessions
# ---------------------------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def make_token(user):
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + 3600,
    }
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{b64url(signature)}"


def decode_token(token):
    header_b64, payload_b64, signature_b64 = token.split(".")
    header = json.loads(b64url_decode(header_b64))
    if header.get("alg") != "none":
        signing_input = f"{header_b64}.{payload_b64}".encode()
        expected = hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(signature_b64)):
            raise ValueError("bad signature")
    return json.loads(b64url_decode(payload_b64))


def current_session():
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id:
        return None
    return SESSIONS.get(session_id)


def start_session(user):
    session_id = request.cookies.get(SESSION_COOKIE) or str(random.randint(100000, 999999))
    SESSIONS[session_id] = {
        "username": user["username"],
        "role": user["role"],
        "created": time.time(),
    }
    return session_id


def attach_session(response, session_id, username):
    response.set_cookie(SESSION_COOKIE, session_id)
    response.set_cookie("remember", b64url(pickle.dumps({"username": username})))
    return response


def authenticate(username, password):
    sql = f"SELECT * FROM users WHERE username = '{username}' AND password_md5 = '{md5(password)}'"
    try:
        return query_one(sql), None
    except sqlite3.Error as exc:
        return None, str(exc)


def username_exists(username):
    try:
        return query_one(f"SELECT id FROM users WHERE username = '{username}'") is not None
    except sqlite3.Error:
        return False


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

LOGIN_PAGE = """<!doctype html>
<html>
  <head><title>BadAS login</title></head>
  <body>
    <h1>Sign in</h1>
    <form method="post" action="/login?next={{ next_url }}">
      <label>Username <input name="username"></label>
      <label>Password <input name="password" type="password"></label>
      <button type="submit">Sign in</button>
    </form>
    <p><a href="/register">Create an account</a></p>
  </body>
</html>
"""

REGISTER_PAGE = """<!doctype html>
<html>
  <head><title>BadAS registration</title></head>
  <body>
    <h1>Create an account</h1>
    <form method="post" action="/register">
      <label>Username <input name="username"></label>
      <label>Password <input name="password" type="password"></label>
      <label>Email <input name="email" type="email"></label>
      <button type="submit">Register</button>
    </form>
  </body>
</html>
"""


@app.before_request
def load_remember_cookie():
    cookie = request.cookies.get("remember")
    if not cookie:
        return
    try:
        g.remembered = pickle.loads(b64url_decode(cookie))
    except Exception:
        g.remembered = None


@app.after_request
def add_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.get("/")
def index():
    message = request.args.get("msg")
    if message is None:
        remembered = getattr(g, "remembered", None)
        if isinstance(remembered, dict) and remembered.get("username"):
            message = f"Welcome back, {remembered['username']}."
        else:
            message = "Welcome to BadAS, the intentionally broken auth service."
    return f"""<!doctype html>
<html>
  <head><title>BadAS</title></head>
  <body>
    <h1>BadAS</h1>
    <p>{message}</p>
    <p><a href="/login">Sign in</a> | <a href="/register">Register</a></p>
  </body>
</html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE, next_url=request.args.get("next", "/"))

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    logger.info("LOGIN username=%s password=%s", username, password)

    user, error = authenticate(username, password)
    if error:
        return f"<h1>Login error</h1><pre>{error}</pre>", 500
    if user is None:
        return f"<h1>Login failed</h1><p>Wrong password for {username}</p>", 401

    session_id = start_session(user)
    response = redirect(request.args.get("next", "/"))
    return attach_session(response, session_id, user["username"])


@app.get("/logout")
def logout():
    response = redirect("/")
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return REGISTER_PAGE

    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    email = data.get("email", "")

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if username_exists(username):
        return jsonify({"error": "username already taken"}), 409

    api_key = "APIKEY-" + md5(username)[:16]
    now = datetime.utcnow().isoformat()
    sql = (
        "INSERT INTO users (username, password_md5, email, role, api_key, reset_token, created_at) "
        f"VALUES ('{username}', '{md5(password)}', '{email}', 'user', '{api_key}', '{md5(username)}', '{now}')"
    )
    run_sql(sql)
    user = query_one(f"SELECT * FROM users WHERE username = '{username}'")
    return jsonify({"message": "Registered", "user": dict(user)}), 201


# ---------------------------------------------------------------------------
# User API
# ---------------------------------------------------------------------------

@app.post("/api/login")
def api_login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    logger.info("API LOGIN username=%s password=%s", username, password)

    user, error = authenticate(username, password)
    if error:
        return jsonify({"error": error}), 500
    if user is None:
        if username_exists(username):
            return jsonify({"error": f"Wrong password for {username}"}), 401
        return jsonify({"error": f"Unknown user {username}"}), 401

    session_id = start_session(user)
    response = jsonify({
        "message": "Success!",
        "token": make_token(user),
        "user": dict(user),
    })
    return attach_session(response, session_id, user["username"])


@app.get("/api/session")
def api_session():
    session = current_session()
    if session is None:
        return jsonify({"error": "not logged in"}), 401
    return jsonify({"session_id": request.cookies.get(SESSION_COOKIE), **session})


@app.get("/api/me")
def api_me():
    token = request.headers.get("Authorization", "")
    if token.startswith("Bearer "):
        token = token[7:]
    if not token:
        token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "missing token"}), 401

    try:
        claims = decode_token(token)
    except Exception as exc:
        return jsonify({"error": f"invalid token: {exc}"}), 401
    return jsonify({
        "username": claims.get("sub"),
        "role": claims.get("role"),
        "claims": claims,
    })


@app.post("/account/password")
def account_password():
    session = current_session()
    if session is None:
        return jsonify({"error": "login required"}), 401

    data = request.get_json(silent=True) or request.form
    new_password = data.get("password", "")
    if not new_password:
        return jsonify({"error": "password is required"}), 400

    run_sql(
        "UPDATE users SET password_md5 = "
        f"'{md5(new_password)}' WHERE username = '{session['username']}'"
    )
    logger.info("PASSWORD CHANGE username=%s password=%s", session["username"], new_password)
    return jsonify({"message": "Password changed"})


@app.get("/api/users/<int:user_id>")
def api_user_detail(user_id):
    user = query_one(f"SELECT * FROM users WHERE id = {user_id}")
    if user is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(dict(user))


@app.get("/api/users/search")
def api_user_search():
    term = request.args.get("q", "")
    sql = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{term}%'"
    try:
        users = query_all(sql)
    except sqlite3.Error as exc:
        return jsonify({"error": str(exc), "query": sql}), 500
    return jsonify([dict(user) for user in users])


@app.put("/api/users/<int:user_id>")
def api_user_update(user_id):
    changes = request.get_json(silent=True) or {}
    if not changes:
        return jsonify({"error": "no fields supplied"}), 400

    connection = db()
    try:
        for field, value in changes.items():
            connection.execute(f"UPDATE users SET {field} = '{value}' WHERE id = {user_id}")
        connection.commit()
    finally:
        connection.close()

    user = query_one(f"SELECT * FROM users WHERE id = {user_id}")
    if user is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(dict(user))


@app.delete("/api/users/<int:user_id>")
def api_user_delete(user_id):
    run_sql(f"DELETE FROM users WHERE id = {user_id}")
    return jsonify({"message": f"user {user_id} deleted"})


# ---------------------------------------------------------------------------
# Admin
# ---------------------------------------------------------------------------

@app.get("/admin/users")
def admin_users():
    if request.headers.get("X-Admin") != "true":
        return jsonify({"error": "admin access required"}), 403
    return jsonify([dict(user) for user in query_all("SELECT * FROM users")])


@app.get("/admin/export")
def admin_export():
    users = query_all("SELECT * FROM users")
    lines = ["id,username,password_md5,email,role,api_key,reset_token,created_at"]
    for user in users:
        lines.append(",".join(str(user[key]) for key in user.keys()))
    return Response("\n".join(lines), mimetype="text/csv")


@app.get("/admin/audit")
def admin_audit():
    if not os.path.exists(LOG_PATH):
        return Response("", mimetype="text/plain")
    with open(LOG_PATH, "r", errors="replace") as handle:
        return Response(handle.read(), mimetype="text/plain")


# ---------------------------------------------------------------------------
# "Utility" endpoints
# ---------------------------------------------------------------------------

@app.get("/files")
def files():
    name = request.args.get("name", "welcome.txt")
    path = os.path.join(UPLOAD_DIR, name)
    try:
        with open(path, "r", errors="replace") as handle:
            content = handle.read()
    except OSError as exc:
        return f"<h1>File not found</h1><pre>{exc}</pre>", 404
    return Response(content, mimetype="text/plain")


@app.get("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "missing url", 400
    try:
        with urllib.request.urlopen(url, timeout=5) as remote:
            body = remote.read().decode("utf-8", "replace")
    except Exception as exc:
        return Response(f"fetch failed: {exc}", status=500, mimetype="text/plain")
    return Response(body, mimetype="text/plain")


@app.get("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    command = "ping -c 1 " + host
    try:
        output = subprocess.check_output(
            command, shell=True, stderr=subprocess.STDOUT, timeout=5
        )
    except subprocess.CalledProcessError as exc:
        output = exc.output
    return Response(output.decode("utf-8", "replace"), mimetype="text/plain")


@app.get("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string("Hello, " + name)


@app.post("/api/calc")
def calc():
    data = request.get_json(silent=True) or {}
    expression = data.get("expr") or request.args.get("expr", "")
    if not expression:
        return jsonify({"error": "missing expr"}), 400
    return jsonify({"expr": expression, "result": eval(expression)})


# ---------------------------------------------------------------------------
# Password reset and diagnostics
# ---------------------------------------------------------------------------

@app.post("/reset/request")
def reset_request():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    user = query_one(f"SELECT * FROM users WHERE username = '{username}'")
    if user is None:
        return jsonify({"error": "no such user"}), 404

    token = md5(username)
    run_sql(f"UPDATE users SET reset_token = '{token}' WHERE id = {user['id']}")
    logger.info("PASSWORD RESET REQUEST username=%s token=%s", username, token)
    return jsonify({
        "message": f"Password reset link sent to {user['email']}",
        "token": token,
    })


@app.post("/reset/confirm")
def reset_confirm():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    token = data.get("token", "")
    new_password = data.get("password", "")

    user = query_one(
        f"SELECT * FROM users WHERE username = '{username}' AND reset_token = '{token}'"
    )
    if user is None:
        return jsonify({"error": "invalid token"}), 400

    run_sql(
        "UPDATE users SET password_md5 = "
        f"'{md5(new_password)}' WHERE id = {user['id']}"
    )
    logger.info("PASSWORD RESET CONFIRM username=%s password=%s", username, new_password)
    return jsonify({"message": "Password updated"})


@app.get("/debug")
def debug_info():
    return jsonify({
        "config": {key: str(value) for key, value in app.config.items()},
        "secrets": {"SECRET_KEY": SECRET_KEY, "JWT_SECRET": JWT_SECRET},
        "db_path": DB_PATH,
        "log_path": LOG_PATH,
        "sessions": SESSIONS,
        "users": [dict(user) for user in query_all("SELECT * FROM users")],
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Run the deliberately vulnerable BadAS server.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=5001, help="listen port (default: 5001)")
    parser.add_argument("--no-debug", action="store_true", help="disable Flask debug mode")
    args = parser.parse_args()

    init_db()
    app.run(
        host=args.host,
        port=args.port,
        debug=not args.no_debug,
        use_reloader=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
