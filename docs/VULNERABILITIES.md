# BadAS vulnerability answer key

> **SPOILER WARNING**
> This document lists every planted flaw, how to exploit it, and how to fix it.
> If you are doing the exercise, read `docs/REVIEW_GUIDE.md` first and write
> your own findings before continuing.

BadAS maps to the [OWASP Top 10 2021](https://owasp.org/Top10/). The table
below is the index; each finding has a detailed entry with a location, impact,
and mitigation, plus an exploit where one applies. Severity is the rough impact
of the flaw in this lab, not a formal CVSS score.

## Summary

| ID | OWASP | CWE | Finding | Location | Severity |
|---|---|---|---|---|---|
| A01-1 | A01 | 639 | IDOR exposes any user's profile, hash, API key, and reset token | `GET /api/users/<id>` | High |
| A01-2 | A01 | 862 | Account deletion has no authentication or authorization | `DELETE /api/users/<id>` | High |
| A01-3 | A01 | 807 | Admin access is granted by a client-controlled `X-Admin` header | `GET /admin/users` | Critical |
| A01-4 | A01 | 306 | Admin export and audit endpoints require no authentication | `GET /admin/export`, `GET /admin/audit` | Critical |
| A01-5 | A01 | 915 | Mass assignment plus missing auth on profile update | `PUT /api/users/<id>` | Critical |
| A01-6 | A01 | 352 | No CSRF protection on cookie-authenticated state changes | `POST /account/password`, `GET /logout` | High |
| A01-7 | A01 | 601 | Open redirect via the login `next` parameter | `POST /login` | Medium |
| A01-8 | A01 | 22 | Path traversal reads arbitrary files | `GET /files?name=` | High |
| A02-1 | A02 | 916 | Unsalted MD5 password storage | `users.password_md5` | High |
| A02-2 | A02 | 798 | Hardcoded session/JWT secrets and default admin password | `auth_server.py` | Critical |
| A02-3 | A02 | 330 | Six-digit session IDs from Python's `random` module | `start_session()` | High |
| A02-4 | A02 | 640 | Password reset token is `MD5(username)` and never expires | `reset_request()` | High |
| A02-5 | A02 | 598 | Secrets returned in API responses and URL query strings | login, reset, `/api/me` | High |
| A02-6 | A02 | 330 | API keys are derived predictably from the username | `register()` | Medium |
| A02-7 | A02 | 319 | Service is HTTP-only; credentials and cookies are cleartext | `app.run()` / deployment | High |
| A03-1 | A03 | 89 | SQL injection in login bypasses authentication | `authenticate()` | Critical |
| A03-2 | A03 | 89 | SQL injection in search and other string-built queries | search, register, reset, update | Critical |
| A03-3 | A03 | 78 | OS command injection in the ping utility | `GET /ping?host=` | Critical |
| A03-4 | A03 | 1336 | Server-side template injection in the greeting page | `GET /greet?name=` | Critical |
| A03-5 | A03 | 95 | `eval()` executes arbitrary Python | `POST /api/calc` | Critical |
| A03-6 | A03 | 79 | Reflected XSS in the landing page and login error | `GET /?msg=`, `POST /login` | Medium |
| A04-1 | A04 | 307 | No rate limiting, lockout, or backoff on authentication | login, register, reset | High |
| A04-2 | A04 | 521 | No password policy; `1` is accepted | `register()`, reset | Medium |
| A04-3 | A04 | 204 | Username enumeration via distinct responses | login, register, reset | Medium |
| A04-4 | A04 | 640 | Reset flow returns the token, has no expiry, and is reusable | `reset_*()` | High |
| A04-5 | A04 | 308 | No MFA and no email verification | account lifecycle | Medium |
| A04-6 | A04 | 620 | Password change does not require the current password | `POST /account/password` | Medium |
| A05-1 | A05 | 489 | Flask debug mode and interactive debugger are enabled | `app.run(debug=True)` | High |
| A05-2 | A05 | 200 | Unauthenticated `/debug` dumps secrets, users, and live sessions | `GET /debug` | Critical |
| A05-3 | A05 | 942 | CORS reflects any origin with credentials allowed | `add_cors_headers()` | High |
| A05-4 | A05 | 693 | Security headers and cache controls are absent | all responses | Medium |
| A05-5 | A05 | 1004 | Cookies lack `HttpOnly`, `Secure`, and `SameSite` | `attach_session()` | High |
| A05-6 | A05 | 209 | Verbose SQL, filesystem, and network errors reach clients | several handlers | Medium |
| A06-1 | A06 | 1395 | Intentionally outdated dependencies and EOL runtime | `requirements.txt` | High |
| A06-2 | A06 | 497 | `Server` header discloses framework and Python versions | dev server | Low |
| A07-1 | A07 | 1392 | Default `root:password` account and weak seeded passwords | `SEED_USERS` | Critical |
| A07-2 | A07 | 384 | Session fixation: login accepts a client-supplied session ID | `start_session()` | High |
| A07-3 | A07 | 613 | Logout does not invalidate the server-side session | `logout()` | Medium |
| A07-4 | A07 | 613 | Sessions never expire and are never rotated | `SESSIONS` | Medium |
| A07-5 | A07 | 347 | JWT verification accepts `alg: none` | `decode_token()` | Critical |
| A07-6 | A07 | 613 | JWT `exp` is ignored; role comes from the token; no revocation | `decode_token()`, `/api/me` | High |
| A08-1 | A08 | 502 | Unsafe pickle deserialization of the `remember` cookie | `load_remember_cookie()` | Critical |
| A09-1 | A09 | 532 | Passwords, reset tokens, and new passwords are logged in plaintext | `logger.info()` calls | High |
| A09-2 | A09 | 117 | Newlines in usernames forge audit log entries | login handlers | Medium |
| A09-3 | A09 | 778 | No monitoring, alerting, retention, or protected audit trail | logging setup | Medium |
| A10-1 | A10 | 918 | Unrestricted SSRF with `file://`, internal URLs, and redirects | `GET /fetch?url=` | High |

---

## A01 — Broken Access Control

### A01-1 — IDOR on user profiles

**Location:** `api_user_detail()` / `GET /api/users/<id>`

**What is wrong:** The endpoint looks up any numeric ID and returns the entire
row without checking who is asking. There is no session check, no ownership
check, and no response filtering. The row contains `password_md5`,
`reset_token`, and `api_key`.

```bash
curl http://127.0.0.1:5001/api/users/1
```

**Impact:** Unauthenticated disclosure of every user's password hash, email,
role, API key, and password-reset token. The hash and token feed the offline
cracking and account-takeover findings. The unauthenticated search endpoint
(`/api/users/search`) exposes the same username, email, and role fields for
every matching account.

**Mitigation:** Enforce object-level authorization on every read. Derive the
caller from the authenticated session, allow access to another user's record
only through an explicit admin capability, and return a response DTO that
contains only fields the caller is allowed to see.

```python
row = query_one("SELECT * FROM users WHERE id = ?", (user_id,))
if row is None:
    abort(404)
if not can_view(current_user(), row):
    abort(403)
return jsonify(public_profile(row))  # no hash, token, or API key
```

### A01-2 — Unauthenticated account deletion

**Location:** `api_user_delete()` / `DELETE /api/users/<id>`

**What is wrong:** The handler deletes the row immediately. It does not check
for a session, a role, ownership, or a CSRF token.

```bash
curl -X DELETE http://127.0.0.1:5001/api/users/5
```

**Impact:** Any client that can reach the service can destroy accounts. If
deletion is used by an upstream system, it can also break audit trails or
orphan data.

**Mitigation:** Require authentication, authorize the action against the target
object, require re-authentication for destructive operations, and record an
audit event. Prefer soft deletion with a recoverable retention window.

### A01-3 — Admin authorization trusts the `X-Admin` header

**Location:** `admin_users()` / `GET /admin/users`

**What is wrong:** The only authorization decision is
`request.headers.get("X-Admin") != "true"`. Any client can add that header.

```bash
curl -H 'X-Admin: true' http://127.0.0.1:5001/admin/users
```

**Impact:** Full user dump, including hashes, reset tokens, and API keys.
Combined with the default admin password, this is a direct path to total
compromise.

**Mitigation:** Never make authorization decisions from client-controlled
headers. Resolve the principal from a validated session or token, then check a
server-side role or permission. Centralize the check in a decorator or
middleware so individual routes cannot forget it.

```python
def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user() or current_user().role != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped
```

### A01-4 — Unauthenticated admin export and audit endpoints

**Location:** `admin_export()` / `GET /admin/export`; `admin_audit()` /
`GET /admin/audit`

**What is wrong:** Both endpoints skip authentication entirely. The export
returns a CSV of every column, including `password_md5`, `api_key`, and
`reset_token`. The audit endpoint returns the raw application log.

```bash
curl http://127.0.0.1:5001/admin/export
curl http://127.0.0.1:5001/admin/audit
```

**Impact:** One request dumps the entire credential store. The audit log
contains plaintext passwords from the logging flaw, so it is a second
credential dump. The export also writes user-controlled cells verbatim:
because registration accepts arbitrary usernames and email addresses, a value
beginning with `=`, `+`, `-`, or `@` can become a spreadsheet formula when the
CSV is opened (CSV/formula injection).

**Mitigation:** Apply the admin authorization check to the entire `/admin`
prefix, not per endpoint. Redact secrets from exports, rate-limit bulk reads,
and keep audit data in a separate access-controlled system. Log access to the
export itself. For CSV output, use a CSV library with correct quoting and
prefix formula-leading cells with a single quote (or reject them on input).

### A01-5 — Mass assignment and missing authorization on profile update

**Location:** `api_user_update()` / `PUT /api/users/<id>`

**What is wrong:** The handler iterates over every JSON key and interpolates
both the column name and the value into SQL. There is no authentication, no
ownership check, and no allowlist of updatable fields.

```bash
curl -X PUT http://127.0.0.1:5001/api/users/3 \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

A caller can also overwrite `password_md5` or `reset_token`.

**Impact:** Privilege escalation without authentication, plus account takeover
by replacing the stored hash. The dynamic column name is also a SQL injection
sink.

**Mitigation:** Authenticate and authorize first. Accept only an explicit
schema of safe fields (`email`, `display_name`), ignore or reject `role`,
`password_md5`, `api_key`, and other server-managed columns, and bind values
with placeholders. Column names must come from an allowlist, never from the
request body.

```python
ALLOWED_FIELDS = {"email", "display_name"}
for field in data:
    if field not in ALLOWED_FIELDS:
        abort(400)
```

### A01-6 — CSRF on password change and logout

**Location:** `account_password()` / `POST /account/password`;
`logout()` / `GET /logout`; `login()` / `POST /login`

**What is wrong:** The password-change endpoint authenticates with the session
cookie but does not require a CSRF token, does not check `Origin` or
`Referer`, and accepts `application/x-www-form-urlencoded` posts. The session
cookie has no `SameSite` attribute. Logout is a GET request, and login has no
login-CSRF protection.

```html
<form action="http://127.0.0.1:5001/account/password" method="POST">
  <input name="password" value="attacker-chosen">
</form>
<script>document.forms[0].submit()</script>
```

**Impact:** A malicious page can change a logged-in victim's password and take
over the account. Login CSRF can also force a victim into an attacker's
account, polluting later activity. Registration and reset endpoints also lack
CSRF tokens, although they are lower impact without a victim session.

**Mitigation:** Use a per-session CSRF token in a custom header or a
double-submit cookie; reject form posts without it. Set `SameSite=Lax` or
`Strict` on session cookies. Check `Origin`/`Referer` as defense in depth.
Require the current password or a fresh MFA challenge for password changes,
and make logout a POST with CSRF protection.

### A01-7 — Open redirect after login

**Location:** `login()` / `POST /login?next=...`

**What is wrong:** The handler passes `request.args.get("next", "/")` directly
to `redirect()`.

```bash
curl -i -X POST 'http://127.0.0.1:5001/login?next=https://evil.example/' \
  -d 'username=root&password=password'
```

The response is `302 Location: https://evil.example/`.

**Impact:** Phishing and trust abuse: a link on the real domain sends users to
an attacker site after authentication. In flows that carry tokens or codes in
URLs, it can assist token theft.

**Mitigation:** Only allow same-origin relative paths. Parse the target, reject
absolute URLs and protocol-relative (`//host`) values, and prefer generating
the destination with `url_for()` rather than accepting a URL.

```python
target = request.args.get("next", "/")
if not target.startswith("/") or target.startswith("//") or "\\" in target:
    target = "/"
```

### A01-8 — Path traversal in file delivery

**Location:** `files()` / `GET /files?name=...`

**What is wrong:** `os.path.join(UPLOAD_DIR, name)` is used without normalizing
or containing the resulting path. `..` escapes the upload directory, and an
absolute path discards `UPLOAD_DIR` entirely.

```bash
curl 'http://127.0.0.1:5001/files?name=../auth_server.py'
curl 'http://127.0.0.1:5001/files?name=../badas.db'
curl 'http://127.0.0.1:5001/files?name=/etc/passwd'
```

**Impact:** Arbitrary file read as the server user: source code, the SQLite
database, the log with plaintext passwords, configuration, and any
world-readable system file.

**Mitigation:** Do not accept raw filenames. Use an opaque identifier mapped to
a stored record, or `werkzeug.utils.safe_join`/`send_from_directory` with a
resolved-path containment check. Reject absolute paths, `..`, null bytes, and
symlinks. Run with least privilege so a traversal is not a full-host read.

```python
from flask import send_from_directory
return send_from_directory(UPLOAD_DIR, name, as_attachment=True)
```

---

## A02 — Cryptographic Failures

### A02-1 — Unsalted MD5 password storage

**Location:** `md5()` and `users.password_md5`

**What is wrong:** Passwords are stored as bare `MD5(password)`. There is no
salt, no pepper, and no work factor. MD5 is fast and GPU-friendly.

```bash
curl http://127.0.0.1:5001/api/users/1
# password_md5 = 5f4dcc3b5aa765d61d8327deb882cf99 = md5("password")
```

**Impact:** A database leak leads to near-instant offline cracking and
rainbow-table lookups. Identical passwords produce identical hashes, so
cracking one account compromises every account that reused the password.

**Mitigation:** Use Argon2id (preferred), bcrypt, or scrypt with a unique salt
per password and a tuned cost factor. Store the algorithm and parameters with
the hash, and rehash on successful login when parameters change. A pepper kept
in a KMS adds defense if the database alone leaks.

```python
from argon2 import PasswordHasher
ph = PasswordHasher()
stored = ph.hash(password)
ph.verify(stored, password)
```

### A02-2 — Hardcoded secrets and default admin password

**Location:** top of `auth_server.py`: `SECRET_KEY`, `JWT_SECRET`,
`DEFAULT_ADMIN_PASSWORD`, `SEED_USERS`

**What is wrong:** The JWT signing key (`badas-jwt-secret`) and Flask secret
are constants in source. The root account's password is literally `password`.
The same secret is used in every environment that runs this code.

**Impact:** Anyone with the source can forge JWTs, sign session data, and log
in as root. Secrets in source are also copied into forks, screenshots, and
build artifacts.

**Mitigation:** Load secrets from a secret manager or environment at runtime,
use a different value per environment, rotate on exposure, and never ship a
default account. Add secret scanning to CI. For this lab the values are fake
and intentionally committed; the fix is to remove the pattern, not just change
the string.

### A02-3 — Weak session identifiers

**Location:** `start_session()`

**What is wrong:** Session IDs are `str(random.randint(100000, 999999))`:
six digits, about 900,000 possibilities, generated by the Mersenne Twister
`random` module rather than a CSPRNG. They are also never expired.

```bash
# Any successful login shows a six-digit session_id.
curl -i -X POST http://127.0.0.1:5001/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"root","password":"password"}'
```

**Impact:** Session IDs are guessable and brute-forceable, especially with no
rate limit and no expiry. Predictable IDs also make fixation and hijacking
easier.

**Mitigation:** Generate at least 128 bits of entropy with `secrets`, e.g.
`secrets.token_urlsafe(32)`. Store sessions server-side with an absolute and
idle timeout, rotate the ID on login and privilege change, and revoke on
logout.

### A02-4 — Predictable password-reset token

**Location:** `reset_request()` and `reset_confirm()`

**What is wrong:** The reset token is `md5(username)`. It contains no random
value, is deterministic, and is stored in plaintext in the database and log.
It is also prefilled at seed time for every account.

```bash
curl -X POST http://127.0.0.1:5001/reset/request \
  -H 'Content-Type: application/json' -d '{"username":"alice"}'
# token = 6384e2b2184bcbf58eccf10ca7a6563c = md5("alice")
```

**Impact:** Anyone who knows a username can compute the reset token and take
over the account without receiving email.

**Mitigation:** Generate at least 32 random bytes with `secrets.token_urlsafe`.
Store only a hash of the token, bind it to the user and a single purpose,
expire it after 15–60 minutes, mark it used on first success, and invalidate
it when the password changes. Send it only to a verified address.

### A02-5 — Secrets in API responses and URLs

**Location:** `api_login()` and `register()` return `dict(user)`;
`reset_request()` returns `token`; `api_session()` echoes the session ID;
`api_me()` accepts `?token=`

**What is wrong:** The login response includes the user's `password_md5`,
`api_key`, and `reset_token` because the whole row is serialized. The reset
endpoint returns the token in the response body. `/api/me` accepts a JWT in
the query string, which puts it in browser history, proxy logs, and
`Referer` headers.

**Impact:** Secrets leak to any client-side logging, analytics, browser cache,
or intermediary. The reset token in the response defeats the email channel.

**Mitigation:** Return explicit response DTOs, never database rows. Never
return password hashes, reset tokens, or API keys from authentication
endpoints. Keep tokens in headers or secure cookies, not URLs. Mark
authentication responses `Cache-Control: no-store`.

### A02-6 — Predictable API keys

**Location:** `register()`

**What is wrong:** New API keys are `"APIKEY-" + md5(username)[:16]`. They are
deterministic from public information and stored in plaintext. Seeded keys use
the same guessable `APIKEY-<name>-000N` shape.

**Impact:** An attacker who knows a username can predict the API key, and any
database or export leak exposes valid keys directly.

**Mitigation:** Generate keys with a CSPRNG (`secrets.token_urlsafe(32)`),
prefix them for identification only, store a hash or an encrypted value, scope
them to least privilege, and support rotation and revocation. Never derive a
credential from a username.

### A02-7 — No TLS

**Location:** `app.run()` and the deployment guidance

**What is wrong:** The service is HTTP-only. Passwords, session cookies, JWTs,
and reset tokens cross the network in cleartext. Cookies also lack the
`Secure` attribute, so a browser would send them over HTTP.

**Impact:** Anyone on the network path can read credentials and hijack
sessions.

**Mitigation:** Terminate TLS 1.2+ at a reverse proxy or serve HTTPS directly,
redirect HTTP to HTTPS, set `Strict-Transport-Security`, and mark cookies
`Secure`. Treat plaintext HTTP as a development-only transport and never bind
the lab to a non-loopback interface.

---

## A03 — Injection

### A03-1 — SQL injection authentication bypass

**Location:** `authenticate()`, called by both login handlers

**What is wrong:** The query is built with an f-string:

```python
sql = f"SELECT * FROM users WHERE username = '{username}' AND password_md5 = '{md5(password)}'"
```

The username `root' --` comments out the password check.

```bash
curl -X POST http://127.0.0.1:5001/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"root'"'"' --","password":"anything"}'
```

**Impact:** Complete authentication bypass, including admin accounts. No
password is required.

**Mitigation:** Use parameterized queries for every value. Never concatenate
request data into SQL. Validate input shape only as a secondary control.

```python
row = query_one(
    "SELECT * FROM users WHERE username = ? AND password_md5 = ?",
    (username, md5(password)),
)
```

The real fix also replaces MD5 with a slow password hash, so the stored value
and comparison change accordingly.

### A03-2 — SQL injection in search and other query sinks

**Location:** `api_user_search()`, `username_exists()`, `register()`,
`reset_request()`, `reset_confirm()`, `api_user_update()`

**What is wrong:** Every one of these handlers builds SQL with f-strings.
Search interpolates the `q` parameter directly; registration interpolates
username, email, and timestamp; the reset handlers interpolate usernames and
tokens; profile update interpolates both column names and values.

```bash
curl 'http://127.0.0.1:5001/api/users/search?q=%27%20OR%201%3D1%20--'
```

This returns every row. A `UNION SELECT` can pull data from other tables.

**Impact:** Data exfiltration, authentication bypass, data modification, and
possibly file access depending on the database engine and permissions.

**Mitigation:** Parameterize all values. Use an allowlist for column names and
sort directions, because identifiers cannot be bound as parameters. Prefer an
ORM or query builder for dynamic updates. Add least-privilege database users
and disable dangerous features.

```python
rows = query_all(
    "SELECT id, username, email, role FROM users WHERE username LIKE ?",
    (f"%{term}%",),
)
```

### A03-3 — OS command injection in ping

**Location:** `ping()` / `GET /ping?host=...`

**What is wrong:** The handler concatenates `host` into a shell command and
runs it with `shell=True`.

```bash
curl 'http://127.0.0.1:5001/ping?host=127.0.0.1;id'
curl 'http://127.0.0.1:5001/ping?host=127.0.0.1;cat%20/etc/passwd'
```

**Impact:** Remote code execution as the service user. The response includes
the command output, so exfiltration is trivial.

**Mitigation:** Avoid the shell entirely. Pass an argument vector, validate the
host as an IP address or an allowlisted DNS name, and set a short timeout and
output limit.

```python
subprocess.run(["ping", "-c", "1", host], shell=False, timeout=2, check=True)
```

Even with `shell=False`, validate the host so the utility cannot be pointed at
unexpected targets.

### A03-4 — Server-side template injection

**Location:** `greet()` / `GET /greet?name=...`

**What is wrong:** User input is concatenated into the template source:

```python
return render_template_string("Hello, " + name)
```

```bash
curl 'http://127.0.0.1:5001/greet?name={{7*7}}'      # Hello, 49
curl 'http://127.0.0.1:5001/greet?name={{config}}'   # dumps Flask config
```

**Impact:** Template expressions execute on the server. Configuration and
secrets are exposed immediately; Jinja object traversal can lead to code
execution depending on available globals.

**Mitigation:** Treat input as data, never as template source. Use a fixed
template and pass the value as a context variable, which Jinja escapes.

```python
return render_template_string("Hello, {{ name }}", name=name)
```

Do not rely on a sandbox as the primary defense; avoid evaluating user input
as a template at all.

### A03-5 — `eval()` in the calculator

**Location:** `calc()` / `POST /api/calc`

**What is wrong:** The `expr` field is passed directly to Python's `eval()`.

```bash
curl -X POST http://127.0.0.1:5001/api/calc \
  -H 'Content-Type: application/json' \
  -d '{"expr":"__import__(\"os\").getcwd()"}'
```

**Impact:** Arbitrary Python execution: file access, network access, command
execution, and full host compromise.

**Mitigation:** Do not use `eval`. For literal data use `ast.literal_eval`; for
arithmetic use a small parser or a library such as `asteval` with a restricted
namespace and explicit limits. If the feature is not essential, remove it.

### A03-6 — Reflected XSS

**Location:** `index()` / `GET /?msg=...`; `login()` error path

**What is wrong:** The landing page interpolates `msg` into an f-string HTML
response without escaping. The login failure path interpolates the username
into HTML the same way, the remember-me greeting renders a cookie-supplied
username into the same page without escaping, and the file-not-found page
embeds the resolved path (including the requested name) inside raw HTML.

```bash
curl 'http://127.0.0.1:5001/?msg=%3Cscript%3Ealert(1)%3C/script%3E'
```

**Impact:** Script execution in the origin, which can read the session cookie
because it lacks `HttpOnly`, change the password through `POST
/account/password`, and exfiltrate data. The missing CSP removes a second
layer of defense.

**Mitigation:** Use Jinja autoescaping for all HTML, or `markupsafe.escape` for
hand-built markup. Apply contextual encoding, set a restrictive CSP, and mark
cookies `HttpOnly`. Prefer returning data as JSON and rendering it client-side
with safe DOM APIs.

---

## A04 — Insecure Design

### A04-1 — No rate limiting or account lockout

**Location:** login, registration, and reset handlers

**What is wrong:** Failed logins are counted nowhere. A client can try
unlimited passwords for the same account, and there is no IP-based throttle.

```bash
for i in $(seq 1 100); do
  curl -s -o /dev/null -X POST http://127.0.0.1:5001/api/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"root","password":"guess"}'
done
```

**Impact:** Online brute force, credential stuffing, and password spraying.
With the weak seeded passwords, the search space is tiny.

**Mitigation:** Apply per-account and per-IP rate limits with exponential
backoff and jitter. Lock or slow the account after repeated failures without
creating a trivial denial-of-service, alert on spikes, check passwords against
breach corpora, and require MFA for high-value accounts.

### A04-2 — No password policy

**Location:** `register()` and `reset_confirm()`

**What is wrong:** The only validation is that the password is non-empty.
`1`, `password`, and the username itself are accepted.

```bash
curl -X POST http://127.0.0.1:5001/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"weakuser","password":"1","email":"weak@example.com"}'
```

**Impact:** Users can select trivially guessable passwords, undermining every
other authentication control.

**Mitigation:** Follow NIST SP 800-63B: require a minimum length (8, preferably
12+), block common and breached passwords, allow long passphrases, avoid
composition rules that push predictable substitutions, and rate-limit
guessing. Do not impose arbitrary maximum lengths below 64 characters.

### A04-3 — Username enumeration

**Location:** `api_login()`, `register()`, `reset_request()`

**What is wrong:** The login API returns `Unknown user X` for a missing account
and `Wrong password for X` for an existing one. Registration returns a distinct
`409` for a taken username. Reset returns `404 no such user`. The HTML login
also reflects the attempted username.

**Impact:** An attacker can build a list of valid accounts, then focus
credential stuffing and phishing.

**Mitigation:** Return one generic failure message and status for login and
reset. Perform a dummy password-hash verification for unknown users to reduce
timing differences. For registration, use an email-verification flow that does
not reveal whether the address exists. Rate-limit enumeration attempts.

### A04-4 — Password-reset flow design

**Location:** `reset_request()`, `reset_confirm()`

**What is wrong:** The token is deterministic, returned in the HTTP response,
written to the log, never expires, and remains valid after a successful reset.
There is no email verification, no identity challenge, and no rate limit.

**Impact:** Account takeover by anyone who can request a reset for a known
username, compute the token, or read the response/log.

**Mitigation:** Treat reset as a state machine: verify the identifier, issue a
high-entropy single-use token to a verified channel, store only its hash,
expire it quickly, invalidate it on use or password change, rate-limit
requests, and notify the account owner. Invalidate all existing sessions after
a reset. Do not disclose whether an address is registered.

### A04-5 — No MFA and no email verification

**Location:** account lifecycle

**What is wrong:** A new account is usable immediately with a username and
password. There is no email ownership check, no second factor, and no step-up
authentication for sensitive actions.

**Impact:** Stolen or guessed passwords are sufficient for full account
takeover. Unverified addresses also enable impersonation and broken recovery.

**Mitigation:** Verify email ownership before enabling sensitive features.
Offer TOTP or WebAuthn MFA, require it for admins, and use step-up
authentication for password changes, exports, and other high-impact actions.

### A04-6 — Password change without re-authentication

**Location:** `account_password()` / `POST /account/password`

**What is wrong:** A valid session can change the password by submitting only
the new value. The current password is not required, and other sessions are
not invalidated.

**Impact:** Session hijacking or CSRF becomes permanent account takeover: the
attacker sets a new password and locks the owner out.

**Mitigation:** Require the current password or a fresh MFA challenge, enforce
CSRF protection, invalidate all other sessions and refresh tokens, notify the
user, and rate-limit the operation.

---

## A05 — Security Misconfiguration

### A05-1 — Debug mode and interactive debugger

**Location:** `main()` / `app.run(debug=not args.no_debug)`

**What is wrong:** Debug mode is on by default. Exceptions return full
tracebacks, and Werkzeug's interactive debugger is enabled. The verifier gets a
`ZeroDivisionError` traceback from `/api/calc`.

**Impact:** Source paths, code snippets, configuration, and stack details leak.
If the debugger console is reachable and the PIN is obtained, it provides
remote code execution. The pinned Werkzeug version also has debugger-related
CVEs. Even with `--no-debug`, `app.run()` is Werkzeug's development server, not
a hardened production server.

**Mitigation:** Disable debug mode in every non-development environment, run
with a production WSGI server, return generic error pages with a correlation
ID, and keep detailed errors in server-side logs. Never expose the debugger to
an untrusted network.

### A05-2 — Unauthenticated `/debug` information dump

**Location:** `debug_info()` / `GET /debug`

**What is wrong:** The endpoint returns Flask configuration, `SECRET_KEY`,
`JWT_SECRET`, database and log paths, every user row, and the live `SESSIONS`
dictionary with active session IDs.

```bash
curl http://127.0.0.1:5001/debug
```

**Impact:** Complete compromise: forge JWTs, hijack live sessions, read hashes
and reset tokens, and locate the database and log for follow-up access.

**Mitigation:** Remove the endpoint from production builds, or protect it with
admin authentication and network restrictions. Never serialize secrets or
session stores. If diagnostics are required, expose only health status and
aggregate metrics.

### A05-3 — Permissive CORS with credentials

**Location:** `add_cors_headers()`

**What is wrong:** The `Origin` header is reflected into
`Access-Control-Allow-Origin`, and
`Access-Control-Allow-Credentials: true` is always set. `Allow-Headers` and
`Allow-Methods` are wildcards. There is no `Vary: Origin`.

```bash
curl -i -H 'Origin: https://evil.example' http://127.0.0.1:5001/
```

**Impact:** Any website can make credentialed requests and read authenticated
responses in a victim's browser, enabling data theft and chained CSRF. Missing
`Vary: Origin` also creates cache-poisoning risk.

**Mitigation:** Use an explicit allowlist of trusted origins, echo only exact
matches, allow credentials only when necessary, restrict methods and headers,
and send `Vary: Origin`. Do not combine wildcard origins with credentials.

### A05-4 — Missing security headers and cache controls

**Location:** all responses (`after_request` only adds CORS headers)

**What is wrong:** There is no `Content-Security-Policy`,
`X-Frame-Options`/`frame-ancestors`, `Strict-Transport-Security`,
`X-Content-Type-Options`, `Referrer-Policy`, or `Permissions-Policy`.
Authentication and user responses also lack `Cache-Control: no-store`.

**Impact:** XSS has no CSP mitigation, the site can be framed for clickjacking,
MIME sniffing can turn uploads into active content, and sensitive responses can
be cached by browsers or proxies.

**Mitigation:** Add a strict CSP, `X-Frame-Options: DENY` (or
`frame-ancestors 'none'`), HSTS on HTTPS, `nosniff`, a referrer policy, and
`Cache-Control: no-store` on authenticated responses. Use a maintained
extension such as Flask-Talisman or a reverse-proxy configuration.

### A05-5 — Insecure cookie attributes

**Location:** `attach_session()` / `set_cookie()`

**What is wrong:** Both `session_id` and `remember` are set without
`HttpOnly`, `Secure`, or `SameSite`. The `Path` is `/`.

**Impact:** JavaScript can read the session cookie (amplifying XSS), the cookie
is sent over HTTP, and cross-site requests carry it by default, enabling CSRF.

**Mitigation:** Set `HttpOnly=True`, `Secure=True`, and `SameSite="Lax"` or
`"Strict"`; use the `__Host-` prefix where possible; scope the path narrowly;
and avoid long-lived cookies for authentication. Rotate the session ID on
login.

### A05-6 — Verbose SQL, filesystem, and network errors

**Location:** `api_user_search()`, `files()`, `fetch()`, `api_me()`

**What is wrong:** Error handlers return raw exception text and even the
failing SQL query. File errors disclose the resolved path. Fetch errors
disclose the target and network failure details.

**Impact:** Attackers learn schema, query structure, filesystem layout, and
internal network behavior, which accelerates SQLi, traversal, and SSRF
exploitation.

**Mitigation:** Return a generic message and a correlation ID. Log the full
exception server-side with access controls. Never echo queries, paths,
internal hostnames, or stack traces to clients.

---

## A06 — Vulnerable and Outdated Components

### A06-1 — Outdated dependencies and EOL runtime

**Location:** `requirements.txt`, Python 3.9 runtime

**What is wrong:** The pins are intentionally old. At the time of writing,
OSV reports multiple advisories for each:

| Package | Pinned | Selected known issues |
|---|---|---|
| Flask | 2.0.1 | [CVE-2023-30861](https://nvd.nist.gov/vuln/detail/CVE-2023-30861) (fixed 2.2.5), [CVE-2026-27205](https://nvd.nist.gov/vuln/detail/CVE-2026-27205) (fixed 3.1.3) |
| Werkzeug | 2.0.3 | [CVE-2023-23934](https://nvd.nist.gov/vuln/detail/CVE-2023-23934) and [CVE-2023-25577](https://nvd.nist.gov/vuln/detail/CVE-2023-25577) (fixed 2.2.3), [CVE-2023-46136](https://nvd.nist.gov/vuln/detail/CVE-2023-46136) (fixed 2.3.8), [CVE-2024-34069](https://nvd.nist.gov/vuln/detail/CVE-2024-34069) (debugger RCE, fixed 3.0.3) |
| requests | 2.19.1 | [CVE-2018-18074](https://nvd.nist.gov/vuln/detail/CVE-2018-18074) (fixed 2.20.0), [CVE-2023-32681](https://nvd.nist.gov/vuln/detail/CVE-2023-32681) (fixed 2.31.0), [CVE-2024-35195](https://nvd.nist.gov/vuln/detail/CVE-2024-35195) (fixed 2.32.0), [CVE-2024-47081](https://nvd.nist.gov/vuln/detail/CVE-2024-47081) (fixed 2.32.4) |
| Jinja2 | 3.0.3 | [CVE-2024-22195](https://nvd.nist.gov/vuln/detail/CVE-2024-22195) (fixed 3.1.3), [CVE-2024-34064](https://nvd.nist.gov/vuln/detail/CVE-2024-34064) (fixed 3.1.4), [CVE-2024-56201](https://nvd.nist.gov/vuln/detail/CVE-2024-56201) and [CVE-2024-56326](https://nvd.nist.gov/vuln/detail/CVE-2024-56326) (fixed 3.1.5), [CVE-2025-27516](https://nvd.nist.gov/vuln/detail/CVE-2025-27516) (fixed 3.1.6) |

Python 3.9 reached end of security support in October 2025. The pinned stack
also makes the lab hard to run on current Python releases.

**Impact:** Known vulnerabilities in the framework and HTTP client, no
security patches, and an unsupported runtime. The debugger RCE is directly
relevant because debug mode is enabled.

**Mitigation:** Upgrade to supported releases, remove unused dependencies,
regenerate the lockfile, and run `pip-audit` (or Dependabot/Renovate) in CI.
Pin exact versions plus hashes, and patch on a defined cadence.

```bash
python -m pip install pip-audit
pip-audit -r requirements.txt
```

### A06-2 — Version disclosure in the `Server` header

**Location:** Werkzeug development server

**What is wrong:** Responses advertise the framework and Python versions, for
example `Server: Werkzeug/2.0.3 Python/3.9.6`.

**Impact:** Low on its own; it lets an attacker match the deployment to known
CVEs and prioritize exploits.

**Mitigation:** Put a reverse proxy in front of the app, normalize or remove
the `Server` header, and avoid revealing patch levels. Patching is the real
fix; header suppression only reduces reconnaissance.

---

## A07 — Identification and Authentication Failures

### A07-1 — Default and weak credentials

**Location:** `SEED_USERS`

**What is wrong:** The admin account is `root:password`. Other seeded accounts
use `alice123`, `hunter2`, and `dave`. These are created automatically on first
start.

**Impact:** Immediate admin compromise with a well-known credential pair.

**Mitigation:** Never create default accounts. Require an explicit bootstrap
step with a unique, strong credential delivered out of band, or disable the
account until setup is complete. Force a password change on first use and
remove demo accounts from non-demo deployments.

### A07-2 — Session fixation

**Location:** `start_session()`

**What is wrong:** If the request already has a `session_id` cookie, login
reuses it instead of issuing a new one. The server then associates the
authenticated user with the attacker-chosen ID.

```bash
curl -i -X POST http://127.0.0.1:5001/login \
  -H 'Cookie: session_id=fixated-by-attacker' \
  -d 'username=root&password=password'
# The same cookie now maps to root in /api/session.
```

**Impact:** An attacker who can set a cookie on the victim's browser (via XSS,
a sibling subdomain, or a crafted link) can pre-bind a session and then use it
after the victim logs in.

**Mitigation:** Always generate a fresh session ID after successful
authentication, discard any client-supplied ID, rotate again on privilege
changes, and bind the session to a server-side record with an expiry. Set
cookies with `Secure`, `HttpOnly`, and `SameSite`.

### A07-3 — Logout does not invalidate the session

**Location:** `logout()`

**What is wrong:** Logout only sends a `Set-Cookie` that deletes the browser
copy. `SESSIONS[session_id]` remains valid forever, so replaying the old cookie
still authenticates.

**Impact:** A stolen cookie remains usable after the victim logs out. Shared
or compromised devices cannot be effectively logged out. The `remember`
cookie is not cleared either, so the deserialization path remains reachable
after logout.

**Mitigation:** Delete the server-side session record on logout, invalidate all
sessions on password change, clear the remember cookie, and maintain a
revocation list for tokens. Use a POST with CSRF protection for logout.

### A07-4 — Sessions never expire or rotate

**Location:** `SESSIONS`, `current_session()`

**What is wrong:** Each session stores a `created` timestamp that is never
checked. There is no idle timeout, absolute timeout, or periodic rotation, and
sessions survive until the process restarts.

**Impact:** A stolen session is valid indefinitely, and long-lived sessions
increase the exposure window for XSS and cookie theft.

**Mitigation:** Enforce both idle and absolute timeouts, rotate IDs
periodically and on privilege changes, store sessions in a shared store with
TTL, and revoke on logout, password reset, and suspicious activity.

### A07-5 — JWT `alg: none` is accepted

**Location:** `decode_token()`

**What is wrong:** If the header says `alg: none`, the signature check is
skipped entirely and the payload is trusted.

```python
header = b64({"alg": "none"})
payload = b64({"sub": "root", "role": "admin", "exp": 1})
token = f"{header}.{payload}."
# GET /api/me with "Authorization: Bearer <token>" returns root/admin.
```

**Impact:** Anyone can mint an admin token. Complete authentication and
authorization bypass.

**Mitigation:** Use a vetted JWT library with an explicit algorithm allowlist
(`HS256` or `RS256`, never `none`), verify the signature before reading claims,
reject unknown `alg`/`typ` values, and use asymmetric keys where multiple
services verify tokens.

### A07-6 — JWT `exp` ignored, role trusted, no revocation

**Location:** `decode_token()`, `api_me()`

**What is wrong:** The payload includes `exp`, but verification never reads it.
The handler returns the `role` from the token instead of loading the current
role from the database. There is no issuer, audience, token type, or
revocation check, and tokens are accepted from the query string.

**Impact:** Expired tokens remain valid forever. A user whose role is revoked
in the database keeps the old role until the token is replaced. A token leaked
through a URL or log is usable by anyone.

**Mitigation:** Validate `exp`, `nbf`, and `iat` with a small clock skew;
validate `iss`, `aud`, and `typ`; load authorization data from the database on
each request; use short-lived access tokens plus rotating refresh tokens; keep
a revocation mechanism; and never accept credentials in URLs.

---

## A08 — Software and Data Integrity Failures

### A08-1 — Unsafe pickle deserialization of the `remember` cookie

**Location:** `load_remember_cookie()` and `attach_session()`

**What is wrong:** On every request, the `remember` cookie is base64-decoded
and passed to `pickle.loads()` if present. The cookie is not signed or
encrypted. Pickle is not a data format; it is a program that constructs
arbitrary objects and can call functions during deserialization.

```python
class Payload:
    def __reduce__(self):
        return (os.system, ("id",))

cookie = base64.urlsafe_b64encode(pickle.dumps(Payload())).rstrip(b"=").decode()
# Send: Cookie: remember=<cookie>
```

The verifier uses a benign `touch` payload and checks that the marker file was
created.

**Impact:** Unauthenticated remote code execution. This is the most severe
finding in the lab: a single crafted cookie compromises the host.

**Mitigation:** Never unpickle untrusted data. Use a signed, opaque session
identifier (server-side store) or JSON plus an HMAC (`itsdangerous`) with
strict verification. If legacy pickle cookies exist, invalidate them and
migrate users, rather than trying to sanitize the pickle.

---

## A09 — Security Logging and Monitoring Failures

### A09-1 — Plaintext passwords and tokens in logs

**Location:** every `logger.info()` call in the login, password-change, and
reset handlers

**What is wrong:** Logs contain the submitted username and password, the new
password, and reset tokens. The log is a plaintext file in the project
directory and is exposed by `/admin/audit` and `/files?name=../badas.log`.

**Impact:** Anyone who reads the log obtains credentials and reset tokens,
including for the admin account. Logs are often shipped to less-protected
systems, widening the exposure.

**Mitigation:** Never log credentials, secrets, tokens, or full request bodies.
Log structured event metadata (event type, user ID, source IP, outcome,
correlation ID) and redact sensitive fields centrally. Restrict log access,
encrypt at rest, and set retention.

### A09-2 — Log injection

**Location:** login handlers

**What is wrong:** The username is interpolated into a plaintext log line
without escaping newlines.

```bash
curl -X POST http://127.0.0.1:5001/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"evil\nFAKE-AUDIT-ENTRY","password":"x"}'
```

The log now contains an attacker-controlled line that looks like a real audit
event.

**Impact:** Forged audit entries, confusion during incident response, and
potential log-parser exploitation.

**Mitigation:** Use structured logging (JSON) with proper field encoding, and
strip or escape CR/LF and control characters. Do not build log lines by string
concatenation.

### A09-3 — No monitoring, alerting, or protected audit trail

**Location:** logging setup, `/admin/audit`

**What is wrong:** There is no alert on repeated failures, password changes, or
admin exports; no retention or rotation policy; no integrity protection; and
the audit endpoint is unauthenticated. Failed logins are logged with passwords
but not monitored.

**Impact:** Attacks proceed without detection, evidence is readable or
tamperable by the attacker, and the log can grow without bound.

**Mitigation:** Centralize logs in an append-only or WORM store with access
controls, define retention, alert on authentication anomalies and privileged
actions, and protect the audit endpoint with admin authorization. Include
correlation IDs and monitor for gaps.

---

## A10 — Server-Side Request Forgery

### A10-1 — Unrestricted SSRF in `/fetch`

**Location:** `fetch()` / `GET /fetch?url=...`

**What is wrong:** The server fetches any URL supplied by the client, follows
redirects, supports `file://`, and returns the response body or the raw
exception.

```bash
curl 'http://127.0.0.1:5001/fetch?url=http://127.0.0.1:5001/debug'
curl 'http://127.0.0.1:5001/fetch?url=file:///etc/passwd'
curl 'http://127.0.0.1:5001/fetch?url=http://169.254.169.254/latest/meta-data/'
```

**Impact:** Access to internal services, cloud metadata credentials, and local
files. The response is reflected, so the attacker sees the data. Redirects can
bypass a naive host check.

**Mitigation:** Allowlist schemes (`https` only), hosts, and ports; resolve DNS
and reject loopback, private, link-local, and multicast addresses before
connecting; disable or revalidate redirects; use a dedicated egress proxy or
network policy; require metadata-service protections; enforce timeouts and
response-size limits; never return raw network errors.

```python
if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
    abort(400)
```

---

## Remediation order

If this were a real service, fix in this order. The first group removes direct
host compromise; the second removes authentication bypass and credential
disclosure; the third closes the remaining access-control and injection paths;
the last is hardening.

1. **Remove code-execution paths:** delete pickle deserialization, `eval`,
   `shell=True`, and template-source injection. These are unconditional
   Critical findings.
2. **Replace string-built SQL:** parameterize every value and allowlist every
   identifier. This closes login bypass, data exfiltration, and several
   second-order paths at once.
3. **Add a single authorization layer:** authenticate every route, authorize
   the specific object, remove the `X-Admin` trust, protect `/admin/*`, and
   stop returning database rows.
4. **Rebuild the credential flows:** Argon2id, CSPRNG session IDs and reset
   tokens, rotation on login, server-side revocation, strict JWT validation,
   rate limits, password policy, and re-authentication for sensitive actions.
5. **Contain the remaining surfaces:** SSRF allowlist and egress controls,
   file-path containment, CSRF tokens and `SameSite`, open-redirect
   allowlist, CORS allowlist, security headers, and no-cache on authenticated
   responses.
6. **Operate it:** disable debug, patch dependencies and the runtime, redact
   logs, centralize monitoring, and add regression tests for each fix.

## Cross-cutting exploit chains

These are the combinations worth highlighting in a review, because individual
findings often look lower severity until chained:

1. **Anonymous to admin:** `X-Admin: true` → `/admin/users` → password hashes
   and reset tokens → crack or reset → admin login. Default `root:password`
   makes it a single request.
2. **Anonymous to RCE:** `remember` pickle cookie → `os.system`. Also
   `/api/calc` `eval`, `/ping` command injection, and `/greet` SSTI.
3. **Anonymous to full credential dump:** `/admin/export` or
   `/files?name=../badas.db`, plus `/admin/audit` for plaintext passwords.
4. **XSS to account takeover:** reflected XSS + no `HttpOnly` → read
   `session_id` → `POST /account/password` (no current-password check) →
   permanent takeover.
5. **Fixation to takeover:** set `session_id` → victim logs in → attacker
   reuses the cookie. Logout does not revoke it.
6. **Reset takeover:** `/reset/request` → token is `md5(username)` and is
   returned in the response → `/reset/confirm` → log in with the new password.
7. **SSRF to secrets:** `/fetch?url=http://127.0.0.1:5001/debug` → JWT secret
   and live sessions; or cloud metadata credentials.
8. **JWT forgery:** `alg: none` or the hardcoded `badas-jwt-secret` → mint
   `role: admin` → `/api/me` accepts it and no database role check occurs.

## Verification coverage

`tools/verify_flaws.py` runs 37 live checks across these findings. Some
findings are design or deployment gaps (for example A02-7 no TLS, A04-5 no
MFA, A06-1 outdated pins, A09-3 monitoring) and are documented rather than
exercised over HTTP. The verifier uses a throwaway database and log, so it
never touches your working lab data.

## References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NVD](https://nvd.nist.gov/)
- [OSV](https://osv.dev/)
