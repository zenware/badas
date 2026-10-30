# BadAS

**A deliberately vulnerable authentication service for code-review practice.**

> **WARNING**
> BadAS is insecure by design. It contains working authentication bypasses,
> SQL injection, command injection, SSRF, unsafe deserialization, and several
> paths to remote code execution. Run it on `127.0.0.1` only, with synthetic
> data, and never expose it to a network. Do not reuse any code from this
> repository in real software.

## What this is

BadAS is a small Flask + SQLite authentication service whose purpose is to be
read, poked at, and reviewed. It implements the features a real service needs —
login, sessions, registration, password reset, API tokens, profile management,
admin exports, file delivery, and diagnostics — using the kind of shortcuts
that show up in real vulnerable code.

It is intentionally *legible*. The flaws are not hidden behind clever
obfuscation; they are the obvious-but-wrong way to implement each feature. The
goal is that a reviewer can find them by reading the request handlers, then
confirm them with an HTTP client.

The project ships in three layers:

| Layer | File | Purpose |
|---|---|---|
| Vulnerable service | `auth_server.py` | The code under review |
| Review guide | `docs/REVIEW_GUIDE.md` | How to run the exercise without spoilers |
| Answer key | `docs/VULNERABILITIES.md` | Every planted flaw, how to exploit or verify it, and how to fix it |

A verifier, `tools/verify_flaws.py`, starts the service with a throwaway
database and exercises the documented attack surface with real requests. It is
also a worked example of the exploit chains.

## Quick start

The pinned stack is verified on Python 3.9.6. It is deliberately old, so newer
Python releases may refuse to build it; use a 3.9 container if necessary, or
update the pins and adjust A06 in the answer key.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python auth_server.py
```

The server listens on `http://127.0.0.1:5001`. Useful options:

```bash
python auth_server.py --port 5002
python auth_server.py --no-debug      # disables debug mode; removes one finding
```

The database (`badas.db`) and log (`badas.log`) are created on first start;
`uploads/` ships with a sample file. Delete the database and log to reset the
lab:

```bash
rm -f badas.db badas.log
```

### Seeded accounts

| Username | Password | Role |
|---|---|---|
| `root` | `password` | admin |
| `alice` | `alice123` | user |
| `bob` | `hunter2` | user |
| `dave` | `dave` | user |

The seeded credentials are deliberately terrible. They are part of the
exercise, not a setup step to fix.

### Client

`auth_client.py` is a thin CLI for manual exploration:

```bash
python auth_client.py login root password
python auth_client.py user 2
python auth_client.py search alice
python auth_client.py me <token>
python auth_client.py fetch http://127.0.0.1:5001/debug
python auth_client.py ping '127.0.0.1; id'
```

Use `--url http://127.0.0.1:5002` if you changed the port. The client prints
the raw status and body so it stays useful as a review tool.

## Service map

| Method | Path | What it does |
|---|---|---|
| GET | `/` | Landing page |
| GET/POST | `/login` | HTML login, session cookie, `next` redirect |
| GET | `/logout` | Logs the user out |
| GET/POST | `/register` | Account creation |
| POST | `/api/login` | JSON login; returns a JWT and session cookie |
| GET | `/api/session` | Returns the current server-side session |
| GET | `/api/me` | Returns claims from a bearer JWT (or `?token=`) |
| POST | `/account/password` | Changes the logged-in user's password |
| GET | `/api/users/<id>` | User profile |
| GET | `/api/users/search?q=` | Username search |
| PUT | `/api/users/<id>` | Updates user fields |
| DELETE | `/api/users/<id>` | Deletes a user |
| GET | `/admin/users` | Admin user list |
| GET | `/admin/export` | CSV export of all users |
| GET | `/admin/audit` | Returns the application log |
| GET | `/files?name=` | Reads a file from `uploads/` |
| GET | `/fetch?url=` | Fetches a remote URL |
| GET | `/ping?host=` | Pings a host |
| GET | `/greet?name=` | Renders a greeting |
| POST | `/api/calc` | Evaluates an arithmetic expression |
| GET | `/debug` | Diagnostics and configuration |
| POST | `/reset/request` | Requests a password-reset token |
| POST | `/reset/confirm` | Confirms a password reset |

## Finding the flaws

Start with `docs/REVIEW_GUIDE.md`. It explains the exercise, suggests a review
workflow, and gives a category checklist without revealing answers.

When you have written up your own findings, open `docs/VULNERABILITIES.md`.
It covers 46 findings across A01–A10, and each entry has:

- the OWASP Top 10 2021 category and CWE,
- the exact handler or route,
- a concrete exploitation request where one applies,
- the impact,
- a mitigation with the corrected pattern.

Some findings are deliberately cross-cutting: the same weak secret appears in
the source, `/debug`, and the admin export; the reset token is predictable,
never expires, and is returned in the response. The answer key calls out those
chains rather than pretending each flaw is isolated.

## Verifying the lab

```bash
.venv/bin/python tools/verify_flaws.py
```

The verifier starts a fresh instance on a free localhost port with a temporary
database and log, runs 37 exploit checks, and prints a pass/fail table. It
exits non-zero if any documented behaviour has drifted. Running it before you
have attempted the review will spoil most of the exercise.

## Design notes

- **One bad decision per feature.** The login handler shows string-built SQL;
  the session code shows fixation and weak identifiers; the file endpoint shows
  traversal; the fetch endpoint shows SSRF.
- **Reachable, not theoretical.** Every major flaw is exercised by the
  verifier, including the RCE paths. No flaw exists only in a comment.
- **Realistic shape.** The service has the endpoints, error messages, and
  admin conveniences that make these flaws appear in production. It is not a
  collection of disconnected snippets.
- **Documented mitigations.** The answer key pairs each flaw with the boring,
  standard fix: parameterised queries, Argon2id, authorization middleware,
  CSRF tokens, strict JWT validation, an SSRF allowlist, and so on.

## Layout

```text
auth_server.py              vulnerable Flask service
auth_client.py              CLI client
requirements.txt            intentionally outdated pins
uploads/                    file-delivery root
docs/REVIEW_GUIDE.md        exercise instructions and checklist
docs/VULNERABILITIES.md     answer key with exploit and mitigation
tools/verify_flaws.py       live exploit verifier
```

## Scope and safety

BadAS is for local, educational use. The database and accounts are synthetic.
The only "secrets" are fake values committed on purpose. If you adapt this for
a classroom or workshop, keep the service bound to localhost or an isolated
container network, and tell participants explicitly that the application is
hostile by construction.
