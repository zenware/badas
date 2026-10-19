# Review guide

This guide is for the person doing the review. It explains how to run BadAS,
how to work through it, and how to write findings. It deliberately does **not**
list the flaws. When you are ready, the answer key is in
`docs/VULNERABILITIES.md`, and `tools/verify_flaws.py` proves the behaviour.

## Safety first

BadAS is hostile by construction. It contains working authentication bypasses
and remote code execution. Run it on `127.0.0.1`, in a disposable environment,
with synthetic data. Do not expose it to a network, do not point it at real
services, and do not reuse its code. The "secrets" in the repository are fake
values committed on purpose.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python auth_server.py
```

The server listens on `http://127.0.0.1:5001`. Leave debug mode on for the
exercise; one of the findings depends on it. To start fresh:

```bash
rm -f badas.db badas.log
```

Seeded accounts are listed in the README. The CLI client is convenient for
manual requests:

```bash
python auth_client.py login root password
python auth_client.py user 1
```

`curl` works just as well. Keep a scratch file of requests and responses; the
evidence is part of a good finding.

## The exercise

Work in passes rather than trying to read the whole file at once.

### Pass 1 — Map the surface

Read `auth_server.py` and list every route. For each one, record:

- the HTTP method and path,
- the handler function,
- the inputs it accepts (path, query, body, cookies, headers),
- the state it reads or changes,
- who is supposed to be allowed to call it.

The README service map is a starting point, but verify it against the code.

### Pass 2 — Follow the data

For each input, trace it from the request to its sink: a SQL query, a shell
command, a template, `eval`, a file path, an outbound HTTP request, a log line,
or an HTML response. Ask what happens if the value contains quotes, newlines,
`../`, a URL, a template expression, or a JSON field the developer did not
expect.

### Pass 3 — Check the decisions

For each state-changing route, ask:

- Is there an authentication check at all?
- Is there an authorization check against the specific object?
- Can the client influence the role, owner, or identifier?
- Is the action protected against CSRF?
- Is the session rotated, expired, or revoked correctly?
- Are errors and secrets returned to the caller?

### Pass 4 — Check the platform

Read `requirements.txt`, the Flask configuration, the cookie settings, the
logging setup, and the startup command. Ask what a deployment of this code
would expose: debug pages, version banners, missing headers, verbose errors,
cleartext transport, default accounts.

## OWASP-oriented checklist

Use these questions as prompts. They are generic on purpose.

### A01 — Broken access control

- Does every route check authentication, or only the ones with an obvious
  "admin" name?
- Does authorization check the object, not just the action?
- Can a client change an ID, role, owner, or hidden field and get a different
  result?
- Are state-changing requests protected against CSRF?
- Are redirects restricted to local destinations?
- Can a path or filename escape its intended directory?

### A02 — Cryptographic failures

- How are passwords stored? Salted? Slow? Tuned?
- Are keys and secrets in source, config, or environment?
- How are session identifiers and reset tokens generated? How much entropy?
- Do sensitive values appear in URLs, responses, logs, or caches?
- Is transport encrypted end to end?

### A03 — Injection

- Is any request data concatenated into SQL, a shell command, a template, or
  `eval`?
- Are SQL values parameterized? Are identifiers allowlisted?
- Is `shell=True` used with user input?
- Is user input ever treated as template source?
- Is HTML output escaped in every context?
- Are logs built from unescaped user input?

### A04 — Insecure design

- Can authentication be attempted without limit?
- What password policy exists, and is it based on modern guidance?
- Do error messages reveal whether an account exists?
- Does password recovery prove identity, expire, and prevent reuse?
- Is MFA available or required for sensitive roles?
- Do sensitive actions require re-authentication?

### A05 — Security misconfiguration

- Is debug mode or an interactive debugger reachable?
- Is there a diagnostic endpoint that exposes configuration or state?
- Is CORS scoped to trusted origins, and is credentials mode justified?
- Are CSP, frame protection, HSTS, nosniff, and cache controls present?
- Do cookies have `HttpOnly`, `Secure`, and `SameSite`?
- Do errors reveal stack traces, SQL, paths, or internal hosts?

### A06 — Vulnerable and outdated components

- Are dependencies pinned to versions with known advisories?
- Is the runtime still supported?
- Is there automated dependency scanning?
- Do response headers disclose versions?

### A07 — Identification and authentication failures

- Are default or weak credentials present?
- Is the session ID regenerated at login and privilege change?
- Does logout invalidate the session server-side?
- Do sessions expire and rotate?
- Are JWTs verified strictly, including algorithm, signature, expiry, issuer,
  audience, and role source?
- Are tokens accepted from URLs or logs?

### A08 — Software and data integrity failures

- Is any untrusted data deserialized with a format that can execute code?
- Are cookies and client-side state signed or otherwise integrity-protected?
- Are dependencies and build artifacts verified?

### A09 — Security logging and monitoring failures

- Do logs contain passwords, tokens, or full request bodies?
- Can user input forge or break log entries?
- Is there alerting for failed logins, privilege changes, and bulk exports?
- Is the audit trail access-controlled, retained, and tamper-evident?
- Are failed authentication events recorded at all?

### A10 — Server-side request forgery

- Can the server be asked to fetch an arbitrary URL?
- Are schemes, hosts, ports, and redirects restricted?
- Are private, loopback, link-local, and metadata addresses blocked after DNS
  resolution?
- Does the response body come back to the caller?
- Are timeouts and response sizes bounded?

## Writing a finding

Use a consistent format. A concise, reproducible finding is more useful than a
long one.

```markdown
### Title

- **Location:** `function()` / `METHOD /path`
- **Category:** OWASP A0x / CWE-xxx
- **Severity:** Critical | High | Medium | Low
- **Preconditions:** unauthenticated, any user, admin, etc.

**Description**
What the code does and why it is wrong, in two or three sentences.

**Reproduction**
Exact request(s) and the observed response. Include status codes and the
relevant body or header.

**Impact**
What an attacker gains and what data or capability is lost.

**Remediation**
The specific fix, with the safe API or pattern. Mention defense in depth when
one control is not enough.
```

Prefer evidence over adjectives. "The response contains
`password_md5=5f4d...`, which equals MD5 of the seeded password" is stronger
than "the endpoint leaks sensitive data".

## Scoring suggestions

If you are using BadAS for a class or study group:

| Level | Target |
|---|---|
| Warm-up | Find 8 findings across at least 4 OWASP categories |
| Working review | Find 15 findings, including one full exploit chain |
| Thorough review | Find 25+ findings, including every RCE path and the auth/session flaws |
| Answer key | Match the documented findings and explain which single fix breaks the most chains |

Quality beats count. A well-evidenced high-severity finding with a correct
mitigation is worth more than ten speculative ones.

## If you get stuck

- Follow every user-controlled string until it reaches a sink.
- Compare routes that look similar; one may have an authorization check and
  another may not.
- Look at what the login response returns, not just the status code.
- Inspect every `Set-Cookie` header, not just the HTML.
- Try the endpoints without a cookie, with an ordinary user, and with an
  admin.
- Read the imports and the startup command. Some findings are configuration,
  not request handling.
- Check what happens with quote characters, newlines, `..`, `file://`, and
  unexpected JSON keys.

## Revealing the answer key

When you have written your findings:

1. Open `docs/VULNERABILITIES.md` and compare. It covers 46 findings across
   A01–A10 with exploits and mitigations.
2. Run `.venv/bin/python tools/verify_flaws.py`. It starts a fresh instance
   with a temporary database and runs 37 exploit checks. It is a worked
   example of the requests, not a substitute for the review.
3. Pick one exploit chain from the answer key and explain, in your own words,
   which control would have broken it earliest.

## Discussion questions

- Which finding is the highest-impact, and which is the most likely to be
  dismissed as "only a configuration issue"?
- Which single mitigation removes the most attack paths: parameterized SQL,
  authentication middleware, strict JWT verification, or removing pickle?
- Why is a six-digit session ID a problem even if it is generated randomly?
- Why does returning a password hash from an API matter if the hash is
  "one-way"?
- How would you test that every route has an authorization check, rather than
  checking them one by one?
- Which flaws would still exist after adding a web application firewall?
