# I_am_admin Cookie

## Summary

This breach exploits a poorly designed authentication mechanism that stores an admin privilege flag directly inside a client-side cookie as an unsalted MD5 hash. By decoding the hash, modifying the value, and re-encoding it, an attacker can grant themselves admin access with no credentials required.

---

## Category

**Cookie Tampering / Broken Authentication**
OWASP: [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---

## Steps to Reproduce

### 1. Open the target site and inspect cookies

Navigate to the BornToSec web application in your browser. Open the browser's developer tools (F12) and go to the **Application** → **Cookies** tab. You will find a cookie named:

```
I_am_admin
```

with a value similar to:

```
68934a3e9455fa72420237eb05902327
```

### 2. Identify the hash

The value is a 32-character hexadecimal string — a classic MD5 digest. Paste it into any MD5 reverse-lookup tool (e.g. [md5decrypt.net](https://md5decrypt.net), [crackstation.net](https://crackstation.net)) or run it locally:

```bash
# Verify the hash
echo -n "false" | md5sum
# Output: 68934a3e9455fa72420237eb05902327
```

The cookie decodes to the plaintext string **`false`** — meaning the application is simply storing `md5("false")` to indicate the current user is *not* an admin.

### 3. Compute the forged value

Generate the MD5 hash of the string **`true`**:

```bash
echo -n "true" | md5sum
# Output: b326b5062b2f0e69046810717534cb09
```

### 4. Overwrite the cookie

Using your browser's dev tools or a tool like **Cookie Editor**, change the `I_am_admin` cookie value from:

```
68934a3e9455fa72420237eb05902327   ← md5("false")
```

to:

```
b326b5062b2f0e69046810717534cb09   ← md5("true")
```

### 5. Reload the page

Refresh the page. The server reads the cookie, computes nothing more than a hash comparison, and grants admin privileges — revealing the flag.

---

## Why This Works

The application trusts a value stored entirely on the client side (the cookie) to make a security decision. It uses MD5 as its "protection", but MD5:

- **Is not a secret** — it is a public, deterministic function. Anyone who can see the hash output can reproduce it.
- **Is not a keyed function** — there is no secret salt, so an attacker can independently hash any input.
- **Has preimage lookup tables** — common strings like `"false"` and `"true"` appear in rainbow tables and are instantly reversible online.

This means the "hash" provides zero security. It is security through obscurity at best.

---

## Root Cause

| Problem | Detail |
|---|---|
| Client-side trust | Admin status is determined by a cookie the user can freely edit |
| Weak hashing | MD5 is used as if it were encryption or a MAC — it is neither |
| No server-side session | There is no server-stored session record to cross-check the cookie against |
| No signing/HMAC | The cookie carries no cryptographic signature, so forgery is trivial |

---

## Remediation

1. **Never store authorization state in client-side cookies without signing them.** Use a framework-provided session mechanism that keeps the authoritative state server-side (e.g. a session ID mapped to a server-side store).

2. **If you must embed data in a cookie, sign it.** Use HMAC-SHA256 with a secret key. Libraries like `itsdangerous` (Python), `express-session` (Node), or built-in signed cookies in Rails/Laravel handle this automatically.

3. **Do not use MD5 for any security purpose.** It is cryptographically broken. For password hashing use bcrypt, Argon2, or scrypt. For integrity use HMAC-SHA256 or higher.

4. **Apply the principle of least privilege.** Admin flags should be stored in the database and retrieved on the server after authenticating a session — never handed to the client.

### Secure pattern (pseudocode)

```python
# On login — store only a session ID in the cookie
session_id = generate_secure_random_token()
session_store[session_id] = {"user_id": user.id, "is_admin": user.is_admin}
set_cookie("session", session_id, httponly=True, secure=True, samesite="Strict")

# On each request — look up state server-side, never trust cookie content
session = session_store.get(request.cookies["session"])
if session and session["is_admin"]:
    grant_admin_access()
```

---

## References

- [OWASP: Testing for Cookies Attributes](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes)
- [OWASP: Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication)
- [CWE-565: Reliance on Cookies without Validation and Integrity Checking](https://cwe.mitre.org/data/definitions/565.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
