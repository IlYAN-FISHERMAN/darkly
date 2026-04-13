# Password Recovery — Email Parameter Tampering

## Summary

This breach exploits a password recovery form that accepts the destination email address as a client-controlled parameter in the HTTP request. By intercepting the request and changing the email value to any address of the attacker's choosing, the application processes the modified request without verification — demonstrating that the server applies no server-side binding between the recovery action and the legitimate account owner's email.

---

## Category

**Broken Access Control / Parameter Tampering**
OWASP: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
CWE: [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)

---

## Steps to Reproduce

### 1. Locate the password recovery form

Navigate to the forgotten password / account recovery page on the BornToSec web application. The form presents an email field pre-populated or associated with the account (in this case `webmaster@borntosec.com`).

### 2. Intercept the request

Set up Burp Suite to intercept outgoing requests. Submit the recovery form, then catch the request before it reaches the server.

The outgoing request will contain the email as a parameter, for example:

```
POST /index.php?page=recover HTTP/1.1
...

mail=webmaster%40borntosec.com&Submit=Submit
```

or as a GET parameter:

```
GET /index.php?page=recover&mail=webmaster@borntosec.com&Submit=Submit
```

### 3. Modify the email parameter

In Burp Suite's Intercept panel, replace the original email value with any target address:

```
mail=attacker@evil.com
```

The server has no mechanism to verify that this address belongs to the account being recovered, or that the client is authorised to redirect the recovery to a different address.

### 4. Forward the request

Forward the modified request. The server processes it as valid and returns the flag:

```
1d4855f7337c0c14b6f44946872c4eb33853f40b2d54393fbe94f49f1e19bbb0
```

---

## Why This Works

Password recovery flows require a strict, server-side binding: the recovery email must come from the **server's own stored record** for that account, never from the incoming request. Accepting the destination email as a client parameter means the client decides where the recovery link goes — an attacker can redirect it to an address they control and take over the account entirely.

The server treats the email field as trusted input. It is not.

---

## Root Cause

| Problem | Detail |
|---|---|
| Recovery email supplied by client | The `mail` parameter in the request determines where recovery is sent |
| No server-side lookup | The server does not fetch the email from the user record in the database |
| No CSRF token | The recovery form has no anti-CSRF protection, making the request trivially replayable |
| No confirmation step | The recovery action is executed immediately on the intercepted request with no secondary verification |

---

## Remediation

### 1. Never accept the target email as a request parameter

The recovery destination must be read exclusively from the server-side user record. The only input the client should provide is an identifier (username or the email itself as a *lookup key*, not a *delivery destination*):

```python
# Correct flow
def request_recovery(username_or_email):
    user = db.find_user(username_or_email)
    if user:
        token = generate_secure_token()
        store_token(user.id, token, expiry=timedelta(hours=1))
        # Email address comes from the DATABASE — never from the request
        send_recovery_email(to=user.email, token=token)
```

```php
// PHP equivalent
$user = $db->findByEmail($_POST['email']); // email used only as lookup key
if ($user) {
    $token = bin2hex(random_bytes(32));
    $db->storeToken($user->id, $token, time() + 3600);
    mail($user->email, "Password Reset", "https://site.com/reset?token=$token");
    //   ^^^^^^^^^^^^ from DB, not from $_POST
}
```

### 2. Use time-limited, single-use tokens

Recovery tokens should:
- Be cryptographically random (`random_bytes(32)` / `secrets.token_urlsafe()`)
- Expire after a short window (15–60 minutes)
- Be invalidated immediately after use
- Be stored as a hash server-side (so a database leak doesn't yield usable tokens)

```python
import secrets, hashlib

raw_token = secrets.token_urlsafe(32)
token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
db.store_reset_token(user_id=user.id, token_hash=token_hash, expires_in=3600)
send_email(user.email, reset_link=f"/reset?token={raw_token}")
```

### 3. Add CSRF protection to the recovery form

Include a server-generated, session-bound CSRF token in every form submission so the request cannot be forged or replayed by an intercepting attacker:

```html
<form method="POST" action="/recover">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="email" name="email">
    <button type="submit">Send recovery link</button>
</form>
```

### 4. Rate-limit recovery requests

Limit the number of recovery requests per email address and per IP to prevent enumeration and abuse:

```python
@limiter.limit("3 per hour", key_func=lambda: request.form.get("email"))
@limiter.limit("10 per hour", key_func=get_remote_address)
def recover():
    ...
```

### 5. Respond identically whether the account exists or not

To prevent account enumeration, always return the same message regardless of whether the email matched a real account:

```
"If an account with that email exists, a recovery link has been sent."
```

---

## References

- [OWASP: Testing for Account Enumeration and Guessable User Account](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [OWASP: Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP: CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-640: Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
