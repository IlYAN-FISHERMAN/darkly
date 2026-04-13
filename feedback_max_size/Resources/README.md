# Feedback Form — Oversized Input / Missing Server-Side Validation

## Summary

This breach exploits a feedback form that enforces input length restrictions only on the client side (via HTML `maxlength` attributes or frontend JavaScript). By intercepting the HTTP request and replacing a field value with a payload far exceeding the expected maximum length, the server processes the oversized input without complaint and returns the flag — demonstrating a complete absence of server-side input validation.

---

## Category

**Improper Input Validation / Missing Server-Side Validation**
OWASP: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) /
[A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## Steps to Reproduce

### 1. Navigate to the feedback page

Open the feedback form in the browser. It contains standard fields (name, message, etc.) with visible length limits enforced by the frontend.

### 2. Intercept the request

Set up a proxy (e.g. **Burp Suite** or **OWASP ZAP**) to intercept outgoing HTTP traffic, or use the browser's built-in network devtools to capture the form submission.

Fill in the form fields normally and click submit — then intercept the request before it reaches the server.

The raw POST body will look something like:

```
name=John&feedback=Hello&submit=Submit
```

### 3. Replace a field value with an oversized payload

In the intercepted request, replace the value of a field (e.g. `name`) with a very long string — well beyond any reasonable maximum:

```
name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&feedback=Hello&submit=Submit
```


### 4. Forward the request

Let the modified request through to the server. Because no server-side length validation exists, the application processes the oversized input and returns the flag.

---

## Why This Works

HTML attributes like `maxlength` and frontend JavaScript validation are **browser-enforced only**. Any user who can send a raw HTTP request — which is everyone — bypasses them entirely. The server received an oversized value it never expected, triggering an unhandled code path that revealed the flag.

This is one of the most fundamental and enduring rules in web security:

> **Never trust the client. All validation must be repeated on the server.**

Client-side validation is a UX convenience. It is not a security control.

---

## Root Cause

| Problem | Detail |
|---|---|
| Validation only on client | `maxlength` / JS checks are trivially bypassed by intercepting the request |
| No server-side length check | The backend processes input of arbitrary length with no guard |
| Unhandled edge case | An oversized value triggers a code path that exposes sensitive output |

---

## Remediation

### Always validate on the server

Every constraint enforced in the frontend must be independently enforced on the backend. Client-side checks should be treated as a convenience layer only.

---

## References

- [OWASP: Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
- [OWASP: Testing for Client-Side Validation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/07-Testing_Cross_Site_Script_Inclusion)
