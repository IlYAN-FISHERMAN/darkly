# Survey Grade — Client-Side Maximum Value Bypass

## Summary

This breach exploits a survey form that enforces a maximum grade value of 10 only on the client side. By intercepting the POST request and submitting a value larger than 10, the server accepts the out-of-range input without complaint — another instance of trusting the client to enforce business logic that only the server should control.

---

## Category

**Improper Input Validation / Client-Side Enforcement of Server-Side Security**
OWASP: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
CWE: [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html) /
[CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)

---

## Steps to Reproduce

### 1. Locate the survey / grading form

Navigate to the survey page on the BornToSec web application. The form presents a grade or rating input, visually constrained to a range of 1–10 (via an HTML `<select>`, `<input type="range">`, or `max` attribute).

### 2. Intercept the POST request

Set up Burp Suite to intercept outgoing requests. Submit the form with any valid in-range value, then catch the POST request before it reaches the server.

The body will contain a grade parameter, for example:

```
grade=10&sujet=2&submit=Submit
```

### 3. Modify the grade value

In Burp Suite's Intercept panel, replace the grade value with a number exceeding 10:

```
grade=1337&sujet=2&submit=Submit
```

### 4. Forward the request

Forward the modified request. The server processes the out-of-range value without validation and returns the flag:

```
03a944b434d5baff05f46c4bede5792551a2595574bcafc9a6e25f67c382ccaa
```

---

## Why This Works

HTML form constraints — `max`, `min`, `maxlength`, `type="range"`, and `<select>` option lists — are enforced by the browser rendering the form. They do not exist in the HTTP request itself. Any tool that sends HTTP directly (Burp Suite, curl, Python requests) bypasses them completely. The server received a value of `1337` and had no code to reject it.

This is the same fundamental flaw as the feedback oversized input breach — validation exists only in the frontend, which the attacker never touches.

---

## Root Cause

| Problem | Detail |
|---|---|
| Range enforced only by HTML attributes | `max="10"` on the input is a browser hint, not a server constraint |
| No server-side bounds check | The backend processes any integer value submitted, regardless of range |
| Business logic lives in the client | The rule "grades must be between 1 and 10" is only expressed in the UI |

---

## Remediation

### 1. Validate the range on the server

Every constraint the frontend enforces must be independently verified on the backend. The check must happen before the value is used:

```python
# Python / Flask
grade = request.form.get("grade", type=int)

if grade is None or not (1 <= grade <= 10):
    abort(400, "Grade must be between 1 and 10.")
```

```php
// PHP
$grade = intval($_POST['grade']);

if ($grade < 1 || $grade > 10) {
    http_response_code(400);
    die("Grade must be between 1 and 10.");
}
```

### 2. Use a schema / validation library

Centralise all field constraints in a schema so they cannot be omitted for any endpoint:

```python
# Python with marshmallow
from marshmallow import Schema, fields, validate

class SurveySchema(Schema):
    grade = fields.Int(required=True, validate=validate.Range(min=1, max=10))
    sujet = fields.Int(required=True)

schema = SurveySchema()
errors = schema.validate(request.form)
if errors:
    abort(400, str(errors))
```

### 3. Treat client-side constraints as UX only

Retain HTML `min`/`max` attributes and `<select>` lists — they provide a good user experience by giving immediate feedback. They just must never be the *only* enforcement layer. Think of the frontend as a helpful guide and the backend as the actual gatekeeper.

### 4. Enforce constraints at the database level too

Add a CHECK constraint at the database layer as a final safety net:

```sql
ALTER TABLE survey_responses
    ADD CONSTRAINT chk_grade CHECK (grade BETWEEN 1 AND 10);
```

This ensures that even if application-layer validation is accidentally bypassed, invalid data can never be persisted.

---

## References

- [OWASP: Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
