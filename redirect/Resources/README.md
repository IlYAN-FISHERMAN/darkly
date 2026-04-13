# Open Redirect — Unvalidated URL Redirect via `site` Parameter

## Summary

This breach exploits a redirect endpoint that accepts a destination URL as a plain, unvalidated query parameter. By passing any arbitrary domain to the `site` parameter, an attacker can cause the application to redirect users to a completely external site — with the trusted domain appearing in the initial link. This is a classic open redirect vulnerability, commonly exploited in phishing campaigns.

---

## Category

**Open Redirect / Unvalidated Redirect**
OWASP: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
CWE: [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)

---

## Steps to Reproduce

### 1. Identify the redirect endpoint

The application exposes a redirect page via the `page` parameter:

```
http://{MACHINE_IP}/index.php?page=redirect&site=
```

### 2. Supply an arbitrary destination

Pass any external domain as the `site` value:

```
http://{MACHINE_IP}/index.php?page=redirect&site=google.com
```

The server performs the redirect to `google.com` without validating whether that destination is permitted.

### 3. Flag

The server returns the flag before or during the redirect:

```
b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab4
```

---

## Why This Works

The application passes the `site` parameter value directly into a redirect response with no validation:

```php
// What the vulnerable code likely looks like
header("Location: http://" . $_GET['site']);
exit();
```

There is no check that the destination is on an approved list of internal pages or trusted domains. The server trusts the client entirely to provide a safe redirect target — which it cannot.

---

## Real-World Impact

On its own, an open redirect does not compromise the server. Its danger is in how it enables attacks against **users**:

**Phishing:** An attacker crafts a link using the trusted domain as the visible host, but redirecting to a malicious lookalike:

```
http://trusted-bank.com/index.php?page=redirect&site=evil-bank.com/login
```

The user sees `trusted-bank.com` in the URL bar when they click the link — by the time they notice the redirect, they are on the attacker's page. This is particularly effective in emails, where link previews show the original domain.

**OAuth token theft:** Some OAuth flows use redirect URIs. If an authorisation server uses an open redirect on its domain, an attacker can manipulate the `redirect_uri` to exfiltrate the access token via the open redirect endpoint on the same trusted domain.

---

## Root Cause

| Problem | Detail |
|---|---|
| Destination URL fully client-controlled | `$_GET['site']` is used directly as the redirect target |
| No allowlist of permitted destinations | Any domain is accepted without validation |
| No warning page | The redirect fires immediately with no interstitial prompt to the user |

---

## Remediation

### 1. Use an allowlist of permitted redirect destinations

The most robust fix — only allow redirects to a predefined set of known-safe destinations:

```php
$allowed = [
    "home"    => "/index.php?page=home",
    "profile" => "/index.php?page=profile",
    "upload"  => "/index.php?page=upload",
];

$key = $_GET['site'] ?? "";
if (!array_key_exists($key, $allowed)) {
    http_response_code(400);
    die("Invalid redirect destination.");
}

header("Location: " . $allowed[$key]);
exit();
```

By mapping user-supplied keys to server-controlled URLs, the user never controls the actual destination.

```python
# Python / Flask equivalent
ALLOWED_REDIRECTS = {
    "home":    "/",
    "profile": "/profile",
}

dest_key = request.args.get("site", "")
dest_url = ALLOWED_REDIRECTS.get(dest_key)

if not dest_url:
    abort(400)

return redirect(dest_url)
```

### 2. If redirecting to user-supplied URLs is required, restrict to the same origin

If the use case genuinely requires dynamic URLs (e.g. post-login return URLs), validate that the destination is on the same domain:

```python
from urllib.parse import urlparse

def is_safe_redirect(url: str) -> bool:
    parsed = urlparse(url)
    # Allow only relative URLs or same-host absolute URLs
    return not parsed.netloc or parsed.netloc == request.host

return_to = request.args.get("next", "/")
if not is_safe_redirect(return_to):
    return_to = "/"

return redirect(return_to)
```

### 3. Add an interstitial warning page

If external redirects are a genuine product requirement, show a warning page before sending the user off-site:

```
You are leaving trusted-site.com and being redirected to:
  → google.com

[ Continue ]   [ Go back ]
```

This eliminates the phishing risk by making the redirect destination explicit before the user leaves.

### 4. Avoid redirect endpoints entirely where possible

If the redirect endpoint exists only to send users to internal pages, replace it with direct links. Redirect-via-parameter patterns are rarely necessary and consistently dangerous.

---

## References

- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [OWASP: Testing for Client-Side URL Redirect](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/04-Testing_for_Client-Side_URL_Redirect)
- [CWE-601: URL Redirection to Untrusted Site ('Open Redirect')](https://cwe.mitre.org/data/definitions/601.html)
- [PortSwigger: Open Redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)
