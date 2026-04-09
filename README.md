*This project has been created as part of the 42 curriculum by cbopp and ilyanar*
# darkly

# Darkly — Enumeration Findings

## Directory Enumeration (DirBuster)

| Path | Status | Redirect |
|------|--------|----------|
| `/images/` | 301 | http://10.11.10.2/images/ |
| `/admin/` | 301 | http://10.11.10.2/admin/ |
| `/audio/` | 301 | http://10.11.10.2/audio/ |
| `/css/` | 301 | http://10.11.10.2/css/ |
| `/includes/` | 301 | http://10.11.10.2/includes/ |
| `/js/` | 301 | http://10.11.10.2/js/ |
| `/fonts/` | 301 | http://10.11.10.2/fonts/ |
| `/errors/` | 301 | http://10.11.10.2/errors/ |
| `/whatever/` | 301 | http://10.11.10.2/whatever/ |

---

## SQL Injection Enumeration (sqlmap)

### Available Databases (6)

- `information_schema`
- `Member_Brute_Force`
- `Member_guestbook`
- `Member_images`
- `Member_Sql_Injection`
- `Member_survey`

---

### Database: `information_schema` — 63 tables

<details>
<summary>Show all tables</summary>

| Table |
|-------|
| CHARACTER_SETS |
| CLIENT_STATISTICS |
| COLLATIONS |
| COLLATION_CHARACTER_SET_APPLICABILITY |
| COLUMN_PRIVILEGES |
| COLUMNS |
| ENGINES |
| EVENTS |
| FILES |
| GLOBAL_STATUS |
| GLOBAL_VARIABLES |
| INDEX_STATISTICS |
| INNODB_BUFFER_PAGE |
| INNODB_BUFFER_PAGE_LRU |
| INNODB_BUFFER_POOL_PAGES |
| INNODB_BUFFER_POOL_PAGES_BLOB |
| INNODB_BUFFER_POOL_PAGES_INDEX |
| INNODB_BUFFER_POOL_STATS |
| INNODB_CHANGED_PAGES |
| INNODB_CMP |
| INNODB_CMPMEM |
| INNODB_CMPMEM_RESET |
| INNODB_CMP_RESET |
| INNODB_INDEX_STATS |
| INNODB_LOCKS |
| INNODB_LOCK_WAITS |
| INNODB_RSEG |
| INNODB_SYS_COLUMNS |
| INNODB_SYS_FIELDS |
| INNODB_SYS_FOREIGN |
| INNODB_SYS_FOREIGN_COLS |
| INNODB_SYS_INDEXES |
| INNODB_SYS_STATS |
| INNODB_SYS_TABLES |
| INNODB_SYS_TABLESTATS |
| INNODB_TABLE_STATS |
| INNODB_TRX |
| INNODB_UNDO_LOGS |
| KEY_CACHES |
| KEY_COLUMN_USAGE |
| PARAMETERS |
| PARTITIONS |
| PLUGINS |
| PROCESSLIST |
| PROFILING |
| QUERY_CACHE_INFO |
| REFERENTIAL_CONSTRAINTS |
| ROUTINES |
| SCHEMATA |
| SCHEMA_PRIVILEGES |
| SESSION_STATUS |
| SESSION_VARIABLES |
| STATISTICS |
| TABLES |
| TABLESPACES |
| TABLE_CONSTRAINTS |
| TABLE_PRIVILEGES |
| TABLE_STATISTICS |
| TRIGGERS |
| USER_PRIVILEGES |
| USER_STATISTICS |
| VIEWS |
| XTRADB_ADMIN_COMMAND |

</details>

---

### Database: `Member_Brute_Force`

| Table |
|-------|
| db_default |

---

### Database: `Member_guestbook`

| Table |
|-------|
| guestbook |

---

### Database: `Member_images`

| Table |
|-------|
| list_images |

---

### Database: `Member_Sql_Injection`

| Table |
|-------|
| users |

---

### Database: `Member_survey`

| Table |
|-------|
| vote_dbs |

---

## Table Data

### `Member_images.list_images` - 5 entries

| id | url | title | comment |
|----|-----|-------|---------|
| 1  | https://fr.wikipedia.org/wiki/Programme_ | Nsa       | An image about the NSA ! |
| 2  | https://fr.wikipedia.org/wiki/Fichier:42 | 42 !      | There is a number.. |
| 3  | https://fr.wikipedia.org/wiki/Logo_de_Go | Google    | Google it ! |
| 4  | https://en.wikipedia.org/wiki/Earth#/med | Earth     | Earth!          |
| 5  | borntosec.ddns.net/images.png            | Hack me ? | If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46 |



### `Member_survey.vote_dbs` — 5 entries

| id_vote | subject | vote | nb_vote |
|---------|---------|------|---------|
| 2 | wil | 4217.2 | 4257 |
| 3 | alex | 5.4375 | 16 |
| 4 | Thor | 8.64707 | 17 |
| 5 | Ben | 9.1 | 666 |
| 6 | ol | 6.969 | 69 |

---

### `Member_Sql_Injection.users` — 4 entries

| user_id | first_name | last_name | town | country | planet | Commentaire | countersign |
|---------|------------|-----------|------|---------|--------|-------------|-------------|
| 1 | one | me | Paris | France | EARTH | Je pense, donc je suis | `2b3366bcfd44f540e630d4dc2b9b06d9` |
| 2 | two | me | Helsinki | Finlande | Earth | Aamu on iltaa viisaampi. | `60e9032c586fb422e2c16dee6286cf10` (oktoberfest) |
| 3 | three | me | Dublin | Irlande | Earth | Dublin is a city of stories and secrets. | `e083b24a01c483437bcf4a9eea7c1b4d` |
| 5 | Flag | GetThe | 42 | 42 | 42 | Decrypt this password -> then lower all the char. Sh256 on it and it's good ! | `5ff9d0165b4f92b14994e5c685cdce28` |

