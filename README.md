# 👻 SpecterSqli

**SpecterSqli** is a **lab-focused SQL Injection scanner** designed for learning, CTFs, and defensive understanding.
It combines **endpoint discovery, parameter enumeration, concurrency, boolean & time-based SQLi detection, blind data extraction, JSON API support, cookie-based sessions, and reporting** in a single Python tool.

> ⚠️ **Legal Notice:**
> This tool is intended **only for systems you own or have explicit permission to test** (CTFs, labs, training environments).
> Do **NOT** use against unauthorized targets.

---

## ✍️ Author

**rhshourav**
Security Learner | Python | Offensive & Defensive Testing
GitHub: [https://github.com/rhshourav](https://github.com/rhshourav)

---

## 🚀 Features

* ✅ Automatic **endpoint discovery (crawler)**
* ✅ GET & POST **parameter discovery**
* ✅ **Concurrent scanning** of many endpoints
* ✅ Boolean-based SQL injection testing
* ✅ Time-based blind SQL injection detection
* ✅ Blind **per-character data extraction** (lab-only)
* ✅ JSON API support
* ✅ Cookie-based authenticated sessions
* ✅ Vulnerable vs secure backend comparison
* ✅ HTML report with **response-time charts**
* ✅ Defensive security guidance in report
* ✅ Clean CLI interface with `--help`

---

## 🧠 What SpecterSqli Teaches You

SpecterSqli is not just a scanner — it helps you learn:

* How SQL injection works internally
* Why **parameterized queries** stop SQLi
* How time-based attacks bypass error filtering
* How attackers infer data without visible output
* How defenders can **detect & mitigate** attacks

---

## 📦 Requirements

* Python **3.8+**
* Packages:

```bash
pip3 install requests beautifulsoup4 matplotlib
```

---

## 📁 Project Structure

```
specter_sqli.py
endpoints.txt        # optional
cookies.json         # optional
specter_results.json # auto-generated
specter_report.html  # auto-generated
```

---

## 🧪 Basic Usage

### Show help

```bash
python3 specter_sqli.py --help
```

### Scan a single endpoint

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15:5000/login.php
```

### Scan many endpoints concurrently

```bash
python3 specter_sqli.py \
  --targets-file endpoints.txt \
  --concurrency \
  --workers 8
```

---

## 🕷️ Automatic Endpoint Discovery (Crawler)

SpecterSqli can crawl a site and discover GET/POST endpoints automatically.

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15:5000 \
  --crawl \
  --crawl-depth 2
```

✔ Extracts links
✔ Extracts form actions
✔ Same-host only (safe for labs)

---

## 🔎 Parameter Discovery

The scanner:

* Parses HTML forms (`input`, `textarea`, `select`)
* Extracts URL query parameters
* Adds common parameter names automatically

This allows scanning even when parameters are unknown.

---

## ⚡ Boolean SQL Injection Detection

Tests payloads like:

```sql
' OR 1=1 -- -
```

Detection is based on:

* Response length changes
* Success keywords
* SQL error patterns

---

## ⏱️ Time-Based Blind SQL Injection

SpecterSqli detects blind SQLi by measuring response delays using:

* `SLEEP()` (MySQL)
* `pg_sleep()` (PostgreSQL)
* `WAITFOR DELAY` (MSSQL)

Example:

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15/login.php \
  --sleep 4
```

---

## 🔐 Blind Data Extraction (LAB ONLY)

Extracts data character-by-character using timing inference.

Example (extract database name):

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15/login.php \
  --blind-extract "SELECT database()" \
  --blind-param username \
  --maxlen 20
```

✅ Slow
✅ No visible output needed
✅ Educational & powerful

---

## 🔄 JSON API Support

For REST or SPA backends:

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15/api/login \
  --json
```

Payloads are sent as JSON:

```json
{
  "username": "payload",
  "password": "x"
}
```

---

## 🍪 Cookie-Based Sessions

For authenticated testing.

### Example cookies.json

```json
{
  "PHPSESSID": "abcdef123456",
  "sessionid": "xyz987654"
}
```

### Use it

```bash
python3 specter_sqli.py \
  --target http://10.0.2.15/dashboard.php \
  --cookies cookies.json
```

---

## 📊 HTML Report

Automatically generated report:

* Boolean findings
* Time-based results
* Timing charts
* Blind extraction output
* Defensive security guidance

```bash
specter_report.html
```

---

## 🆚 Vulnerable vs Secure Comparison

Compare two backends easily:

```bash
python3 specter_sqli.py \
  --target http://vulnerable.lab/login.php \
  --compare http://secure.lab/login.php
```

---

## 🛡️ Defensive Knowledge (Built-In)

SpecterSqli highlights **why attacks work** and how to stop them:

* Prepared statements
* No error disclosure
* WAF rules
* Rate limiting
* Input validation

This makes it useful for **defensive security training**.

---

## ⚠️ Legal & Ethical Notice

This tool is for:

* ✅ CTFs
* ✅ Labs (DVWA, Juice Shop, VulnHub, TryHackMe)
* ✅ Systems you own

🚫 Unauthorized scanning is illegal
🚫 Blind extraction against real systems is harmful

You are responsible for how you use this tool.

---

## ⭐ Final Notes

SpecterSqli was created as:

* A **learning framework**
* A **research helper**
* A **training companion**

It is intentionally readable, modifiable, and extensible.

