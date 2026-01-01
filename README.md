# 👻 SpecterSqli

**SpecterSqli** is a **lab-focused SQL Injection analysis tool** designed for **academic projects, security labs, and controlled testing environments**.
It demonstrates **how SQL injection vulnerabilities are detected, analyzed, reported, and explained** using Python.

> ⚠️ **Legal Notice**
> This tool is intended **only for systems you own or have explicit permission to test**
> (CTFs, labs, training environments).
> **Unauthorized use is illegal.**

---

## ✍️ Author

**RH Shourav**
Security Learner | Python | Web Application Security
GitHub: [https://github.com/rhshourav](https://github.com/rhshourav)

---

## 🚀 Key Features

* Automatic **HTML form parameter discovery**
* Supports **GET and POST** endpoints
* Boolean-based SQL injection detection
* Time-based blind SQL injection detection
* Blind **character-by-character data extraction** (lab use only)
* Optional **authenticated scanning** (login form support)
* Concurrent scanning of multiple targets
* **Multi-format reporting**:

  * HTML (default)
  * JSON
  * Markdown
  * Plain Text
* Detailed findings:

  * Payload used
  * Evidence
  * Severity
  * Impact
  * Exploitation explanation (educational)
  * Remediation guidance

---

## 🧠 Educational Purpose

SpecterSqli is built to help students understand:

* How SQL injection vulnerabilities arise
* Why boolean and time-based SQLi work
* How attackers infer data without error messages
* How proper defenses stop SQL injection
* How professional security reports are structured

It focuses on **clarity and explanation**, not aggressive exploitation.

---

## 📦 Requirements

* Python **3.8+**
* Dependencies:

```bash
pip install requests beautifulsoup4
```

---

## 📁 Project Structure

```
specter_sqli.py
targets.txt          # optional
specter_report.html  # generated (default)
specter_report.json  # optional
specter_report.md    # optional
specter_report.txt   # optional
```

---

## 🧪 Basic Usage

### Show help

```bash
python specter_sqli.py --help
```

---

### Scan a single target (HTML report)

```bash
python specter_sqli.py \
  --target http://localhost/login.php
```

---

### Scan multiple targets concurrently

```bash
python specter_sqli.py \
  --targets-file targets.txt \
  --concurrency \
  --workers 6
```

---

## 🔎 Parameter Discovery

SpecterSqli automatically extracts parameters from:

* HTML forms (`input`, `textarea`, `select`)
* Falls back to common parameters if none are found

This allows scanning even when parameter names are unknown.

---

## ⚡ Boolean-Based SQL Injection Detection

Uses logical payloads such as:

```sql
' OR 1=1 -- -
```

Detection is based on:

* Response length comparison
* Behavioral differences
* Reproducible response patterns

---

## ⏱️ Time-Based Blind SQL Injection

Detects blind SQL injection by measuring response delay.

Example:

```bash
python specter_sqli.py \
  --target http://localhost/login.php \
  --sleep 3
```

If response time increases consistently, the parameter is flagged.

---

## 🔐 Blind Data Extraction (LAB ONLY)

Extracts data one character at a time using timing inference.

Example (extract database name):

```bash
python specter_sqli.py \
  --target http://localhost/login.php \
  --blind "SELECT database()" \
  --blind-param username \
  --maxlen 20
```

⚠️ This is **slow by design** and intended **only for learning environments**.

---

## 🔑 Authenticated Scanning (Login Forms)

SpecterSqli can scan protected pages after login.

```bash
python specter_sqli.py \
  --target http://localhost/dashboard.php \
  --login-url http://localhost/login.php \
  --login-user admin \
  --login-pass password123 \
  --login-user-field username \
  --login-pass-field password
```

---

## 📊 Multi-Format Output (NEW)

Choose report format using `--output-format`:

| Format   | Flag             |
| -------- | ---------------- |
| HTML     | `html` (default) |
| JSON     | `json`           |
| Markdown | `md`             |
| Text     | `txt`            |

### Examples

```bash
python specter_sqli.py --target http://localhost/login.php --output-format json
python specter_sqli.py --target http://localhost/login.php --output-format md
python specter_sqli.py --target http://localhost/login.php --output-format txt
```

---

## 🛡️ Defensive Guidance Included

Each finding explains:

* Why the vulnerability exists
* How it can be abused (educational)
* Real-world impact
* How to fix it:

  * Prepared statements
  * Parameterized queries
  * Input validation
  * Least-privilege database access

This makes the report suitable for **defensive security learning**.

---

## ⚠️ Ethical Use Policy

Allowed use:

✅ College projects
✅ Security labs (DVWA, Juice Shop, VulnHub)
✅ CTFs
✅ Systems you own

Not allowed:

🚫 Unauthorized scanning
🚫 Real-world blind extraction
🚫 Data theft or disruption

You are responsible for how you use this tool.

---

## ⭐ Final Notes

SpecterSqli is intentionally:

* Readable
* Modular
* Easy to extend
* Suitable for academic evaluation

It prioritizes **learning, explanation, and responsible security testing**.

