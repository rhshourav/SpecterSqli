# 👻 SpecterMini

**SpecterMini** is a **fast, lightweight SQL Injection lab scanner** for educational purposes and CTF-style labs.

> ⚠️ **Legal Notice:** Only use on systems you own or have explicit permission for.

---

## ✍️ Author

**rhshourav**
GitHub: [https://github.com/rhshourav](https://github.com/rhshourav)
Security Learner | Offensive & Defensive Training

---

## 🚀 Features

* Simple **Boolean SQLi testing**
* Basic **Time-based blind SQLi**
* Works on **GET/POST requests**
* Specify **IP, port, path, and parameter**
* CLI `--help` for fast guidance
* **Lab-friendly**, lightweight, and fast

---

## 🧪 Requirements

* Python 3.x
* `requests` library

Install dependencies:

```bash
pip3 install requests
```

---

## 📦 Usage

### Quick Scan

```bash
python3 specter_mini.py --ip 127.0.0.1 --port 5000 --path /login.php --param username
```

### GET Request Test

```bash
python3 specter_mini.py --ip 127.0.0.1 --path /search.php --method GET --param q
```

### Time-based SQLi Delay

```bash
python3 specter_mini.py --ip 10.10.10.10 --port 8080 --sleep 5
```

### Show Help

```bash
python3 specter_mini.py --help
```

---

## 🧠 How It Works

### Boolean SQLi

Tests if a condition like `OR 1=1` changes the page response.

```sql
' OR 1=1 --
```

### Time-based Blind SQLi

Measures response delays when using `SLEEP()` or similar functions.

```sql
' OR IF(1=1,SLEEP(3),0) --
```

If the response is delayed ≈ sleep time → likely vulnerable.

---

## ⚡ When to Use

* Educational labs ✅
* CTF challenges ✅
* Quick demonstration of SQLi ✅

Use **SpecterSqli (full version)** if you need:

* Automated crawling
* Parameter enumeration
* Blind extraction
* HTML reports

---

## 🛡️ Disclaimer

This tool is **for educational purposes only**.
Unauthorized scanning of websites is illegal.
You are responsible for how you use it.
