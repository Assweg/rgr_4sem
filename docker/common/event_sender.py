import requests
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def send_security_event(event_type, ip, details):
    """
    Отправляет событие безопасности в основное приложение
    """
    try:
        data = {
            "type": event_type,
            "ip": ip,
            "details": details
        }
        
        target_host = os.getenv('TARGET_HOST', 'target_proxy')
        target_port = os.getenv('TARGET_PORT', '8081')
        
        response = requests.post(
            f"http://{target_host}:{target_port}/api/event",
            json=data
        )
        
        if response.status_code == 200:
            logger.info(f"Security event sent successfully: {event_type}")
        else:
            logger.warning(f"Failed to send security event: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error sending security event: {e}") 