FROM python:3.9-slim

WORKDIR /attack
COPY ddos/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ddos/. .
COPY common/event_sender.py /attack/event_sender.py

CMD ["python", "ddos_attack.py"]