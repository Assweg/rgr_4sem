FROM python:3.9-slim

WORKDIR /attack
COPY sqli/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sqli/. .
COPY common/event_sender.py /attack/event_sender.py

CMD ["python", "sqli_attack.py"]