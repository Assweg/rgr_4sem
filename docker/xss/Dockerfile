FROM python:3.9-slim

WORKDIR /attack
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY ../common/event_sender.py /attack/event_sender.py

CMD ["python", "xss_attack.py"]