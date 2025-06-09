FROM python:3.9-slim

WORKDIR /attack
COPY pathtrav/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pathtrav/. .
COPY common/event_sender.py /attack/event_sender.py

CMD ["python", "pathtrav_attack.py"]