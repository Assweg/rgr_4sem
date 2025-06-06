FROM python:3.9-slim

WORKDIR /app

# Копируем сначала только requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все остальные файлы
COPY . .

EXPOSE 5000

CMD ["python", "app.py"] 