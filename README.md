# rgr_4sem — РГР: защищённое веб-приложение мониторинга

Расчётно-графическая работа, 4 семестр. Flask-приложение мониторинга с акцентом на безопасность: SQLi/XSS/DDoS-защита, security headers, логирование.

## Что внутри
- `app.py` — Flask, SQLAlchemy, Flask-Login, модели `User`, `SecurityEvent`, `Log`
- `index.html`, `login.html`, `monitoring.html`, `security.html`, `style.css`, `templates/`
- `init.sql`, `users.json`, `requirements.txt`
- `Dockerfile`, `docker-compose.yml`, `docker-compose.attack.yml`, `nginx.conf`, `docker/`
- `hash.py`, `backup.py`, `backups/`, `security.log`

## Стек
Python, Flask, PostgreSQL, SQLAlchemy, Nginx, Docker

## Запуск
```bash
docker-compose up --build
pip install -r requirements.txt
python app.py
```

## Что изучено
Security headers (CSP, X-Frame-Options), хеширование паролей, защита от инъекций, аудит событий безопасности.

---
**Автор:** Assweg · Telegram: [@assweg](https://t.me/assweg) · Учебное портфолио, все работы — студенческие.
