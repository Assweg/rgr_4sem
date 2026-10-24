# Мониторинг и журнал событий безопасности

![Стек](https://img.shields.io/badge/Python%20%C2%B7%20Flask%20%C2%B7%20PostgreSQL-334155?style=flat-square) ![Семестр](https://img.shields.io/badge/семестр-4-0f766e?style=flat-square) ![Статус](https://img.shields.io/badge/статус-%D0%A3%D1%87%D0%B5%D0%B1%D0%BD%D1%8B%D0%B9%20%D0%BF%D1%80%D0%BE%D0%B5%D0%BA%D1%82-64748b?style=flat-square)

Расчётно-графическая работа: Flask-приложение с авторизацией, страницей мониторинга и журналом событий. В материалах есть отдельные сценарии для исследования поведения приложения при атаках.

## Состав

| Файл или каталог | Назначение |
|---|---|
| [app.py](app.py) | Приложение и API работы с журналом событий |
| [templates](templates/) | Страницы входа, мониторинга и безопасности |
| [init.sql](init.sql) | Инициализация PostgreSQL |
| [backup.py](backup.py) | Сценарий резервного копирования |
| [docker-compose.yml](docker-compose.yml) | Приложение, PostgreSQL, pgAdmin и Nginx |
| [docker-compose.attack.yml](docker-compose.attack.yml) | Дополнительные экспериментальные сервисы |

## Запуск учебного стенда

```bash
git clone https://github.com/Assweg/rgr_4sem.git
cd rgr_4sem
docker compose up --build -d
```

| Сервис | Адрес |
|---|---|
| Flask | http://localhost:5001 |
| Nginx | http://localhost:8081 |
| pgAdmin | http://localhost:8080 |
| PostgreSQL | `localhost:5433` |

Остановка: `docker compose down`.

## Конфигурация

Параметр `DATABASE_URL` задаёт подключение приложения к БД. В Compose находятся демонстрационные реквизиты. Локальные журналы и реальные учётные данные не нужны для чтения исходников.

## Границы работы

Наличие механизмов авторизации и учебных сценариев атак не подтверждает защиту от всех перечисленных угроз. Проверка уязвимостей и запуск атак при оформлении репозитория не выполнялись.

## Материалы

[Отчёт и локальные варианты РГР](https://github.com/Assweg/nstu/tree/main/5sem/%D0%A2%D0%B8%D0%9C%D0%9F).

---

[Все учебные работы](https://github.com/Assweg/nstu) · [Профиль Assweg](https://github.com/Assweg)
