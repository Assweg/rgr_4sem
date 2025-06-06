-- Создание пользователя и базы данных
CREATE USER "user" WITH PASSWORD 'password';
CREATE DATABASE security_db;
GRANT ALL PRIVILEGES ON DATABASE security_db TO "user";

-- Подключение к базе данных
\c security_db;

-- Создание таблиц если они не существуют
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash VARCHAR(200) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(200) NOT NULL,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Предоставление прав на таблицы
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "user";
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "user";

-- Создание тестовых пользователей
INSERT INTO users (username, password_hash) VALUES
    ('admin', 'pbkdf2:sha256:600000$X7GQPHNPqGHqDGe3$c22a70c9c26c7b4fd4a71eeae32c1c5f9a7d8509f0ad3bb45f2c6250e32a0e9d'), -- пароль: admin123
    ('operator', 'pbkdf2:sha256:600000$1XYZ2WNMkLJqRST4$d33b4f7c8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5'), -- пароль: oper123
    ('user1', 'pbkdf2:sha256:600000$7UVW8XYZkLMnPQR5$a11b22c33d44e55f66g77h88i99j00k11l22m33n44o55p66q77r88s99t00u11'), -- пароль: user123
    ('tech', 'pbkdf2:sha256:600000$4RST5UVWkLMnPQR6$b22c33d44e55f66g77h88i99j00k11l22m33n44o55p66q77r88s99t00u11v22'), -- пароль: tech123
    ('monitor', 'pbkdf2:sha256:600000$9WXY0ZABkLMnPQR7$c33d44e55f66g77h88i99j00k11l22m33n44o55p66q77r88s99t00u11v22w33'); -- пароль: mon123 