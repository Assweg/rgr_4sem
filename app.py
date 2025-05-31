# app.py — ИМИТАЦИЯ защиты (всё разрешено, только логирование)

import socketserver
import http.server
import os
import random
import time
import re
import json
import hashlib
import secrets
from collections import defaultdict
from urllib.parse import unquote

PORT = 8000
HOST = '0.0.0.0'
LOG_FILE = 'security.log'
USERS_FILE = 'users.json'

# Регулярки для имитации атак
SQL_REGEX = re.compile(r'(\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\balter\b|--|\/\*|\bwaitfor\b|\bdatabase\b)', re.IGNORECASE)
XSS_REGEX = re.compile(r'<script|javascript:|onerror\s*=|onload\s*=|<\/?\w+.*?>', re.IGNORECASE)
PATH_REGEX = re.compile(r'(\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c|\\|%5c)', re.IGNORECASE)

def generate_node_data():
    return [{
        "id": i,
        "voltage": round(random.uniform(210, 240), 1),
        "current": round(random.uniform(5, 30), 1),
        "load": round(random.uniform(20, 80), 1),
        "status": random.choice(["OK", "Предупреждение", "Ошибка"])
    } for i in range(1, 6)]

def hash_password(password):
    salt = secrets.token_hex(8)
    return f"{salt}${hashlib.sha256((salt + password).encode()).hexdigest()}"

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def _set_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def log_attack(self, ip, method, path, reason):
        attack_types = {
            "SQL-инъекция": "SQLi",
            "XSS-атака": "XSS",
            "DDoS-атака": "DDoS",
            "Path Traversal": "Path",
            "Повторная атака от заблокированного IP": "Blocked"
        }

        log_entry = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "ip": ip,
            "method": method,
            "path": path,
            "reason": reason,
            "type": attack_types.get(reason, "Unknown")
        }

        try:
            log_dir = os.path.dirname(os.path.abspath(LOG_FILE))
            if not os.path.exists(log_dir) and log_dir:
                os.makedirs(log_dir)
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
                f.flush()
                os.fsync(f.fileno())
            print(f"⚠️ АТАКА: {reason} от {ip} → {path}")
        except Exception as e:
            print(f"❌ ЛОГ ошибка: {str(e)}")

    def do_GET(self):
        client_ip = self.client_address[0]
        decoded_path = unquote(self.path)

        if SQL_REGEX.search(decoded_path):
            self.log_attack(client_ip, "GET", self.path, "SQL-инъекция")
        elif PATH_REGEX.search(decoded_path):
            self.log_attack(client_ip, "GET", self.path, "Path Traversal")
        elif self.rate_limit(client_ip):
            self.log_attack(client_ip, "GET", self.path, "DDoS-атака")

        if self.path == '/api/nodes':
            self.send_response(200)
            self._set_headers()
            self.end_headers()
            self.wfile.write(json.dumps(generate_node_data()).encode())
            return

        if self.path == '/api/unblock':
            self.send_response(200)
            self._set_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"status": "unblocked"}).encode())
            return

        if self.path == '/api/blocked':
            self.send_response(200)
            self._set_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"count": 0, "ips": []}).encode())
            return

        if self.path == '/api/logs':
            self.send_response(200)
            self._set_headers()
            self.end_headers()
            try:
                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, 'r', encoding='utf-8') as f:
                        logs = [json.loads(line.strip()) for line in f if line.strip()]
                        self.wfile.write(json.dumps(logs, ensure_ascii=False).encode())
                else:
                    self.wfile.write(b'[]')
            except Exception as e:
                print(f"❌ Ошибка логов: {str(e)}")
                self.wfile.write(b'[]')
            return

        if self.path == '/login.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            with open('login.html', 'rb') as f:
                self.wfile.write(f.read())
            return

        return super().do_GET()

    def do_POST(self):
        client_ip = self.client_address[0]
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len).decode('utf-8', errors='ignore')

        if XSS_REGEX.search(post_body):
            self.log_attack(client_ip, "POST", self.path, "XSS-атака")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def rate_limit(self, ip):
        return random.random() < 0.02  # имитация "перегрузки"

if __name__ == "__main__":
    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            pass
        print(f"📝 Лог файл создан: {os.path.abspath(LOG_FILE)}")
    except Exception as e:
        print(f"❌ Ошибка создания лога: {e}")

    if not os.path.exists(USERS_FILE):
        users = [{"username": "admin", "password_hash": hash_password("admin")}]
        save_users(users)
        print(f"👤 Пользователь admin создан (логин: admin / пароль: admin)")

    with socketserver.TCPServer((HOST, PORT), MyHandler) as httpd:
        print(f"🚀 Сервер запущен: http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Сервер остановлен")
