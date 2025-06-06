from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime
import hashlib
import secrets
from functools import wraps
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Настройка подключения к PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://user:password@db:5432/security_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Добавляем middleware для установки заголовков безопасности
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com"
    return response

# Модель пользователя
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Модель события безопасности
class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # SQLi, XSS, DDoS, Path
    ip = db.Column(db.String(45), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    blocked = db.Column(db.Boolean, default=False)

# Модель лога
class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    action = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def root():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/monitoring')
@login_required
def monitoring():
    return render_template('monitoring.html')

@app.route('/security')
@login_required
def security():
    return render_template('security.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            return render_template('login.html', error='Введите логин и пароль')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            
            # Логируем успешный вход
            log = Log(
                user_id=user.id,
                action='login',
                ip_address=request.remote_addr
            )
            db.session.add(log)
            db.session.commit()
            
            return redirect(url_for('index'))
            
        return render_template('login.html', error='Неверные учетные данные')
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user_id = session['user_id']
        # Логируем выход
        log = Log(
            user_id=user_id,
            action='logout',
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()
        
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/api/logs')
@login_required
def get_logs():
    logs = SecurityEvent.query.order_by(SecurityEvent.timestamp.desc()).all()
    return jsonify([{
        'id': log.id,
        'type': escape(log.type),
        'ip': escape(log.ip),
        'details': escape(log.details) if log.details else '',
        'timestamp': log.timestamp.isoformat(),
        'blocked': log.blocked
    } for log in logs])

@app.route('/api/blocked')
@login_required
def get_blocked():
    blocked = SecurityEvent.query.filter_by(blocked=True).all()
    return jsonify([{
        'id': event.id,
        'ip': escape(event.ip),
        'type': escape(event.type)
    } for event in blocked])

@app.route('/api/unblock', methods=['POST'])
@login_required
def unblock_all():
    SecurityEvent.query.update({SecurityEvent.blocked: False})
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/api/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    try:
        # Удаляем все записи из таблицы security_events
        SecurityEvent.query.delete()
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/event', methods=['POST'])
def log_security_event():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Санитизация входных данных
    event_type = escape(data.get('type', ''))
    ip = escape(data.get('ip', ''))
    details = escape(data.get('details', '')) if data.get('details') else ''
    
    event = SecurityEvent(
        type=event_type,
        ip=ip,
        details=details,
        blocked=False
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({'status': 'success'})

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

def init_db():
    with app.app_context():
        db.create_all()
        
        # Создаем тестовых пользователей
        test_users = [
            {'username': 'admin', 'password': 'admin123'},
            {'username': 'operator', 'password': 'oper123'},
            {'username': 'user1', 'password': 'user123'},
            {'username': 'tech', 'password': 'tech123'},
            {'username': 'monitor', 'password': 'mon123'}
        ]
        
        for user_data in test_users:
            user = User.query.filter_by(username=user_data['username']).first()
            if not user:
                user = User(
                    username=user_data['username'],
                    password_hash=generate_password_hash(user_data['password'])
                )
                db.session.add(user)
        
        db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
