import os
import sqlite3
import json
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
import pandas as pd
from io import BytesIO

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'sqlite:///schooldata.db')
app.config['CREDENTIALS_DB'] = os.environ.get('CREDENTIALS_DB', 'credentials.db')

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")


# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database initialization
def init_databases():
    """Initialize both databases with required tables"""
    
    # Credentials Database
    conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
    cursor_cred = conn_cred.cursor()
    
    cursor_cred.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            last_password_change TEXT,
            first_login INTEGER DEFAULT 1,
            created_at TEXT
        )
    ''')
    
    # Check if super admin exists
    cursor_cred.execute('SELECT user_id FROM credentials WHERE username = ?', ('superadmin',))
    if not cursor_cred.fetchone():
        hashed_password = generate_password_hash('superadmin123')
        cursor_cred.execute('''
            INSERT INTO credentials (user_id, username, password, role, last_password_change, first_login, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', ('SA001', 'superadmin', hashed_password, 'superadmin', datetime.now().isoformat(), 1, datetime.now().isoformat()))
    
    conn_cred.commit()
    conn_cred.close()
    
    # School Data Database
    conn_data = sqlite3.connect('schooldata.db')
    cursor_data = conn_data.cursor()
    
    # Users table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            class TEXT,
            subjects TEXT,
            classes TEXT,
            email TEXT,
            phone TEXT
        )
    ''')
    
    # Check if super admin exists in users
    cursor_data.execute('SELECT user_id FROM users WHERE user_id = ?', ('SA001',))
    if not cursor_data.fetchone():
        cursor_data.execute('''
            INSERT INTO users (user_id, name, role, class, subjects, classes, email, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('SA001', 'Super Admin', 'superadmin', '', '', '', '', ''))
    
    # Homework table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS homework (
            id TEXT PRIMARY KEY,
            subject TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            date_given TEXT NOT NULL,
            due_date TEXT NOT NULL,
            created_by TEXT NOT NULL,
            class TEXT NOT NULL
        )
    ''')
    
    # Grades table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            test_type TEXT NOT NULL,
            score REAL NOT NULL,
            max_score REAL DEFAULT 100,
            date TEXT
        )
    ''')
    
    # Schedule table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class TEXT NOT NULL,
            day TEXT NOT NULL,
            period INTEGER NOT NULL,
            subject TEXT NOT NULL,
            teacher_id TEXT,
            UNIQUE(class, day, period)
        )
    ''')
    
    # Task lists table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS task_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            color TEXT NOT NULL,
            created_at TEXT
        )
    ''')
    
    # Tasks table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            text TEXT NOT NULL,
            notes TEXT,
            completed INTEGER DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY (list_id) REFERENCES task_lists(id) ON DELETE CASCADE
        )
    ''')
    
    # Messages table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id TEXT NOT NULL,
            room_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            read INTEGER DEFAULT 0
        )
    ''')
    
    # Chat rooms table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS chat_rooms (
            room_id TEXT PRIMARY KEY,
            room_name TEXT NOT NULL,
            room_type TEXT NOT NULL,
            members TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_message TEXT
        )
    ''')
    
    # Subjects table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            code TEXT,
            created_at TEXT
        )
    ''')
    
    # Classes table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            section TEXT,
            created_at TEXT
        )
    ''')
    
    # Teacher subjects table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS teacher_subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id TEXT NOT NULL,
            subject TEXT NOT NULL,
            assigned_at TEXT
        )
    ''')
    
    # Upload logs table
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS upload_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uploaded_by TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            records_imported INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL
        )
    ''')
    
    # Audit logs table (production feature)
    cursor_data.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL
        )
    ''')
    
    conn_data.commit()
    conn_data.close()

# Initialize databases on startup
init_databases()

# Database helper functions
def get_db_connection(db_name='schooldata.db'):
    """Get database connection"""
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(user_id, action, details=None):
    """Log admin actions for audit trail"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (user_id, action, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, action, details, request.remote_addr, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                return jsonify({'error': 'Unauthorized access'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes - Authentication
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'student')
        
        # Query credentials database
        conn = sqlite3.connect(app.config['CREDENTIALS_DB'])
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM credentials WHERE username = ?', (username,))
        user_cred = cursor.fetchone()
        conn.close()
        
        if not user_cred:
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not check_password_hash(user_cred['password'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Check role match
        if role == 'admin' and user_cred['role'] not in ['admin', 'superadmin']:
            return jsonify({'error': 'Invalid credentials for admin portal'}), 401
        elif role == 'student' and user_cred['role'] in ['admin', 'superadmin']:
            return jsonify({'error': 'Please use admin portal'}), 401
        
        # Get user profile from school data
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_cred['user_id'],))
        user_profile = cursor.fetchone()
        conn.close()
        
        if not user_profile:
            return jsonify({'error': 'User profile not found'}), 404
        
        # Set session
        session['user_id'] = user_cred['user_id']
        session['username'] = user_cred['username']
        session['name'] = user_profile['name']
        session['role'] = user_cred['role']
        session['class'] = user_profile['class'] or ''
        session['first_login'] = user_cred['first_login']
        
        log_audit(user_cred['user_id'], 'LOGIN', f"Logged in from {request.remote_addr}")
        
        return jsonify({
            'success': True,
            'redirect': url_for('dashboard')
        })
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        log_audit(user_id, 'LOGOUT', 'User logged out')
    session.clear()
    return redirect(url_for('login'))

# Routes - Dashboard
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return redirect(url_for('account'))

@app.route('/dashboard/account')
@login_required
def account():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('account.html', user=user)

@app.route('/dashboard/schedule')
@login_required
def schedule():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('schedule.html', user=user)

@app.route('/dashboard/calendar')
@login_required
def calendar():
    if session['role'] != 'student':
        return redirect(url_for('schedule'))
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('calendar.html', user=user)

@app.route('/dashboard/homework')
@login_required
def homework():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('homework.html', user=user)

@app.route('/dashboard/grades')
@login_required
def grades():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('grades.html', user=user)

@app.route('/dashboard/tasks')
@login_required
def tasks():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('tasks.html', user=user)

@app.route('/dashboard/chat')
@login_required
def chat():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('chat.html', user=user)

@app.route('/dashboard/accounts')
@login_required
@role_required(['admin', 'superadmin'])
def accounts_mgmt():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('accounts_mgmt.html', user=user)

@app.route('/dashboard/import')
@login_required
@role_required(['admin', 'superadmin'])
def data_import():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('data_import.html', user=user)

@app.route('/dashboard/timetable')
@login_required
@role_required(['admin', 'superadmin'])
def timetable_editor():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('timetable_editor.html', user=user)

@app.route('/dashboard/monitor-chats')
@login_required
@role_required(['superadmin'])
def monitor_chats():
    user = {
        'user_id': session['user_id'],
        'name': session['name'],
        'username': session['username'],
        'role': session['role'],
        'class': session.get('class', ''),
        'first_login': session.get('first_login', 0)
    }
    return render_template('monitor_chats.html', user=user)

# API Routes - Account Management
@app.route('/api/account', methods=['GET'])
@login_required
def get_account():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE user_id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
    conn_cred.row_factory = sqlite3.Row
    cursor_cred = conn_cred.cursor()
    cursor_cred.execute('SELECT username, first_login FROM credentials WHERE user_id = ?', (session['user_id'],))
    cred = cursor_cred.fetchone()
    conn_cred.close()
    
    return jsonify({
        'user_id': user['user_id'],
        'name': user['name'],
        'username': cred['username'],
        'role': user['role'],
        'class': user['class'] or '',
        'subjects': user['subjects'] or '',
        'first_login': cred['first_login']
    })

@app.route('/api/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    # Verify current password
    conn = sqlite3.connect(app.config['CREDENTIALS_DB'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM credentials WHERE user_id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Update password
    hashed_password = generate_password_hash(new_password)
    cursor.execute('''
        UPDATE credentials 
        SET password = ?, last_password_change = ?, first_login = 0
        WHERE user_id = ?
    ''', (hashed_password, datetime.now().isoformat(), session['user_id']))
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'PASSWORD_CHANGE', 'User changed their password')
    
    return jsonify({'success': True})

@app.route('/api/admin/reset-password', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
def reset_password():
    data = request.json
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    conn = sqlite3.connect(app.config['CREDENTIALS_DB'])
    cursor = conn.cursor()
    hashed_password = generate_password_hash(new_password)
    cursor.execute('''
        UPDATE credentials 
        SET password = ?, last_password_change = ?, first_login = 1
        WHERE user_id = ?
    ''', (hashed_password, datetime.now().isoformat(), user_id))
    conn.commit()
    conn.close()
    
    log_audit(session['user_id'], 'PASSWORD_RESET', f'Reset password for user {user_id}')
    
    return jsonify({'success': True})

# API Routes - Tasks
@app.route('/api/task-lists', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def task_lists():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT tl.*, 
                   COUNT(t.id) as total_tasks,
                   SUM(CASE WHEN t.completed = 1 THEN 1 ELSE 0 END) as completed_tasks
            FROM task_lists tl
            LEFT JOIN tasks t ON tl.id = t.list_id
            WHERE tl.user_id = ?
            GROUP BY tl.id
            ORDER BY tl.created_at
        ''', (session['user_id'],))
        lists = [dict(row) for row in cursor.fetchall()]
        
        # Get tasks for each list
        for lst in lists:
            cursor.execute('''
                SELECT * FROM tasks 
                WHERE list_id = ? 
                ORDER BY completed, created_at
            ''', (lst['id'],))
            lst['tasks'] = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return jsonify(lists)
    
    elif request.method == 'POST':
        data = request.json
        cursor.execute('''
            INSERT INTO task_lists (user_id, name, color, created_at)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], data['name'], data['color'], datetime.now().isoformat()))
        conn.commit()
        list_id = cursor.lastrowid
        conn.close()
        return jsonify({'id': list_id, 'success': True})
    
    elif request.method == 'PUT':
        data = request.json
        cursor.execute('''
            UPDATE task_lists 
            SET name = ?, color = ?
            WHERE id = ? AND user_id = ?
        ''', (data['name'], data['color'], data['id'], session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        list_id = request.args.get('id')
        cursor.execute('DELETE FROM tasks WHERE list_id = ?', (list_id,))
        cursor.execute('DELETE FROM task_lists WHERE id = ? AND user_id = ?', (list_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/tasks', methods=['GET', 'POST', 'PUT', 'DELETE'])
@login_required
def tasks_api():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC', (session['user_id'],))
        tasks = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(tasks)
    
    elif request.method == 'POST':
        data = request.json
        cursor.execute('''
            INSERT INTO tasks (list_id, user_id, text, notes, completed, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
        ''', (data['list_id'], session['user_id'], data['text'], data.get('notes', ''), datetime.now().isoformat()))
        conn.commit()
        task_id = cursor.lastrowid
        conn.close()
        return jsonify({'id': task_id, 'success': True})
    
    elif request.method == 'PUT':
        data = request.json
        if 'completed' in data:
            cursor.execute('''
                UPDATE tasks 
                SET completed = ?
                WHERE id = ? AND user_id = ?
            ''', (data['completed'], data['id'], session['user_id']))
        else:
            cursor.execute('''
                UPDATE tasks 
                SET text = ?, notes = ?
                WHERE id = ? AND user_id = ?
            ''', (data['text'], data.get('notes', ''), data['id'], session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        task_id = request.args.get('id')
        cursor.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

# API Routes - Schedule
@app.route('/api/schedule', methods=['GET'])
@login_required
def get_schedule():
    class_name = request.args.get('class', session.get('class', ''))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT day, period, subject 
        FROM schedule 
        WHERE class = ?
        ORDER BY day, period
    ''', (class_name,))
    rows = cursor.fetchall()
    conn.close()
    
    # Organize by day
    schedule = {}
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
    for day in days:
        schedule[day] = [''] * 8
    
    for row in rows:
        day_idx = days.index(row['day']) if row['day'] in days else -1
        if day_idx >= 0 and 0 <= row['period'] - 1 < 8:
            schedule[row['day']][row['period'] - 1] = row['subject']
    
    return jsonify(schedule)

@app.route('/api/admin/schedule', methods=['GET', 'PUT'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_schedule():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        class_name = request.args.get('class', '')
        cursor.execute('''
            SELECT day, period, subject 
            FROM schedule 
            WHERE class = ?
            ORDER BY day, period
        ''', (class_name,))
        rows = cursor.fetchall()
        conn.close()
        
        schedule = {}
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        for day in days:
            schedule[day] = [''] * 8
        
        for row in rows:
            if row['day'] in days and 0 <= row['period'] - 1 < 8:
                schedule[row['day']][row['period'] - 1] = row['subject']
        
        return jsonify(schedule)
    
    elif request.method == 'PUT':
        data = request.json
        class_name = data['class']
        schedule = data['schedule']
        
        # Delete existing schedule for this class
        cursor.execute('DELETE FROM schedule WHERE class = ?', (class_name,))
        
        # Insert new schedule
        days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        for day in days:
            if day in schedule:
                for period, subject in enumerate(schedule[day], 1):
                    if subject:
                        cursor.execute('''
                            INSERT INTO schedule (class, day, period, subject)
                            VALUES (?, ?, ?, ?)
                        ''', (class_name, day, period, subject))
        
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'SCHEDULE_UPDATE', f'Updated schedule for class {class_name}')
        
        return jsonify({'success': True})

@app.route('/api/admin/check-conflicts', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
def check_conflicts():
    data = request.json
    class_name = data['class']
    day = data['day']
    period = data['period']
    subject = data['subject']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get teacher for this subject
    cursor.execute('SELECT teacher_id FROM teacher_subjects WHERE subject = ?', (subject,))
    teacher = cursor.fetchone()
    
    if not teacher:
        conn.close()
        return jsonify({'conflict': False})
    
    teacher_id = teacher['teacher_id']
    
    # Check if teacher has another class at same time
    cursor.execute('''
        SELECT s.class, u.name as teacher_name
        FROM schedule s
        JOIN teacher_subjects ts ON s.subject = ts.subject
        JOIN users u ON ts.teacher_id = u.user_id
        WHERE ts.teacher_id = ? AND s.day = ? AND s.period = ? AND s.class != ?
    ''', (teacher_id, day, period, class_name))
    conflict = cursor.fetchone()
    
    if conflict:
        # Find alternative periods
        cursor.execute('''
            SELECT DISTINCT period 
            FROM schedule 
            WHERE class = ? AND day = ?
        ''', (class_name, day))
        occupied = [row['period'] for row in cursor.fetchall()]
        
        cursor.execute('''
            SELECT DISTINCT period 
            FROM schedule 
            WHERE day = ? AND subject IN (
                SELECT subject FROM teacher_subjects WHERE teacher_id = ?
            )
        ''', (day, teacher_id))
        teacher_occupied = [row['period'] for row in cursor.fetchall()]
        
        alternatives = []
        for p in range(1, 9):
            if p not in occupied and p not in teacher_occupied:
                alternatives.append(p)
        
        conn.close()
        return jsonify({
            'conflict': True,
            'details': [{
                'teacher': conflict['teacher_name'],
                'conflicting_class': conflict['class']
            }],
            'alternatives': alternatives[:3]
        })
    
    conn.close()
    return jsonify({'conflict': False})

# API Routes - Homework
@app.route('/api/homework', methods=['GET', 'POST', 'DELETE'])
@login_required
def homework_api():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        if session['role'] == 'student':
            cursor.execute('''
                SELECT * FROM homework 
                WHERE class = ?
                ORDER BY due_date
            ''', (session['class'],))
        else:
            cursor.execute('SELECT * FROM homework ORDER BY due_date')
        
        homework = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(homework)
    
    elif request.method == 'POST':
        data = request.json
        hw_id = f"HW{int(datetime.now().timestamp())}"
        cursor.execute('''
            INSERT INTO homework (id, subject, title, description, date_given, due_date, created_by, class)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (hw_id, data['subject'], data['title'], data.get('description', ''), 
              data['date_given'], data['due_date'], session['user_id'], data['class']))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'HOMEWORK_CREATE', f"Created homework: {data['title']}")
        
        return jsonify({'success': True, 'id': hw_id})
    
    elif request.method == 'DELETE':
        hw_id = request.args.get('id')
        cursor.execute('DELETE FROM homework WHERE id = ?', (hw_id,))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'HOMEWORK_DELETE', f"Deleted homework: {hw_id}")
        
        return jsonify({'success': True})

# API Routes - Grades
@app.route('/api/grades', methods=['GET', 'POST'])
@login_required
def grades_api():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        student_id = request.args.get('student_id', session['user_id'])
        
        cursor.execute('''
            SELECT subject, test_type, score 
            FROM grades 
            WHERE student_id = ?
        ''', (student_id,))
        rows = cursor.fetchall()
        conn.close()
        
        # Organize by test type
        grades = {}
        test_types = ['PT1', 'PT2', 'PT3', 'PF', 'F']
        for test_type in test_types:
            grades[test_type] = {}
        
        for row in rows:
            if row['test_type'] in grades:
                grades[row['test_type']][row['subject']] = row['score']
        
        return jsonify(grades)
    
    elif request.method == 'POST':
        data = request.json
        cursor.execute('''
            INSERT INTO grades (student_id, subject, test_type, score, max_score, date)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (data['student_id'], data['subject'], data['test_type'], 
              data['score'], data.get('max_score', 100), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'GRADE_ENTRY', f"Added grade for {data['student_id']}")
        
        return jsonify({'success': True})

# API Routes - Chat
@app.route('/api/chat/users', methods=['GET'])
@login_required
def chat_users():
    query = request.args.get('q', '')
    
    if len(query) < 2:
        return jsonify([])
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT user_id, name, role 
        FROM users 
        WHERE (name LIKE ? OR user_id LIKE ?) AND user_id != ?
        LIMIT 20
    ''', (f'%{query}%', f'%{query}%', session['user_id']))
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(users)

@app.route('/api/chat/rooms', methods=['GET', 'POST'])
@login_required
def chat_rooms():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT * FROM chat_rooms 
            WHERE members LIKE ?
            ORDER BY last_message DESC
        ''', (f'%{session["user_id"]}%',))
        rooms = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(rooms)
    
    elif request.method == 'POST':
        data = request.json
        room_type = data['room_type']
        members = data['members']
        room_name = data.get('room_name', '')
        
        # For direct chats, check if room exists
        if room_type == 'direct':
            sorted_members = ','.join(sorted([session['user_id']] + members))
            cursor.execute('''
                SELECT room_id FROM chat_rooms 
                WHERE room_type = 'direct' AND members = ?
            ''', (sorted_members,))
            existing = cursor.fetchone()
            
            if existing:
                conn.close()
                return jsonify({'room_id': existing['room_id']})
            
            # Create room name from members
            cursor.execute('SELECT name FROM users WHERE user_id = ?', (members[0],))
            other_user = cursor.fetchone()
            room_name = other_user['name']
            members_str = sorted_members
        else:
            members_str = ','.join([session['user_id']] + members)
        
        room_id = f"ROOM{int(datetime.now().timestamp())}"
        cursor.execute('''
            INSERT INTO chat_rooms (room_id, room_name, room_type, members, created_by, created_at, last_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (room_id, room_name, room_type, members_str, session['user_id'], 
              datetime.now().isoformat(), datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        return jsonify({'room_id': room_id})

@app.route('/api/chat/messages/<room_id>', methods=['GET', 'POST'])
@login_required
def chat_messages(room_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT m.*, u.name as sender_name 
            FROM messages m
            JOIN users u ON m.sender_id = u.user_id
            WHERE m.room_id = ?
            ORDER BY m.timestamp
        ''', (room_id,))
        messages = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(messages)
    
    elif request.method == 'POST':
        data = request.json
        cursor.execute('''
            INSERT INTO messages (sender_id, room_id, message, timestamp, read)
            VALUES (?, ?, ?, ?, 0)
        ''', (session['user_id'], room_id, data['message'], datetime.now().isoformat()))
        
        # Update last message time
        cursor.execute('''
            UPDATE chat_rooms 
            SET last_message = ?
            WHERE room_id = ?
        ''', (datetime.now().isoformat(), room_id))
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/superadmin/all-chats', methods=['GET'])
@login_required
@role_required(['superadmin'])
def superadmin_all_chats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT cr.*, COUNT(m.id) as message_count
        FROM chat_rooms cr
        LEFT JOIN messages m ON cr.room_id = m.room_id
        GROUP BY cr.room_id
        ORDER BY cr.last_message DESC
    ''')
    rooms = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(rooms)

@app.route('/api/superadmin/chat-messages/<room_id>', methods=['GET'])
@login_required
@role_required(['superadmin'])
def superadmin_chat_messages(room_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT m.*, u.name as sender_name 
        FROM messages m
        JOIN users u ON m.sender_id = u.user_id
        WHERE m.room_id = ?
        ORDER BY m.timestamp
    ''', (room_id,))
    messages = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(messages)

# API Routes - Admin
@app.route('/api/admin/accounts', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_accounts():
    if request.method == 'GET':
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users ORDER BY role, name')
        users = [dict(row) for row in cursor.fetchall()]
        
        # Get usernames
        conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
        conn_cred.row_factory = sqlite3.Row
        cursor_cred = conn_cred.cursor()
        
        for user in users:
            cursor_cred.execute('SELECT username FROM credentials WHERE user_id = ?', (user['user_id'],))
            cred = cursor_cred.fetchone()
            user['username'] = cred['username'] if cred else ''
        
        conn.close()
        conn_cred.close()
        return jsonify(users)
    
    elif request.method == 'POST':
        data = request.json
        
        # Generate user ID
        role = data['role']
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if role == 'student':
            cursor.execute("SELECT user_id FROM users WHERE role = 'student' ORDER BY user_id DESC LIMIT 1")
            last = cursor.fetchone()
            user_id = f"S{int(last['user_id'][1:]) + 1:03d}" if last else "S001"
        elif role == 'teacher':
            cursor.execute("SELECT user_id FROM users WHERE role = 'teacher' ORDER BY user_id DESC LIMIT 1")
            last = cursor.fetchone()
            user_id = f"T{int(last['user_id'][1:]) + 1:03d}" if last else "T001"
        else:
            cursor.execute("SELECT user_id FROM users WHERE role = 'admin' ORDER BY user_id DESC LIMIT 1")
            last = cursor.fetchone()
            user_id = f"A{int(last['user_id'][1:]) + 1:03d}" if last else "A001"
        
        # Insert into credentials
        conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
        cursor_cred = conn_cred.cursor()
        hashed_password = generate_password_hash(data['password'])
        
        try:
            cursor_cred.execute('''
                INSERT INTO credentials (user_id, username, password, role, last_password_change, first_login, created_at)
                VALUES (?, ?, ?, ?, ?, 1, ?)
            ''', (user_id, data['username'], hashed_password, role, datetime.now().isoformat(), datetime.now().isoformat()))
            conn_cred.commit()
        except sqlite3.IntegrityError:
            conn_cred.close()
            conn.close()
            return jsonify({'error': 'Username already exists'}), 400
        
        conn_cred.close()
        
        # Insert into users
        cursor.execute('''
            INSERT INTO users (user_id, name, role, class, subjects, classes, email, phone)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, data['name'], role, data.get('class', ''), 
              data.get('subjects', ''), '', '', ''))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'ACCOUNT_CREATE', f"Created account: {user_id}")
        
        return jsonify({'success': True, 'user_id': user_id})
    
    elif request.method == 'DELETE':
        user_id = request.args.get('id')
        
        # Delete from both databases
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
        cursor_cred = conn_cred.cursor()
        cursor_cred.execute('DELETE FROM credentials WHERE user_id = ?', (user_id,))
        conn_cred.commit()
        conn_cred.close()
        
        log_audit(session['user_id'], 'ACCOUNT_DELETE', f"Deleted account: {user_id}")
        
        return jsonify({'success': True})

@app.route('/api/admin/subjects', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_subjects():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM subjects ORDER BY name')
        subjects = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(subjects)
    
    elif request.method == 'POST':
        data = request.json
        try:
            cursor.execute('''
                INSERT INTO subjects (name, code, created_at)
                VALUES (?, ?, ?)
            ''', (data['name'], data.get('code', ''), datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Subject already exists'}), 400
    
    elif request.method == 'DELETE':
        name = request.args.get('name')
        cursor.execute('DELETE FROM subjects WHERE name = ?', (name,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/admin/classes-list', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_classes():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM classes ORDER BY name')
        classes = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(classes)
    
    elif request.method == 'POST':
        data = request.json
        try:
            cursor.execute('''
                INSERT INTO classes (name, section, created_at)
                VALUES (?, ?, ?)
            ''', (data['name'], data.get('section', ''), datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return jsonify({'success': True})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'error': 'Class already exists'}), 400
    
    elif request.method == 'DELETE':
        name = request.args.get('name')
        cursor.execute('DELETE FROM classes WHERE name = ?', (name,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/admin/teacher-subjects', methods=['GET', 'POST', 'DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_teacher_subjects():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT ts.*, u.name as teacher_name
            FROM teacher_subjects ts
            JOIN users u ON ts.teacher_id = u.user_id
            ORDER BY u.name, ts.subject
        ''')
        assignments = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify(assignments)
    
    elif request.method == 'POST':
        data = request.json
        cursor.execute('''
            INSERT INTO teacher_subjects (teacher_id, subject, assigned_at)
            VALUES (?, ?, ?)
        ''', (data['teacher_id'], data['subject'], datetime.now().isoformat()))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    
    elif request.method == 'DELETE':
        assignment_id = request.args.get('id')
        cursor.execute('DELETE FROM teacher_subjects WHERE id = ?', (assignment_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True})

@app.route('/api/admin/teachers-list', methods=['GET'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_teachers_list():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, name FROM users WHERE role = 'teacher' ORDER BY name")
    teachers = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(teachers)

@app.route('/api/admin/upload', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
def admin_upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    data_type = request.form.get('data_type', 'auto')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Process file
    try:
        filename = secure_filename(file.filename)
        file_ext = filename.rsplit('.', 1)[1].lower()
        
        if file_ext == 'csv':
            df = pd.read_csv(file)
        elif file_ext in ['xlsx', 'xls']:
            df = pd.read_excel(file)
        elif file_ext == 'json':
            df = pd.read_json(file)
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        # Normalize column names
        df.columns = df.columns.str.lower().str.strip().str.replace(' ', '_')
        
        # Auto-detect data type if needed
        if data_type == 'auto':
            if 'class' in df.columns and 'name' in df.columns:
                data_type = 'students'
            elif 'subjects' in df.columns:
                data_type = 'teachers'
            elif 'day' in df.columns and 'period' in df.columns:
                data_type = 'schedule'
            elif 'due_date' in df.columns:
                data_type = 'homework'
            elif 'test_type' in df.columns:
                data_type = 'grades'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        records_imported = 0
        errors = []
        
        if data_type == 'students':
            for idx, row in df.iterrows():
                try:
                    # Generate user ID
                    cursor.execute("SELECT user_id FROM users WHERE role = 'student' ORDER BY user_id DESC LIMIT 1")
                    last = cursor.fetchone()
                    user_id = f"S{int(last['user_id'][1:]) + 1:03d}" if last else "S001"
                    
                    name = row.get('name', '')
                    username = row.get('username', name.lower().replace(' ', ''))
                    password = row.get('password', 'student123')
                    class_name = row.get('class', '')
                    
                    # Insert credentials
                    conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
                    cursor_cred = conn_cred.cursor()
                    hashed_password = generate_password_hash(password)
                    cursor_cred.execute('''
                        INSERT INTO credentials (user_id, username, password, role, last_password_change, first_login, created_at)
                        VALUES (?, ?, ?, 'student', ?, 1, ?)
                    ''', (user_id, username, hashed_password, datetime.now().isoformat(), datetime.now().isoformat()))
                    conn_cred.commit()
                    conn_cred.close()
                    
                    # Insert user
                    cursor.execute('''
                        INSERT INTO users (user_id, name, role, class, subjects, classes, email, phone)
                        VALUES (?, ?, 'student', ?, '', '', ?, ?)
                    ''', (user_id, name, class_name, row.get('email', ''), row.get('phone', '')))
                    
                    records_imported += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        elif data_type == 'teachers':
            for idx, row in df.iterrows():
                try:
                    cursor.execute("SELECT user_id FROM users WHERE role = 'teacher' ORDER BY user_id DESC LIMIT 1")
                    last = cursor.fetchone()
                    user_id = f"T{int(last['user_id'][1:]) + 1:03d}" if last else "T001"
                    
                    name = row.get('name', '')
                    username = row.get('username', name.lower().replace(' ', ''))
                    password = row.get('password', 'teacher123')
                    subjects = row.get('subjects', '')
                    
                    conn_cred = sqlite3.connect(app.config['CREDENTIALS_DB'])
                    cursor_cred = conn_cred.cursor()
                    hashed_password = generate_password_hash(password)
                    cursor_cred.execute('''
                        INSERT INTO credentials (user_id, username, password, role, last_password_change, first_login, created_at)
                        VALUES (?, ?, ?, 'teacher', ?, 1, ?)
                    ''', (user_id, username, hashed_password, datetime.now().isoformat(), datetime.now().isoformat()))
                    conn_cred.commit()
                    conn_cred.close()
                    
                    cursor.execute('''
                        INSERT INTO users (user_id, name, role, class, subjects, classes, email, phone)
                        VALUES (?, ?, 'teacher', '', ?, ?, '', '')
                    ''', (user_id, name, subjects, row.get('classes', '')))
                    
                    records_imported += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        elif data_type == 'schedule':
            for idx, row in df.iterrows():
                try:
                    cursor.execute('''
                        INSERT OR REPLACE INTO schedule (class, day, period, subject)
                        VALUES (?, ?, ?, ?)
                    ''', (row['class'], row['day'], int(row['period']), row['subject']))
                    records_imported += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        elif data_type == 'homework':
            for idx, row in df.iterrows():
                try:
                    hw_id = f"HW{int(datetime.now().timestamp())}_{idx}"
                    cursor.execute('''
                        INSERT INTO homework (id, subject, title, description, date_given, due_date, created_by, class)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (hw_id, row['subject'], row['title'], row.get('description', ''),
                          row.get('date_given', datetime.now().isoformat()), row['due_date'], 
                          session['user_id'], row['class']))
                    records_imported += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        elif data_type == 'grades':
            for idx, row in df.iterrows():
                try:
                    cursor.execute('''
                        INSERT INTO grades (student_id, subject, test_type, score, max_score, date)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (row['student_id'], row['subject'], row['test_type'], 
                          float(row['score']), row.get('max_score', 100), datetime.now().isoformat()))
                    records_imported += 1
                except Exception as e:
                    errors.append(f"Row {idx + 1}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        # Log upload
        conn = get_db_connection()
        cursor = conn.cursor()
        status = 'success' if records_imported > 0 else 'failed'
        message = f"Imported {records_imported} records. " + (f"Errors: {len(errors)}" if errors else "")
        cursor.execute('''
            INSERT INTO upload_logs (uploaded_by, file_name, file_type, status, message, records_imported, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], filename, data_type, status, message, records_imported, datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'DATA_IMPORT', f"Imported {records_imported} {data_type} records")
        
        return jsonify({
            'success': True,
            'records_imported': records_imported,
            'errors': errors[:5]  # Return first 5 errors
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Socket.IO Events
@socketio.on('join_room')
def handle_join_room(data):
    room_id = data['room_id']
    join_room(room_id)
    emit('user_joined', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id)

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data['room_id']
    leave_room(room_id)
    emit('user_left', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id)

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data['room_id']
    message = data['message']
    
    # Save to database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO messages (sender_id, room_id, message, timestamp, read)
        VALUES (?, ?, ?, ?, 0)
    ''', (session['user_id'], room_id, message, datetime.now().isoformat()))
    
    cursor.execute('''
        UPDATE chat_rooms 
        SET last_message = ?
        WHERE room_id = ?
    ''', (datetime.now().isoformat(), room_id))
    
    conn.commit()
    conn.close()
    
    # Broadcast to room
    emit('receive_message', {
        'sender_id': session['user_id'],
        'sender_name': session['name'],
        'message': message,
        'timestamp': datetime.now().isoformat()
    }, room=room_id)

@socketio.on('typing')
def handle_typing(data):
    room_id = data['room_id']
    emit('user_typing', {
        'user_id': session['user_id'],
        'name': session['name']
    }, room=room_id, include_self=False)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    room_id = data['room_id']
    emit('user_stop_typing', {
        'user_id': session['user_id']
    }, room=room_id, include_self=False)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=os.environ.get('DEBUG', 'False') == 'True')
