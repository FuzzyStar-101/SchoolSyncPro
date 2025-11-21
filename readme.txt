# 🎓 SchoolSync Pro - Production Deployment Guide

A comprehensive school management system with real-time chat, task management, timetable scheduling, and more.

## 📋 Features

- **Multi-role Authentication**: Super Admin, Admin, Teacher, Student
- **Real-time Chat**: WhatsApp-style messaging with Socket.IO
- **Task Management**: Google Tasks-style task lists
- **Timetable Editor**: Drag-and-drop schedule creation with conflict detection
- **Homework Management**: Create and track assignments
- **Grade Management**: Enter and view student grades
- **Data Import**: Bulk upload via CSV/Excel/JSON
- **Accounts Management**: CRUD operations for users
- **Audit Logging**: Track all admin actions
- **Password Security**: Hashing, minimum 8 characters, forced password change

## 🚀 Quick Start (Local Development)

### Prerequisites
- Python 3.8+
- pip
- Git

### Installation

```bash
# Clone repository
git clone <your-repo-url>
cd schoolsync-pro

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Access at: `http://localhost:5000`

**Default Super Admin Credentials:**
- Username: `superadmin`
- Password: `superadmin123`
- Click "ADMIN" toggle before logging in

## 🌐 Deploy to Render

### Step 1: Prepare Your Repository

1. Create a new GitHub repository
2. Push all files to GitHub:

```bash
git init
git add .
git commit -m "Initial commit - SchoolSync Pro"
git branch -M main
git remote add origin <your-github-repo-url>
git push -u origin main
```

### Step 2: Create Render Account

1. Go to [render.com](https://render.com)
2. Sign up / Sign in with GitHub

### Step 3: Deploy Web Service

1. Click **"New +"** → **"Web Service"**
2. Connect your GitHub repository
3. Configure:
   - **Name**: `schoolsync-pro`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --worker-class eventlet -w 1 app:app`
   - **Plan**: Free (for testing) or paid (for production)

### Step 4: Set Environment Variables

In Render dashboard, add these environment variables:

```
SECRET_KEY=<generate-random-32-char-string>
DEBUG=False
PORT=10000
```

To generate a secure SECRET_KEY:
```python
import secrets
print(secrets.token_hex(32))
```

### Step 5: Deploy

Click **"Create Web Service"** and wait for deployment (2-5 minutes)

### Step 6: Access Your App

Your app will be available at: `https://schoolsync-pro.onrender.com`

## 🔒 Production Security Checklist

- [x] Passwords hashed with Werkzeug
- [x] Secret key from environment variable
- [x] Session-based authentication
- [x] Role-based access control
- [x] SQL injection prevention (parameterized queries)
- [x] File upload validation
- [x] Audit logging for admin actions
- [ ] Add HTTPS enforcement (Render provides this automatically)
- [ ] Add rate limiting (optional for production)
- [ ] Add CSRF protection (optional enhancement)

## 📊 Database Management

### SQLite (Development & Small Schools)

Default configuration uses SQLite:
- `credentials.db` - User authentication
- `schooldata.db` - Application data

**Backup Command:**
```bash
# Create backups
cp credentials.db credentials.db.backup
cp schooldata.db schooldata.db.backup
```

### PostgreSQL Upgrade (Production)

For larger schools with concurrent users:

1. **Create PostgreSQL database on Render:**
   - Dashboard → New → PostgreSQL
   - Copy the Internal Database URL

2. **Update app.py:**

Replace:
```python
import sqlite3
```

With:
```python
import psycopg2
from psycopg2.extras import RealDictCursor
```

Replace connection function:
```python
def get_db_connection(db_name='schooldata.db'):
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn
```

With:
```python
def get_db_connection():
    conn = psycopg2.connect(
        os.environ.get('DATABASE_URL'),
        cursor_factory=RealDictCursor
    )
    return conn
```

3. **Set environment variable:**
```
DATABASE_URL=<your-postgres-url>
```

## 📁 File Structure

```
schoolsync-pro/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── Procfile               # Render deployment config
├── README.md              # This file
├── credentials.db         # Auth database (auto-created)
├── schooldata.db          # App database (auto-created)
├── uploads/               # File uploads (auto-created)
└── templates/
    ├── login.html         # Login page
    ├── base.html          # Base template
    ├── account.html       # Account management
    ├── schedule.html      # Daily schedule
    ├── calendar.html      # Weekly calendar
    ├── homework.html      # Homework management
    ├── grades.html        # Grade viewer
    ├── tasks.html         # Task lists
    ├── chat.html          # Real-time chat
    ├── accounts_mgmt.html # User CRUD
    ├── data_import.html   # Bulk import
    ├── timetable_editor.html # Schedule editor
    └── monitor_chats.html # Super admin chat monitoring
```

## 👥 User Roles & Permissions

### Super Admin (SA001)
- Full system access
- Monitor all chats (read-only)
- Manage all users
- Access all features

### Admin (A001, A002, ...)
- Manage students/teachers
- Import bulk data
- Create/edit schedules
- All teacher features

### Teacher (T001, T002, ...)
- Create homework
- Enter grades
- View schedules
- Chat with students
- Manage tasks

### Student (S001, S002, ...)
- View schedule & calendar
- View homework & grades
- Chat with teachers/peers
- Manage personal tasks

## 📝 API Endpoints

### Authentication
- `POST /login` - User login
- `GET /logout` - User logout

### Account Management
- `GET /api/account` - Get user profile
- `POST /api/change-password` - Change password
- `POST /api/admin/reset-password` - Admin reset user password

### Tasks
- `GET /api/task-lists` - Get all task lists with tasks
- `POST /api/task-lists` - Create new list
- `POST /api/tasks` - Create new task
- `PUT /api/tasks` - Update task
- `DELETE /api/tasks` - Delete task

### Schedule
- `GET /api/schedule` - Get schedule for class
- `PUT /api/admin/schedule` - Save schedule
- `POST /api/admin/check-conflicts` - Check teacher conflicts

### Homework
- `GET /api/homework` - Get homework (filtered by role)
- `POST /api/homework` - Create homework
- `DELETE /api/homework` - Delete homework

### Grades
- `GET /api/grades` - Get grades for student
- `POST /api/grades` - Enter grade

### Chat
- `GET /api/chat/users` - Search users
- `GET /api/chat/rooms` - Get user's chat rooms
- `POST /api/chat/rooms` - Create chat room
- `GET /api/chat/messages/<room_id>` - Get messages

### Admin
- `GET /api/admin/accounts` - List all accounts
- `POST /api/admin/accounts` - Create account
- `DELETE /api/admin/accounts` - Delete account
- `POST /api/admin/upload` - Import data file

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask session secret | `dev-secret-key...` |
| `DEBUG` | Debug mode | `False` |
| `PORT` | Server port | `5000` |
| `DATABASE_URL` | Database connection | `sqlite:///schooldata.db` |
| `UPLOAD_FOLDER` | File upload directory | `uploads` |

### Database Schema

**credentials.db:**
- `credentials` - User login info (user_id, username, password, role, first_login)

**schooldata.db:**
- `users` - User profiles
- `homework` - Homework assignments
- `grades` - Student grades
- `schedule` - Class schedules
- `task_lists` - Task list containers
- `tasks` - Individual tasks
- `messages` - Chat messages
- `chat_rooms` - Chat room metadata
- `subjects` - Available subjects
- `classes` - Class list
- `teacher_subjects` - Teacher-subject assignments
- `upload_logs` - Import history
- `audit_logs` - Admin action logs

## 📤 Data Import Format

### Students CSV
```csv
name,class,username,password,email,phone
John Doe,10A,johndoe,student123,john@example.com,1234567890
Jane Smith,10B,janesmith,student123,jane@example.com,0987654321
```

### Teachers CSV
```csv
name,subjects,username,password
Mr. Anderson,Mathematics,anderson,teacher123
Ms. Johnson,Physics;Chemistry,johnson,teacher123
```

### Schedule CSV
```csv
class,day,period,subject
10A,Monday,1,Mathematics
10A,Monday,2,Physics
10A,Tuesday,1,Chemistry
```

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Kill process on port 5000
lsof -ti:5000 | xargs kill -9
```

### Socket.IO Not Connecting
- Ensure eventlet is installed
- Check CORS settings in app.py
- Verify WebSocket support on hosting platform

### Database Locked Error
- Close all database connections
- Restart the application
- Consider upgrading to PostgreSQL

### File Upload Fails
- Check `uploads/` directory exists
- Verify file size < 16MB
- Ensure valid file extensions (.csv, .xlsx, .json)

## 📈 Scaling Considerations

### Small School (< 100 users)
- SQLite database
- Single Render instance
- Free tier acceptable

### Medium School (100-500 users)
- PostgreSQL database
- Paid Render instance
- Consider Redis for sessions

### Large School (500+ users)
- PostgreSQL with connection pooling
- Multiple instances with load balancer
- Redis for session management
- CDN for static assets
- Dedicated file storage (S3/Cloudflare R2)

## 🔄 Backup Strategy

### Automated Backups (PostgreSQL on Render)
Render provides automatic daily backups for PostgreSQL databases.

### Manual Backups (SQLite)
```bash
# Schedule with cron (Linux/Mac)
0 2 * * * cd /path/to/app && cp *.db backups/$(date +\%Y\%m\%d)_backup.db
```

## 📧 Support & Maintenance

### Regular Maintenance Tasks
- [ ] Review audit logs weekly
- [ ] Backup databases daily
- [ ] Update dependencies monthly
- [ ] Review user access quarterly
- [ ] Test disaster recovery annually

### Monitoring
- Check Render dashboard for errors
- Monitor database size
- Track active users
- Review upload logs

## 📄 License

This project is provided as-is for commercial use in small schools.

## 🙏 Acknowledgments

Built with:
- Flask (Python web framework)
- Socket.IO (Real-time communication)
- SQLite/PostgreSQL (Databases)
- Font Awesome (Icons)
- Render (Hosting)

---

**Version:** 1.0.0  
**Last Updated:** November 2024  
**Status:** Production Ready ✅