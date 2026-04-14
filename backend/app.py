

from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from psycopg2 import pool as psycopg2_pool
import json
import random
import bcrypt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables FIRST — before any os.getenv() call
load_dotenv()


app = Flask(__name__)


def smart_limit_key():
    """Rate limit by phone/email from request body if available, else fall back to IP.
    This prevents a single user from bypassing limits by switching IPs."""
    try:
        body = request.get_json(silent=True) or {}
        identifier = body.get('phone') or body.get('email') or body.get('identifier')
        if identifier:
            return f"user:{identifier}"
    except Exception:
        pass
    return f"ip:{get_remote_address()}"

limiter = Limiter(
    app=app,
    key_func=smart_limit_key,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://"
)
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        # Strip "Bearer " prefix if present
        token = auth_header.replace('Bearer ', '').strip()
        if not token or not verify_admin_token(token):
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def verify_admin_token(token):
    """Verify JWT token for admin"""
    try:
        import base64
        decoded = base64.b64decode(token).decode()
        token_data = json.loads(decoded)
        
        # Check expiry
        if datetime.now().timestamp() > token_data.get('exp', 0):
            return False
        
        # Check role
        return token_data.get('role') == 'admin'
    except:
        return False

    
# Try to import Twilio (optional)
try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False
    print("âš ï¸ Twilio not installed. SMS features will be disabled.")

# CORS origins from env
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5000','https://pg-website2.onrender.com/api/auth.html').split(',')

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,  # âœ… Now reads from .env!
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
JWT_SECRET = os.getenv('JWT_SECRET')
FLASK_ENV = os.getenv('FLASK_ENV', 'development')
DEBUG_MODE = FLASK_ENV == 'development'
if not ADMIN_EMAIL or not ADMIN_PASSWORD or not JWT_SECRET:
    raise ValueError("❌ CRITICAL: ADMIN_EMAIL, ADMIN_PASSWORD, and JWT_SECRET must be set in .env file!")


# ==================== DATABASE CONNECTION POOL ====================
# Supports both DATABASE_URL (Render) and individual env vars (local dev)
DB_POOL = None

def init_db_pool():
    """Initialize the database connection pool (lazy init)."""
    global DB_POOL
    if DB_POOL is not None:
        return DB_POOL

    database_url = os.getenv('DATABASE_URL')

    try:
        if database_url:
            # Render provides a postgres:// URL — psycopg2 needs postgresql://
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            DB_POOL = psycopg2_pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=50,
                dsn=database_url,
                sslmode='require'
            )
            print("✅ Database pool initialized using DATABASE_URL")
        else:
            # Local development fallback
            DB_POOL = psycopg2_pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=50,
                host=os.getenv('DB_HOST', 'localhost'),
                database=os.getenv('DB_NAME', 'pg_system'),
                user=os.getenv('DB_USER', 'postgres'),
                password=os.getenv('DB_PASSWORD')
            )
            print("✅ Database pool initialized using individual DB env vars")
    except Exception as e:
        print(f"❌ Database pool init failed: {e}")
        DB_POOL = None
        raise

    return DB_POOL

EXECUTOR = ThreadPoolExecutor(max_workers=30)
def get_db_connection():
    """Borrow a connection from the pool (stored on Flask's 'g' per request)."""
    if 'db_conn' not in g:
        # Ensure pool is initialized
        pool = init_db_pool()
        g.db_conn = pool.getconn()
    return g.db_conn

@app.teardown_appcontext
def release_db_connection(exception=None):
    """Return the borrowed connection back to the pool after every request."""
    conn = g.pop('db_conn', None)
    if conn is not None:
        if exception:
            conn.rollback()  # Roll back on error so connection is reusable
        DB_POOL.putconn(conn)

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
SENDER_NAME = os.getenv('SENDER_NAME','AR PG')

# SMS configuration (Twilio)
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN', '')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER', '')

# Owner contact (for payment notifications)
OWNER_PHONE = os.getenv('OWNER_PHONE')
OWNER_EMAIL = os.getenv('OWNER_EMAIL')
OWNER_NAME = os.getenv('OWNER_NAME', 'AR PG Owner')

import secrets
import string

def generate_random_password(length=12):
    """Generate secure random password for admin-added students"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password
import hashlib

def hash_password(password):
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()
def check_password(password, hashed):
    """Verify password"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Initialize Twilio client
twilio_client = None
if TWILIO_AVAILABLE and TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN:
    try:
        twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        print("âœ… Twilio SMS enabled!")
    except Exception as e:
        print(f"âš ï¸ Twilio initialization failed: {str(e)}")
else:
    print("âš ï¸ Twilio SMS disabled (not installed or credentials not found)")

def send_email(recipient_email, subject, body, is_html=False):
    """Send email to recipient"""
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg['To'] = recipient_email

        # Attach body
        if is_html:
            msg.attach(MIMEText(body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))

        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        print(f"âœ… Email sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"âŒ Error sending email: {str(e)}")
        return False

def send_payment_reminder_email(student_name, student_email, amount, due_date):
    """Send payment reminder email"""
    subject = f"Payment Reminder - AR PG Monthly Rent Due"
    
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                <h2>ðŸ’³ Payment Reminder</h2>
            </div>
            
            <div style="padding: 20px; background: #f9f9f9;">
                <p>Hello <strong>{student_name}</strong>,</p>
                
                <p>This is a friendly reminder that your monthly rent payment is due.</p>
                
                <div style="background: white; padding: 15px; border-left: 4px solid #667eea; margin: 20px 0;">
                    <p><strong>Payment Details:</strong></p>
                    <p>ðŸ’° <strong>Amount:</strong> â‚¹{amount}</p>
                    <p>ðŸ“… <strong>Due Date:</strong> {due_date}</p>
                    <p>ðŸ¢ <strong>PG Name:</strong> AR PG</p>
                </div>
                
                <p><strong>Payment Methods:</strong></p>
                <ul>
                    <li>ðŸ’³ Online Payment (Credit/Debit Card, UPI)</li>
                    <li>ðŸ¦ Bank Transfer</li>
                    <li>ðŸ“± Mobile Wallet</li>
                </ul>
                
                <p>Please make the payment at your earliest convenience. You can login to your dashboard to pay online.</p>
                
                <p>If you have any questions, please contact us.</p>
                
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    <strong>AR PG Management System</strong><br>
                    This is an automated message. Please do not reply to this email.
                </p>
            </div>
        </body>
    </html>
    """
    
    EXECUTOR.submit(send_email, student_email, subject, body, True)
    return True

def send_announcement_email(student_name, student_email, announcement_title, announcement_body):
    """Send announcement email"""
    subject = f"Announcement - {announcement_title}"
    
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                <h2>ðŸ“¢ {announcement_title}</h2>
            </div>
            
            <div style="padding: 20px; background: #f9f9f9;">
                <p>Hello <strong>{student_name}</strong>,</p>
                
                <div style="background: white; padding: 15px; border-left: 4px solid #27ae60; margin: 20px 0;">
                    {announcement_body}
                </div>
                
                <p>If you have any questions, please contact us.</p>
                
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    <strong>AR PG Management System</strong><br>
                    This is an automated message. Please do not reply to this email.
                </p>
            </div>
        </body>
    </html>
    """
    
    EXECUTOR.submit(send_email, student_email, subject, body, True)
    return True

def send_sms(phone_number, message):
    """Send SMS to student"""
    try:
        if not twilio_client:
            print("âŒ Twilio not configured")
            return False
        
        # Format phone number (add country code if needed)
        if not phone_number.startswith('+'):
            phone_number = '+91' + phone_number  # India country code
        
        message_obj = twilio_client.messages.create(
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number,
            body=message
        )
        
        print(f"âœ… SMS sent to {phone_number}: {message_obj.sid}")
        return True
    except Exception as e:
        print(f"âŒ Error sending SMS: {str(e)}")
        return False

def send_payment_reminder_sms(student_name, phone_number, amount, due_date):
    """Send payment reminder SMS"""
    message = f"Hi {student_name}, Your monthly rent of â‚¹{amount} is due on {due_date}. Please pay at your earliest. AR PG Management"
    return send_sms(phone_number, message)

def send_announcement_sms(student_name, phone_number, announcement):
    """Send announcement SMS"""
    message = f"Hi {student_name}, {announcement} - AR PG Management"
    return send_sms(phone_number, message)

def notify_owner_payment(student_name, student_phone, room_number, amount, payment_method='Online'):
    """Notify owner when student makes payment"""
    try:
        # Send SMS to owner
        sms_message = f"PAYMENT RECEIVED!\nStudent: {student_name}\nPhone: {student_phone}\nRoom: {room_number}\nAmount: â‚¹{amount}\nMethod: {payment_method}\nDate: {datetime.now().strftime('%d-%b-%Y %H:%M')}"
        
        sms_sent = False
        if twilio_client and OWNER_PHONE:
            sms_sent = send_sms(OWNER_PHONE, sms_message)
        
        # Send email to owner
        email_subject = f"ðŸ’° Payment Received - {student_name}"
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>ðŸ’° Payment Received!</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{OWNER_NAME}</strong>,</p>
                    
                    <p>A student has successfully made a payment. Here are the details:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #27ae60; margin: 20px 0;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Student Name:</td>
                                <td style="padding: 8px;">{student_name}</td>
                            </tr>
                            <tr style="background: #f9f9f9;">
                                <td style="padding: 8px; font-weight: bold;">Phone Number:</td>
                                <td style="padding: 8px;">{student_phone}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Room Number:</td>
                                <td style="padding: 8px;">{room_number}</td>
                            </tr>
                            <tr style="background: #f9f9f9;">
                                <td style="padding: 8px; font-weight: bold;">Amount Paid:</td>
                                <td style="padding: 8px; color: #27ae60; font-weight: bold; font-size: 1.2em;">â‚¹{amount}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Payment Method:</td>
                                <td style="padding: 8px;">{payment_method}</td>
                            </tr>
                            <tr style="background: #f9f9f9;">
                                <td style="padding: 8px; font-weight: bold;">Payment Date:</td>
                                <td style="padding: 8px;">{datetime.now().strftime('%d-%b-%Y %H:%M')}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <p>You can verify this payment in the admin dashboard.</p>
                    
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">
                        <strong>AR PG Management System</strong><br>
                        This is an automated notification. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """
        email_sent = False
        if OWNER_EMAIL:
            EXECUTOR.submit(
                send_email,
                OWNER_EMAIL,
                email_subject,
                email_body,
                True
            )
            email_sent = True
        if sms_sent or email_sent:
            print(f"âœ… Owner notified about payment from {student_name}")
            return True
        else:
            print(f"âš ï¸  Failed to notify owner about payment")
            return False
            
    except Exception as e:
        print(f"â Œ Error notifying owner: {str(e)}")
        return False

# @app.before_request
# def handle_preflight():
#     """Handle CORS preflight requests"""
#     if request.method == "OPTIONS":
#         response = jsonify({'status': 'ok'})
#         response.headers['Access-Control-Allow-Origin'] = '*'
#         response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
#         response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
#         return response, 200

# def init_db():
#     """Initialize database with tables"""
#     conn = get_db_connection()
#     cursor = conn.cursor()
#
#     # Create students table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS students (
#             id SERIAL PRIMARY KEY,
#             fullName TEXT NOT NULL,
#             email TEXT NOT NULL,
#             phone TEXT UNIQUE NOT NULL,
#             college TEXT NOT NULL,
#             course TEXT NOT NULL,
#             year TEXT NOT NULL,
#             roomType TEXT NOT NULL,
#             password TEXT NOT NULL,
#             registrationDate TEXT NOT NULL,
#             status TEXT DEFAULT 'Active',
#             roomNumber INTEGER,
#             monthlyRent INTEGER DEFAULT 8000,
#             paymentStatus TEXT DEFAULT 'pending'
#         )
#     ''')
#
#     # Create payments table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS payments (
#             id SERIAL PRIMARY KEY,
#             studentPhone TEXT NOT NULL,
#             amount INTEGER NOT NULL,
#             dueDate TEXT NOT NULL,
#             paymentDate TEXT,
#             status TEXT DEFAULT 'pending',
#             FOREIGN KEY (studentPhone) REFERENCES students(phone)
#         )
#     ''')
#
#     # Create messages table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS messages (
#             id SERIAL PRIMARY KEY,
#             studentPhone TEXT NOT NULL,
#             messageType TEXT NOT NULL,
#             message TEXT NOT NULL,
#             sentDate TEXT NOT NULL,
#             FOREIGN KEY (studentPhone) REFERENCES students(phone)
#         )
#     ''')
#
#     # Create announcements table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS announcements (
#             id SERIAL PRIMARY KEY,
#             title TEXT NOT NULL,
#             message TEXT NOT NULL,
#             type TEXT DEFAULT 'notice',
#             priority TEXT DEFAULT 'low',
#             date TEXT NOT NULL,
#             createdBy TEXT DEFAULT 'Admin',
#             createdAt TEXT NOT NULL
#         )
#     ''')
#
#     # Create table for storing reset codes
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS password_resets (
#             id SERIAL PRIMARY KEY,
#             email TEXT,
#             code TEXT,
#             expires_at TEXT
#         )
#     ''')
#
#     # Create inquiries table
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS inquiries (
#             id SERIAL PRIMARY KEY,
#             name TEXT NOT NULL,
#             email TEXT NOT NULL,
#             phone TEXT NOT NULL,
#             room TEXT,
#             message TEXT,
#             date TEXT NOT NULL
#         )
#     ''')
#
#     cursor.execute('''
#         CREATE TABLE IF NOT EXISTS current_bills (
#             id SERIAL PRIMARY KEY,
#             studentPhone TEXT NOT NULL,
#             amount INTEGER DEFAULT 200,
#             month TEXT NOT NULL,
#             paymentDate TEXT NOT NULL,
#             status TEXT DEFAULT 'paid',
#             paymentProof TEXT,
#             FOREIGN KEY (studentPhone) REFERENCES students(phone)
#         )
#     ''')
#
#     conn.commit()
#     
#     print("âœ… Database initialized!")

# init_db() â€” removed: tables are managed directly in PostgreSQL

# ==================== AUTHENTICATION ROUTES ====================

@app.route('/api/signup', methods=['POST'])
def signup():
    """Handle student signup"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        
        
        # Check if phone already exists
        cursor.execute('SELECT * FROM students WHERE phone = %s', (data['phone'],))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Phone number already registered!'}), 400
        
        # âœ… UPDATED: Now includes monthlyRent based on roomType
        # Determine rent based on room type
        room_type = data.get('roomType', 'Single')
        if room_type == 'Single':
            monthly_rent = 8000
        elif room_type == '2-Bed':
            monthly_rent = 7500
        elif room_type == '3-Bed':
            monthly_rent = 6500
        else:
            monthly_rent = 8000  # Default
        
        # âœ… UPDATED: Insert with monthlyRent
        cursor.execute('''
            INSERT INTO students (fullName, email, phone, college, course, year, roomType, password, registrationDate, monthlyRent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            data['fullName'],
            data['email'],
            data['phone'],
            data['college'],
            data['course'],
            data['year'],
            data['roomType'],
            hash_password(data['password']),
            datetime.now().strftime('%d-%b-%Y'),
            monthly_rent  # âœ… NOW SAVING RENT!
        ))
        
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Signup successful!'}), 201
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Handle student login using email OR phone"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        # âœ… FIX: Accept both 'phone' and 'identifier'
        identifier = data.get('phone') or data.get('identifier') or data.get('email')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({'success': False, 'message': 'Email/Phone and password are required'}), 400


        # Check using phone OR email
        cursor.execute('''
            SELECT * FROM students
                WHERE phone = %s OR email = %s
        ''', (identifier, identifier))

        student = cursor.fetchone()

        if student and check_password(password, student[8]):
            return jsonify({
                'success': True,
                'message': 'Login successful!',
                'student': {
                    'fullName': student[1],
                    'email': student[2],
                    'phone': student[3],
                    'college': student[4],
                    'course': student[5],
                    'year': student[6],
                    'roomType': student[7],
                    'registrationDate': student[9],
                    'roomNumber': student[11]
                }
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Invalid email/phone or password!'}), 401

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== STUDENT ROUTES ====================

@app.route('/api/student/<phone>', methods=['GET'])
def get_student(phone):
    """Get student details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if student:
            return jsonify({
                'success': True,
                'student': {
                    'fullName': student[1],
                    'email': student[2],
                    'phone': student[3],
                    'college': student[4],
                    'course': student[5],
                    'year': student[6],
                    'roomType': student[7],
                    'registrationDate': student[9],
                    'roomNumber': student[11] or 'N/A',
                    'monthlyRent': student[12],
                    'paymentStatus': student[13]
                }
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/student/<phone>/payments', methods=['GET'])
def get_student_payments(phone):
    """Get student payment history"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, amount, dueDate, paymentDate, status 
            FROM payments WHERE studentPhone = %s
            ORDER BY dueDate DESC
        ''', (phone,))
        
        payments = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'payments': [
                {
                    'id': p[0],
                    'amount': p[1],
                    'dueDate': p[2],
                    'paymentDate': p[3],
                    'status': p[4]
                }
                for p in payments
            ]
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        "ownerUpiId": os.getenv('OWNER_UPI'),
        "ownerName": os.getenv('OWNER_NAME'),
        "ownerPhone": os.getenv('OWNER_PHONE'),
        "monthlyRent": 8000,
        "pgName": os.getenv('PG_NAME'),
        "billAmount": os.getenv('CURRENT_BILL_AMOUNT', 200)  # or dynamic if needed
    })

@app.route('/api/student/<phone>/messages', methods=['GET'])
def get_student_messages(phone):
    """Get messages for student"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, messageType, message, sentDate 
            FROM messages WHERE studentPhone = %s
            ORDER BY sentDate DESC
        ''', (phone,))
        
        messages = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'messages': [
                {
                    'id': m[0],
                    'type': m[1],
                    'message': m[2],
                    'date': m[3]
                }
                for m in messages
            ]
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    


    # ==================== GET ROOMMATES ENDPOINT ====================



# ==================== ANNOUNCEMENTS ROUTES ====================

@app.route('/api/announcements', methods=['GET'])
@limiter.limit("30 per minute")
def get_announcements():
    """Get all announcements for students"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, message, type, priority, date, createdBy, createdAt
            FROM announcements
            ORDER BY createdAt DESC
        ''')
        
        announcements = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'announcements': [
                {
                    'id': a[0],
                    'title': a[1],
                    'message': a[2],
                    'type': a[3],
                    'priority': a[4],
                    'date': a[5],
                    'createdBy': a[6],
                    'createdAt': a[7]
                }
                for a in announcements
            ]
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/announcements', methods=['POST'])
def create_announcement():
    """Create new announcement (Admin only)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        
        
        cursor.execute('''
            INSERT INTO announcements (title, message, type, priority, date, createdBy, createdAt)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (
            data.get('title', 'Announcement'),
            data.get('message'),
            data.get('type', 'notice'),
            data.get('priority', 'low'),
            data.get('date', datetime.now().strftime('%Y-%m-%d')),
            data.get('createdBy', 'Admin'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))

        announcement_id = cursor.fetchone()[0]
        conn.commit()
        
        cursor.execute('SELECT * FROM announcements WHERE id = %s', (announcement_id,))
        announcement = cursor.fetchone()
        
        sent_count = 0
        
        if data.get('sendEmail', True):
            send_to_all = data.get('sendToAll', True)
            phones = data.get('phones', [])
            
            if send_to_all:
                cursor.execute('SELECT fullName, email, phone FROM students')
            else:
                if phones:
                    placeholders = ','.join(['%s'] * len(phones))
                    cursor.execute(
                        f'SELECT fullName, email, phone FROM students WHERE phone IN ({placeholders})',
                        phones
                    )
                else:
                    cursor.execute('SELECT fullName, email, phone FROM students LIMIT 0')
            
            students = cursor.fetchall()
            
          

            for student in students:
                student_name = student[0]
                student_email = student[1]
                student_phone = student[2]

                EXECUTOR.submit(
                    send_announcement_email,
                    student_name,
                    student_email,
                    data.get('title', 'Announcement'),
                    data.get('message')
                )

                if data.get('sendSMS', False) and twilio_client:
                    EXECUTOR.submit(
                      send_announcement_sms,
                      student_name,
                      student_phone,
                      data.get('message')[:100]
                  )

                sent_count += 1

        return jsonify({
            'success': True,
            'message': f'Announcement created successfully! Sent to {sent_count} student(s).',
            'announcement': {
                'id': announcement[0],
                'title': announcement[1],
                'message': announcement[2],
                'type': announcement[3],
                'priority': announcement[4],
                'date': announcement[5]
            }
        }), 201

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/announcements/<int:announcement_id>', methods=['DELETE'])
def delete_announcement(announcement_id):
    """Delete announcement (Admin only)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM announcements WHERE id = %s', (announcement_id,))
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Announcement deleted successfully'
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/announcements/<int:announcement_id>', methods=['PUT'])
def update_announcement(announcement_id):
    """Update announcement (Admin only)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        
        
        cursor.execute('''
            UPDATE announcements 
            SET title = %s, message = %s, type = %s, priority = %s
            WHERE id = %s
        ''', (
            data.get('title'),
            data.get('message'),
            data.get('type'),
            data.get('priority'),
            announcement_id
        ))
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': 'Announcement updated successfully'
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== ADMIN ROUTES ====================



@app.route('/api/admin/students', methods=['GET'])
@require_admin
def get_all_students():
    """Get all students (for admin)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # REPLACE WITH:
        cursor.execute('SELECT fullName, email, phone, college, roomNumber, paymentStatus, monthlyRent, roomType FROM students')
        students = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'students': [
                {
                    'fullName': s[0],
                    'email': s[1],
                    'phone': s[2],
                    'college': s[3],
                    'roomNumber': s[4],
                    'paymentStatus': s[5],
                    'monthlyRent': s[6],   # â† ADD THIS
                    'roomType': s[7] 
                }
                for s in students
            ]
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/add-student', methods=['POST'])
@require_admin
def admin_add_student():
    """Admin add student"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        random_password = generate_random_password()
        
        cursor.execute('''
            INSERT INTO students (fullName, email, phone, college, course, year, roomType, password, registrationDate, roomNumber, monthlyRent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            data['fullName'],
            data['email'],
            data['phone'],
            data.get('college', 'N/A'),
            data.get('course', 'N/A'),
            data.get('year', 'N/A'),
            data.get('roomType', 'Single'),
            hash_password(random_password),
            datetime.now().strftime('%d-%b-%Y'),
            data.get('roomNumber'),
            data.get('monthlyRent', 8000)
        ))
        
        conn.commit()
        student_name = data['fullName']
        student_email = data['email']
        
        email_subject = "Welcome to AR PG - Your Account Details"
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>ðŸ  Welcome to AR PG!</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{student_name}</strong>,</p>
                    
                    <p>Your account has been created by the admin. Here are your login details:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0;">
                        <p><strong>Email/Phone:</strong> {student_email}</p>
                        <p><strong>Temporary Password:</strong> <span style="font-size: 1.3em; color: #667eea; font-weight: bold;">{random_password}</span></p>
                    </div>
                    
                    <p><strong>âš ï¸ Important:</strong></p>
                    <ul>
                        <li>Keep this password secure</li>
                        <li>You can change your password after first login</li>
                        <li>Login at: http://localhost:5000/auth.html</li>
                    </ul>
                    
                    <p>If you have any questions, please contact us.</p>
                    
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">
                        <strong>AR PG Management System</strong><br>
                        This is an automated message. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """
        
        # Send email
        EXECUTOR.submit(send_email, student_email, email_subject, email_body, True)
        
        return jsonify({
            'success': True, 
            'message': f'Student added successfully! Password sent to {student_email}'
        }), 201
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/payments', methods=['GET'])
@require_admin
def get_all_payments():
    """Get all payments (for admin)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT s.fullName, s.phone, p.amount, p.dueDate, p.status, s.monthlyRent
            FROM payments p
            JOIN students s ON p.studentPhone = s.phone
            ORDER BY p.dueDate DESC
        ''')
        
        payments = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'payments': [
                {
                    'studentName': p[0],
                    'phone': p[1],
                    'amount': p[2],
                    'dueDate': p[3],
                    'status': p[4],
                    'monthlyRent': p[5]
                }
                for p in payments
            ]
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/mark-paid', methods=['POST', 'OPTIONS'])
def mark_payment_paid():
    """Mark payment as paid"""
    
    # Handle OPTIONS preflight
    if request.method == 'OPTIONS':
        return '', 200
    
    try:
        # Get admin token
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'No authorization token'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify admin token
        try:
            import base64
            token_data = json.loads(base64.b64decode(token).decode())
            
            # Check expiry
            if datetime.now().timestamp() > token_data.get('exp', 0):
                return jsonify({'success': False, 'message': 'Token expired'}), 401
            
            # Check role
            if token_data.get('role') != 'admin':
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
                
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid token'}), 401
        
        # Get student phone
        data = request.json
        phone = data.get('phone')
        
        if not phone:
            return jsonify({'success': False, 'message': 'Phone number required'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber, monthlyRent FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        amount = student[2]
        
        # âœ… FIXED: Remove LIMIT from UPDATE query
        # Update existing pending payment row
        cursor.execute('''
            UPDATE payments 
            SET status = 'paid', paymentDate = %s
            WHERE studentPhone = %s AND status = 'pending'
        ''', (datetime.now().strftime('%d-%b-%Y'), phone))

        # If no pending row existed, INSERT a new payment record
        if cursor.rowcount == 0:
            cursor.execute('''
                INSERT INTO payments (studentPhone, amount, dueDate, paymentDate, status)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                phone,
                amount,
                datetime.now().strftime('%d-%b-%Y'),
                datetime.now().strftime('%d-%b-%Y'),
                'paid'
            ))

        # Also update student payment status
        cursor.execute('''
            UPDATE students 
            SET paymentStatus = 'paid'
            WHERE phone = %s
        ''', (phone,))
        conn.commit()
        
        # Notify owner about the payment (Manual verification)
        notify_owner_payment(student_name, phone, room_number, amount, 'Manual/Cash')
        
        return jsonify({
            'success': True,
            'message': 'Payment marked as paid! Owner notified.'
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Mark paid error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/create-payment-order', methods=['POST'])
def create_payment_order():
    """Create a payment order for Razorpay"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 8000)  # in rupees
        
        
        # Get student details
        cursor.execute('SELECT fullName, email FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
        
        # In real scenario, you'd create order in Razorpay
        # For now, we'll return a mock order
        order_id = f"order_{phone}_{int(datetime.now().timestamp())}"
        
        return jsonify({
            'success': True,
            'orderId': order_id,
            'amount': amount * 100,  # Razorpay expects amount in paise
            'currency': 'INR',
            'studentName': student[0],
            'studentEmail': student[1],
            'studentPhone': phone
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/verify-payment', methods=['POST'])
def verify_payment():
    """Verify payment from Razorpay"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 8000)
        payment_method = data.get('paymentMethod', 'Online')
        
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        
        # Mark payment as paid
        cursor.execute('''
            UPDATE students SET paymentStatus = 'paid'
            WHERE phone = %s
        ''', (phone,))
        
        # Create payment record
        cursor.execute('''
    INSERT INTO payments (studentPhone, amount, dueDate, paymentDate, status)
    VALUES (%s, %s, %s, %s, %s)
''', (
    phone,
    amount,
    datetime.now().strftime('%d-%b-%Y'),
    datetime.now().strftime('%d-%b-%Y'),
    'paid'
))
        conn.commit()
        
        # Notify owner about the payment
        notify_owner_payment(student_name, phone, room_number, amount, payment_method)
        
        return jsonify({
            'success': True,
            'message': 'Payment verified and recorded successfully! Owner has been notified.'
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/send-reminder', methods=['POST'])
@require_admin
def send_reminder():
    """Send reminder to students"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phones = data.get('phones', [])
        message = data.get('message', '')
        messageType = data.get('messageType', 'reminder')
        send_sms_flag = data.get('sendSMS', True)
        send_email_flag = data.get('sendEmail', True)
        
        
        sent_count = 0
        email_errors = []
        sms_errors = []
        
        for phone in phones:
            # Get student details
            cursor.execute('SELECT fullName, email FROM students WHERE phone = %s', (phone,))
            student = cursor.fetchone()
            
            if student:
                student_name = student[0]
                student_email = student[1]
                
                # Save message to database
                cursor.execute('''
                    INSERT INTO messages (studentPhone, messageType, message, sentDate)
                    VALUES (%s, %s, %s, %s)
                ''', (phone, messageType, message, datetime.now().strftime('%d-%b-%Y %H:%M')))
                
                # Send email if enabled
                if send_email_flag and messageType == 'payment':
                    cursor.execute('SELECT monthlyRent FROM students WHERE phone = %s', (phone,))
                    student_rent = cursor.fetchone()
                    rent_amount = student_rent[0] if student_rent else 8000
                    email_sent = send_payment_reminder_email(
                        student_name,
                        student_email,
                        rent_amount,
                        datetime.now().strftime('%d-%b-%Y')
                    )
                    if not email_sent:
                        email_errors.append(student_name)
                elif send_email_flag:
                    email_sent = send_announcement_email(
                        student_name,
                        student_email,
                        "Message from AR PG",
                        message
                    )
                    if not email_sent:
                           email_errors.append(student_name)
                
                # Send SMS if enabled
                if send_sms_flag:
                    if messageType == 'payment':
                        sms_sent = send_payment_reminder_sms(student_name, phone, 8000, datetime.now().strftime('%d-%b-%Y'))
                    else:
                        sms_sent = send_announcement_sms(student_name, phone, message[:100])  # SMS limit
                    
                    if sms_sent:
                        sent_count += 1
                    else:
                        sms_errors.append(student_name)
                else:
                    if send_email_flag:
                        sent_count += 1
        
        conn.commit()
        
        response_message = f'Reminder sent to {sent_count} student(s)!'
        errors = []
        if email_errors:
            errors.append(f"Email errors: {len(email_errors)}")
        if sms_errors:
            errors.append(f"SMS errors: {len(sms_errors)}")
        
        if errors:
            response_message += f' ({", ".join(errors)})'
        
        return jsonify({
            'success': True,
            'message': response_message,
            'sent': sent_count,
            'email_errors': email_errors,
            'sms_errors': sms_errors
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/send-payment-reminder/<phone>', methods=['POST'])
def send_payment_reminder(phone):
    """Send payment reminder to specific student"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT fullName, email, monthlyRent FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
        
        student_name = student[0]
        student_email = student[1]
        amount = student[2]
        
        # Send payment reminder email
        email_sent = send_payment_reminder_email(
            student_name,
            student_email,
            amount,
            datetime.now().strftime('%d-%b-%Y')
        )
        
        # Send SMS
        sms_sent = send_payment_reminder_sms(student_name, phone, amount, datetime.now().strftime('%d-%b-%Y'))
        
        message = []
        if email_sent:
            message.append(f"Email sent to {student_email}")
        if sms_sent:
            message.append(f"SMS sent to {phone}")
        
        if message:
            return jsonify({
                'success': True,
                'message': '; '.join(message)
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send reminder'
            }), 500
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/send-sms', methods=['POST'])
@require_admin
def send_sms_route():
    """Send SMS to students"""
    try:
        data = request.json
        phones = data.get('phones', [])
        message = data.get('message', '')
        
        if not twilio_client:
            return jsonify({
                'success': False,
                'message': 'SMS service not configured. Please add Twilio credentials to .env'
            }), 500
        
        sent_count = 0
        errors = []
        
        for phone in phones:
            # Limit message to 160 characters for SMS
            sms_message = message[:160]
            if send_sms(phone, sms_message):
                sent_count += 1
            else:
                errors.append(phone)
        
        return jsonify({
            'success': True,
            'message': f'SMS sent to {sent_count} student(s)!',
            'sent': sent_count,
            'errors': errors
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/api/admin/update-student', methods=['POST'])
@require_admin
def update_student():
    """Admin endpoint to update existing student details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # Get student data
        data = request.json
        phone = data.get('phone')
        
        if not phone:
            return jsonify({'success': False, 'message': 'Phone number required'}), 400
        
        
        cursor.execute('SELECT * FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        # Update student details
        cursor.execute('''
            UPDATE students 
            SET fullName = %s,
                email = %s,
                roomNumber = %s,
                roomType = %s,
                monthlyRent = %s
            WHERE phone = %s
        ''', (
            data.get('fullName'),
            data.get('email'),
            data.get('roomNumber'),
            data.get('roomType'),
            data.get('monthlyRent'),
            phone
        ))
        
        conn.commit()
        
        print(f"âœ… Student {data.get('fullName')} updated successfully")
        
        return jsonify({
            'success': True,
            'message': f'Student {data.get("fullName")} updated successfully'
        })
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Update student error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500 
    # ==================== DELETE STUDENT ENDPOINT ====================

@app.route('/api/admin/delete-student/<phone>', methods=['DELETE', 'OPTIONS'])
@require_admin
def delete_student(phone):
    """Delete a student from the system (Admin only)"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if student exists
        cursor.execute('SELECT fullName FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({
                'success': False,
                'message': 'Student not found'
            }), 404
        
        student_name = student[0]
        
        # Delete student's payment records first (foreign key constraint)
        cursor.execute('DELETE FROM payments WHERE studentPhone = %s', (phone,))
        
        # Delete student's messages
        cursor.execute('DELETE FROM messages WHERE studentPhone = %s', (phone,))
        
        # Delete the student
        cursor.execute('DELETE FROM students WHERE phone = %s', (phone,))
        
        conn.commit()
        
        print(f"âœ… Student deleted: {student_name} ({phone})")
        
        return jsonify({
            'success': True,
            'message': f'Student {student_name} deleted successfully'
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f"âŒ Error deleting student: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


reset_codes = {}

# ==================== PASSWORD RESET ROUTES ====================

@app.route('/api/forgot-password/send-code', methods=['POST'])
def send_reset_code():
    """Send password reset code to student's email using email address"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400


        # Find student by email
        cursor.execute('SELECT fullName, email FROM students WHERE email = %s', (email,))
        student = cursor.fetchone()

        if not student:
            return jsonify({'success': False, 'message': 'No account found with this email'}), 404

        student_name = student[0]
        student_email = student[1]

        # Generate 6-digit reset code
        code = str(random.randint(100000, 999999))

        # Expire in 10 minutes
        expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')

        # Clear previous codes for this email
        cursor.execute('DELETE FROM password_resets WHERE email = %s', (student_email,))

        # Save new code
        cursor.execute('''
            INSERT INTO password_resets (email, code, expires_at)
            VALUES (%s, %s, %s)
        ''', (student_email, code, expires_at))

        conn.commit()

        # Send email
        subject = "Password Reset Code - AR PG"
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>ðŸ” Password Reset Request</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{student_name}</strong>,</p>
                    
                    <p>We received a request to reset your AR PG password. Use the code below to continue:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0; text-align: center;">
                        <h1 style="color: #667eea; font-size: 2.5em; letter-spacing: 6px; margin: 10px 0;">{code}</h1>
                        <p style="color: #999; font-size: 0.9em;">This code is valid for 10 minutes.</p>
                    </div>
                    
                    <p><strong>âš ï¸ Security tips:</strong></p>
                    <ul>
                        <li>Do not share this code with anyone.</li>
                        <li>If you didn't request this, you can ignore this email.</li>
                    </ul>
                    
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">
                        <strong>AR PG Management System</strong><br>
                        This is an automated message. Please do not reply to this email.
                    </p>
                </div>
            </body>
        </html>
        """

        EXECUTOR.submit(send_email, student_email, subject, body, True)

        return jsonify({
            'success': True,
            'message': f'Reset code sent to {student_email}'
        }), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/forgot-password/verify-code', methods=['POST'])
def verify_reset_code():
    """Verify password reset code using email and code"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')
        code = data.get('code')

        if not email or not code:
            return jsonify({'success': False, 'message': 'Email and code are required'}), 400


        cursor.execute('SELECT code, expires_at FROM password_resets WHERE email = %s', (email,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'No reset request found. Please try again.'}), 404

        stored_code, expires_at_str = row

        # Check expiry
        expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expires_at:
            cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))
            conn.commit()
            return jsonify({'success': False, 'message': 'Reset code expired. Please request a new one.'}), 400

        # Check code
        if stored_code != code:
            return jsonify({'success': False, 'message': 'Invalid reset code'}), 400

        return jsonify({'success': True, 'message': 'Code verified successfully!'}), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/forgot-password/reset', methods=['POST'])
def reset_password():
    """Reset student password using email"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')
        new_password = data.get('newPassword')

        if not email or not new_password:
            return jsonify({'success': False, 'message': 'Email and new password are required'}), 400


        # Make sure there is a valid reset entry (extra safety)
        cursor.execute('SELECT expires_at FROM password_resets WHERE email = %s', (email,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Reset session expired. Please start again.'}), 400

        expires_at_str = row[0]
        expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expires_at:
            cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))
            conn.commit()
            return jsonify({'success': False, 'message': 'Reset code expired. Please request a new one.'}), 400

        # Update student password by email
        cursor.execute('''
            UPDATE students SET password = %s
            WHERE email = %s
        ''', (hash_password(new_password), email)) 

        conn.commit()

        # Remove reset entry
        cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))
        conn.commit()

        return jsonify({'success': True, 'message': 'Password reset successful!'}), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/send-announcement', methods=['POST'])
@require_admin
def send_announcement():
    """Send announcement to all or selected students"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phones = data.get('phones', [])
        title = data.get('title', 'Announcement')
        content = data.get('content', '')
        
        
        # If no phones specified, send to all
        if not phones:
            cursor.execute('SELECT phone FROM students')
            phones = [row[0] for row in cursor.fetchall()]
        
        sent_count = 0
        
        for phone in phones:
            cursor.execute('SELECT fullName, email FROM students WHERE phone = %s', (phone,))
            student = cursor.fetchone()
            
            if student:
                student_name = student[0]
                student_email = student[1]
                
                # Send announcement email
                email_sent = send_announcement_email(
                    student_name,
                    student_email,
                    title,
                    content
                )
                
                if email_sent:
                    sent_count += 1
        
        
        return jsonify({
            'success': True,
            'message': f'Announcement sent to {sent_count} student(s)!',
            'sent': sent_count
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/dashboard-stats', methods=['GET'])
@require_admin
def get_dashboard_stats():
    """Get admin dashboard statistics"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total students
        cursor.execute('SELECT COUNT(*) FROM students')
        total_students = cursor.fetchone()[0]
        
        # Paid students this month
        cursor.execute("SELECT COUNT(*) FROM students WHERE paymentStatus = 'paid'")
        paid_students = cursor.fetchone()[0]
        
        # Pending payments
        cursor.execute("SELECT COUNT(*) FROM students WHERE paymentStatus = 'pending'")
        pending_students = cursor.fetchone()[0]
        
        # Total revenue
       # Total revenue
        cursor.execute('SELECT SUM(monthlyRent) FROM students')
        total_revenue = cursor.fetchone()[0] or 0

        # Revenue from paid students only
        cursor.execute("SELECT SUM(monthlyRent) FROM students WHERE paymentStatus = 'paid'")
        total_collected = cursor.fetchone()[0] or 0

        # Revenue from pending students only
        cursor.execute("SELECT SUM(monthlyRent) FROM students WHERE paymentStatus = 'pending'")
        pending_amount = cursor.fetchone()[0] or 0

        return jsonify({
            'success': True,
            'stats': {
                'totalStudents': total_students,
                'paidThisMonth': paid_students,
                'pendingPayments': pending_students,
                'totalRevenue': total_revenue,
                'totalCollected': total_collected,
                'pendingAmount': pending_amount
            }
        }), 200
    
    except Exception as e:

    
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== TEST ROUTE ====================

@app.route('/api/test', methods=['GET'])
def test():
    """Test if backend is running"""
    return jsonify({'success': True, 'message': 'Backend is running! âœ…'}), 200

# ==================== ERROR HANDLING ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Route not found!'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Internal server error!'}), 500

@app.route('/api/notify-payment', methods=['POST'])
def notify_payment():
    """Notify owner about manual payment (QR/UPI/Bank)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 8000)
        method = data.get('method', 'Manual')
        reference = data.get('reference', 'N/A')
        
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        
        # Create payment record (pending verification)
        cursor.execute('''
            INSERT INTO payments (studentPhone, amount, dueDate, paymentDate, status)
            VALUES (%s, %s, %s, %s, %s)
        ''', (phone, amount, datetime.now().strftime('%d-%b-%Y'), 
              datetime.now().strftime('%d-%b-%Y'), 'pending_verification'))
        
        conn.commit()
        
        # Notify owner
        notify_owner_payment(student_name, phone, room_number, amount, f'{method} - Ref: {reference}')
        
        return jsonify({
            'success': True,
            'message': 'Payment notification sent to owner'
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
# ==================== INQUIRY ROUTE ====================
@app.route('/api/inquiry', methods=['POST'])
def handle_inquiry():
    """Save inquiry from the contact form"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json

        name = data.get('name')
        email = data.get('email')
        phone = data.get('phone')
        room = data.get('room')
        message = data.get('message')


        cursor.execute('''
            INSERT INTO inquiries (name, email, phone, room, message, date)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (name, email, phone, room, message, datetime.now().strftime('%d-%b-%Y %H:%M')))

        conn.commit()

        # Optional: send email notification to owner
        subject = f"New Inquiry from {name}"
        body = f"""
        Name: {name}
        Email: {email}
        Phone: {phone}
        Room: {room}
        Message: {message}
        """
        EXECUTOR.submit(send_email, OWNER_EMAIL, subject, body)

        return jsonify({'success': True, 'message': 'Inquiry submitted successfully!'}), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# âœ… NEW route for Admin Dashboard to view inquiries
@app.route('/api/inquiries', methods=['GET'])
@require_admin
def get_inquiries():
    """Fetch all inquiries for admin dashboard"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM inquiries ORDER BY id DESC')
        inquiries = cursor.fetchall()

        # Convert to list of dicts
        inquiries_list = [
            {
                'id': row[0],
                'name': row[1],
                'email': row[2],
                'phone': row[3],
                'room': row[4],
                'message': row[5],
                'date': row[6]
            }
            for row in inquiries
        ]

        return jsonify({'success': True, 'inquiries': inquiries_list}), 200
    except Exception as e:

        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
import os

# Add these routes BEFORE if __name__ == '__main__':
import os

# Get the directory where backend.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)  # d:\PG\

@app.route('/student/forgot-password.html')
def forgot_password_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'forgot-password.html')

@app.route('/auth.html')
def auth_page():
    return send_from_directory(PARENT_DIR, 'auth.html')

@app.route('/admin/admin.html')
def admin_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'admin'), 'admin.html')

@app.route('/student/dashboard.html')
def dashboard_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'dashboard.html')

@app.route('/student/payment.html')
def payment_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'payment.html')

@app.route('/index.html')
@app.route('/')
def index_page():
    return send_from_directory(PARENT_DIR, 'index.html')

@app.route('/admin/admin-forgot-password.html')
def admin_forgot_password_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'admin'), 'admin-forgot-password.html')

@app.route('/student/current-bill.html')
def current_bill_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'current-bill.html')

@app.route('/admin/announcement.html')
def announcement_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'admin'), 'announcement.html')




# âœ… Serve static files (CSS, JS, images)
@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(PARENT_DIR, filename)
# ==================== ADMIN PASSWORD RESET ROUTES ====================

@app.route('/api/admin-forgot-password/send-code', methods=['POST', 'OPTIONS'])
def admin_send_reset_code():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'}), 400

        # Check if this is an admin email (you can customize this check)
        # For now, let's assume admin email should be in your system
        # Lines 1831-1833 - Replace with:
        ADMIN_EMAIL_FROM_ENV = os.getenv('ADMIN_EMAIL')
        if email != ADMIN_EMAIL_FROM_ENV:
         return jsonify({'success': False, 'message': 'Not an admin email'}), 403


        # Generate 6-digit reset code
        code = str(random.randint(100000, 999999))

        # Expire in 10 minutes
        expires_at = (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')

        # Clear previous codes for this email
        cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))

        # Save new code
        cursor.execute('''
            INSERT INTO password_resets (email, code, expires_at)
            VALUES (%s, %s, %s)
        ''', (email, code, expires_at))

        conn.commit()

        # Send email
        subject = "Admin Password Reset Code - AR PG"
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #1e1f47 0%, #3a2e8a 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>ðŸ” Admin Password Reset Request</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>Admin</strong>,</p>
                    
                    <p>We received a request to reset your admin password. Use the code below:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #3a2e8a; margin: 20px 0; text-align: center;">
                        <h1 style="color: #3a2e8a; font-size: 2.5em; letter-spacing: 6px; margin: 10px 0;">{code}</h1>
                        <p style="color: #999; font-size: 0.9em;">This code is valid for 10 minutes.</p>
                    </div>
                    
                    <p><strong>âš ï¸ Security Alert:</strong></p>
                    <ul>
                        <li>Do not share this code with anyone.</li>
                        <li>If you didn't request this, ignore this email.</li>
                    </ul>
                </div>
            </body>
        </html>
        """

        EXECUTOR.submit(send_email, email, subject, body, True)
        return jsonify({
            'success': True,
            'message': f'Reset code sent to {email}'
        }), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin-forgot-password/verify-code', methods=['POST', 'OPTIONS'])
def admin_verify_reset_code():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')
        code = data.get('code')

        if not email or not code:
            return jsonify({'success': False, 'message': 'Email and code are required'}), 400


        cursor.execute('SELECT code, expires_at FROM password_resets WHERE email = %s', (email,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'No reset request found'}), 404

        stored_code, expires_at_str = row

        # Check expiry
        expires_at = datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expires_at:
            cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))
            conn.commit()
            return jsonify({'success': False, 'message': 'Reset code expired'}), 400

        # Check code
        if stored_code != code:
            return jsonify({'success': False, 'message': 'Invalid reset code'}), 400

        return jsonify({'success': True, 'message': 'Code verified successfully!'}), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin-forgot-password/reset', methods=['POST', 'OPTIONS'])
def admin_reset_password():
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        email = data.get('email')
        new_password = data.get('newPassword')

        if not email or not new_password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400


        # Verify reset session
        cursor.execute('SELECT expires_at FROM password_resets WHERE email = %s', (email,))
        row = cursor.fetchone()

        if not row:
            return jsonify({'success': False, 'message': 'Reset session expired'}), 400

        from dotenv import set_key
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        set_key(env_path, 'ADMIN_PASSWORD', new_password)
        os.environ['ADMIN_PASSWORD'] = new_password

        # Remove reset entry
        cursor.execute('DELETE FROM password_resets WHERE email = %s', (email,))
        conn.commit()

        return jsonify({'success': True, 'message': 'Admin password reset successful!'}), 200

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    # ==================== ADMIN LOGIN ROUTE ====================

@app.route('/api/admin-login', methods=['POST', 'OPTIONS'])
def admin_login():
    """Handle admin login and generate token"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400

        # Hardcoded admin credentials (you can enhance this later with database)
        ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
        ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            # Generate a simple token (base64 encoded JSON)
            import base64
            token_data = {
                'email': email,
                'role': 'admin',
                'exp': (datetime.now() + timedelta(days=1)).timestamp()
            }
            token = base64.b64encode(json.dumps(token_data).encode()).decode()

            return jsonify({
                'success': True,
                'token': token,
                'message': 'Login successful',
                'email': email
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Invalid admin credentials'
            }), 401

    except Exception as e:


        if 'conn' in locals():
            conn.rollback()
        print(f"âŒ Error in admin login: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
    # ==================== CURRENT BILL ROUTES ====================

@app.route('/api/current-bill/status/<phone>', methods=['GET'])
def get_current_bill_status(phone):
    """Check if student has paid current month's electricity bill"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get current month/year
        current_month = datetime.now().strftime('%b-%Y')  # e.g., "Feb-2026"
        
        # Check if current bill is paid
        cursor.execute('''
            SELECT * FROM current_bills 
            WHERE studentPhone = %s AND month = %s AND status = 'paid'
        ''', (phone, current_month))
        
        bill = cursor.fetchone()
        
        return jsonify({
            'success': True,
            'isPaid': bill is not None,
            'month': current_month
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/current-bills/<phone>', methods=['GET'])
def get_student_current_bills(phone):
    """Get current bill history for a specific student"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all bills for this student
        cursor.execute('''
            SELECT id, amount, month, paymentDate, status, paymentProof
            FROM current_bills
            WHERE studentPhone = %s
            ORDER BY paymentDate DESC
        ''', (phone,))
        
        bills = cursor.fetchall()
        
        # Also get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        # Get current month
        current_month = datetime.now().strftime('%b-%Y')
        
        # Check if current month is paid
        current_month_paid = any(b[2] == current_month and b[4] == 'paid' for b in bills)
        
        return jsonify({
            'success': True,
            'student': {
                'name': student[0],
                'phone': phone,
                'roomNumber': student[1] or 'N/A'
            },
            'currentMonth': current_month,
            'isPaid': current_month_paid,
            'bills': [
                {
                    'id': b[0],
                    'amount': b[1],
                    'month': b[2],
                    'paymentDate': b[3],
                    'status': b[4],
                    'hasProof': b[5] is not None
                }
                for b in bills
            ]
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Error fetching bills: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/api/current-bill/email', methods=['POST'])
def email_current_bill():
    """Email current bill to student"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        month = data.get('month', datetime.now().strftime('%b-%Y'))
        
        if not phone:
            return jsonify({'success': False, 'message': 'Phone required'}), 400
        
        
        # Get student details
        cursor.execute('SELECT fullName, email, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        student_email = student[1]
        room_number = student[2] or 'N/A'
        
        # Check if bill is paid
        cursor.execute('''
            SELECT status FROM current_bills 
            WHERE studentPhone = %s AND month = %s
        ''', (phone, month))
        
        bill = cursor.fetchone()
        status = bill[0] if bill else 'Pending'
        
        
        # Calculate due date (5th of next month)
        now = datetime.now()
        if now.month == 12:
            due_date = datetime(now.year + 1, 1, 5)
        else:
            due_date = datetime(now.year, now.month + 1, 5)
        due_date_str = due_date.strftime('%d-%b-%Y')
        
        # Send email
        subject = f"Current Bill - {month} - AR PG"
        body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>âš¡ Current Bill - {month}</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{student_name}</strong>,</p>
                    
                    <p>Here are your current bill details:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Room Number:</td>
                                <td style="padding: 8px;">{room_number}</td>
                            </tr>
                            <tr style="background: #f9f9f9;">
                                <td style="padding: 8px; font-weight: bold;">Bill Month:</td>
                                <td style="padding: 8px;">{month}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Amount:</td>
                                <td style="padding: 8px; color: #667eea; font-weight: bold; font-size: 1.2em;">â‚¹200</td>
                            </tr>
                            <tr style="background: #f9f9f9;">
                                <td style="padding: 8px; font-weight: bold;">Due Date:</td>
                                <td style="padding: 8px;">{due_date_str}</td>
                            </tr>
                            <tr>
                                <td style="padding: 8px; font-weight: bold;">Status:</td>
                                <td style="padding: 8px;">
                                    <span style="{'background: #d4edda; color: #155724;' if status == 'paid' else 'background: #fff3cd; color: #856404;'} padding: 5px 10px; border-radius: 15px; font-weight: bold;">
                                        {status.upper()}
                                    </span>
                                </td>
                            </tr>
                        </table>
                    </div>
                    
                    <p><strong>Payment Details:</strong></p>
                    <ul>
                        <li>Monthly Electricity Charge: â‚¹200</li>
                        <li>Includes: Room lighting, fan, charging points</li>
                        <li>Late Fee: â‚¹50 per day after due date</li>
                    </ul>
                    
                    <p>Login to your dashboard to pay online or view detailed bill.</p>
                    
                    <p style="color: #666; font-size: 12px; margin-top: 30px;">
                        <strong>AR PG Management System</strong><br>
                        Contact: +91-9738225350 | ravishankargowda88@gmail.com
                    </p>
                </div>
            </body>
        </html>
        """
        
        EXECUTOR.submit(send_email, student_email, subject, body, True)
        email_sent = True
        
        if email_sent:
            return jsonify({
                'success': True,
                'message': f'Bill sent to {student_email}'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to send email'
            }), 500
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Email error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/current-bill/pay', methods=['POST'])
def pay_current_bill():
    """Record current bill payment"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 200)
        month = data.get('month')
        
        if not phone:
            return jsonify({'success': False, 'message': 'Phone required'}), 400
        
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        
        # Current month if not provided
        if not month:
            month = datetime.now().strftime('%b-%Y')
        
        # Check if already paid
        cursor.execute('''
            SELECT * FROM current_bills 
            WHERE studentPhone = %s AND month = %s
        ''', (phone, month))
        
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Already paid for this month'}), 400
        
        # Record payment
        cursor.execute('''
            INSERT INTO current_bills (studentPhone, amount, month, paymentDate, status)
            VALUES (%s, %s, %s, %s, %s)
        ''', (phone, amount, month, datetime.now().strftime('%d-%b-%Y'), 'paid'))
        
        conn.commit()
        
        # Notify owner
        notify_owner_payment(student_name, phone, room_number, amount, 'Current Bill (Online)')
        
        return jsonify({
            'success': True,
            'message': 'Current bill paid successfully!'
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/api/current-bill/upload-proof', methods=['POST'])
def upload_current_bill_proof():
    """Upload payment proof for current bill (pending admin verification)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 200)
        month = data.get('month')
        payment_proof = data.get('paymentProof')  # Base64 image
        
        if not phone or not payment_proof:
            return jsonify({'success': False, 'message': 'Phone and payment proof required'}), 400
        
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        
        # Current month if not provided
        if not month:
            month = datetime.now().strftime('%b-%Y')
        
        # Check if already submitted proof for this month
        cursor.execute('''
            SELECT * FROM current_bills 
            WHERE studentPhone = %s AND month = %s
        ''', (phone, month))
        
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'Payment proof already submitted'}), 400
        
        # Save payment proof (pending verification)
        cursor.execute('''
            INSERT INTO current_bills (studentPhone, amount, month, paymentDate, status, paymentProof)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (phone, amount, month, datetime.now().strftime('%d-%b-%Y'), 'pending_verification', payment_proof))
        
        conn.commit()
        
        # Notify owner about pending verification
        notify_owner_payment(student_name, phone, room_number, amount, 'Current Bill (Proof Uploaded - Pending)')
        
        return jsonify({
            'success': True,
            'message': 'Payment proof uploaded! Admin will verify within 24 hours.'
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/api/current-bill/verify/<phone>/<month>', methods=['POST'])
@require_admin
def verify_current_bill_payment(phone, month):
    """Admin verifies current bill payment proof"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.json
        approve = data.get('approve', True)  # True to approve, False to reject
        
        
        # Get payment record
        cursor.execute('''
            SELECT * FROM current_bills 
            WHERE studentPhone = %s AND month = %s AND status = 'pending_verification'
        ''', (phone, month))
        
        payment = cursor.fetchone()
        
        if not payment:
            return jsonify({'success': False, 'message': 'No pending payment found'}), 404
        
        if approve:
            # Approve payment
            cursor.execute('''
                UPDATE current_bills 
                SET status = 'paid'
                WHERE studentPhone = %s AND month = %s
            ''', (phone, month))
            message = 'Payment approved!'
        else:
            # Reject payment
            cursor.execute('''
                DELETE FROM current_bills 
                WHERE studentPhone = %s AND month = %s
            ''', (phone, month))
            message = 'Payment rejected!'
        
        conn.commit()
        
        return jsonify({
            'success': True,
            'message': message
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    
    # ==================== ADD THIS TO YOUR app.py ====================
# Add this route around line 1350 (after the other current-bill routes)

@app.route('/api/current-bills/pending', methods=['GET'])
@require_admin
def get_pending_current_bills():
    """Get all pending current bill verifications for admin"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get all pending verifications with student details
        cursor.execute('''
            SELECT cb.studentPhone, cb.amount, cb.month, cb.paymentDate, 
                   cb.paymentProof, s.fullName, s.roomNumber
            FROM current_bills cb
            JOIN students s ON cb.studentPhone = s.phone
            WHERE cb.status = 'pending_verification'
            ORDER BY cb.paymentDate DESC
        ''')
        
        bills = cursor.fetchall()
        
        return jsonify({
            'success': True,
            'bills': [
                {
                    'phone': b[0],
                    'amount': b[1],
                    'month': b[2],
                    'paymentDate': b[3],
                    'paymentProof': b[4],
                    'studentName': b[5],
                    'roomNumber': b[6] or 'N/A'
                }
                for b in bills
            ]
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    # ==================== RAZORPAY CURRENT BILL ROUTES ====================

@app.route('/api/current-bill/create-razorpay-order', methods=['POST'])
def create_razorpay_order_current_bill():
    """Create Razorpay order for current bill payment"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if not razorpay_client:
            return jsonify({
                'success': False,
                'message': 'Razorpay not configured. Please use UPI payment option.'
            }), 400
        
        data = request.json
        phone = data.get('phone')
        amount = data.get('amount', 200)  # Current bill amount
        
        if not phone:
            return jsonify({'success': False, 'message': 'Phone required'}), 400
        
        
        # Get student details
        cursor.execute('SELECT fullName, email, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        student_email = student[1]
        room_number = student[2] or 'N/A'
        
        # Create Razorpay order
        order_data = {
            'amount': amount * 100,  # Razorpay expects amount in paise (â‚¹200 = 20000 paise)
            'currency': 'INR',
            'receipt': f'current_bill_{phone}_{int(datetime.now().timestamp())}',
            'notes': {
                'student_name': student_name,
                'student_phone': phone,
                'room_number': room_number,
                'bill_type': 'current_bill',
                'month': datetime.now().strftime('%b-%Y')
            }
        }
        
        razorpay_order = razorpay_client.order.create(data=order_data)
        
        return jsonify({
            'success': True,
            'order_id': razorpay_order['id'],
            'amount': amount,
            'currency': 'INR',
            'key_id': RAZORPAY_KEY_ID,
            'student_name': student_name,
            'student_email': student_email,
            'student_phone': phone
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Razorpay order creation error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/current-bill/verify-razorpay-payment', methods=['POST'])
def verify_razorpay_current_bill_payment():
    """Verify Razorpay payment signature and record payment"""
    try:
        if not razorpay_client:
            return jsonify({'success': False, 'message': 'Razorpay not configured'}), 400
        
        data = request.json
        phone = data.get('phone')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_signature = data.get('razorpay_signature')
        
        if not all([phone, razorpay_order_id, razorpay_payment_id, razorpay_signature]):
            return jsonify({'success': False, 'message': 'Missing payment details'}), 400
        
        # Verify payment signature
        try:
            razorpay_client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            })
        except Exception as e:
           if 'conn' in locals():
            conn.rollback()
            print(f'âŒ Payment signature verification failed: {str(e)}')
            return jsonify({
                'success': False,
                'message': 'Payment verification failed. Please contact support.'
            }), 400
        
        # Payment verified! Record in database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get student details
        cursor.execute('SELECT fullName, roomNumber FROM students WHERE phone = %s', (phone,))
        student = cursor.fetchone()
        
        if not student:
            return jsonify({'success': False, 'message': 'Student not found'}), 404
        
        student_name = student[0]
        room_number = student[1] or 'N/A'
        
        month = datetime.now().strftime('%b-%Y')
        
        # Check if already paid
        cursor.execute('''
            SELECT * FROM current_bills 
            WHERE studentPhone = %s AND month = %s
        ''', (phone, month))
        
        if cursor.fetchone():
            return jsonify({
                'success': False,
                'message': 'Bill already paid for this month'
            }), 400
        
        # Record payment as PAID (Razorpay verified!)
        cursor.execute('''
            INSERT INTO current_bills (studentPhone, amount, month, paymentDate, status)
            VALUES (%s, %s, %s, %s, %s)
        ''', (phone, 200, month, datetime.now().strftime('%d-%b-%Y'), 'paid'))
        
        conn.commit()
        
        # Notify owner
        notify_owner_payment(student_name, phone, room_number, 200, 'Current Bill (Razorpay - Verified)')
        
        return jsonify({
            'success': True,
            'message': 'Payment verified and recorded successfully!',
            'payment_id': razorpay_payment_id
        }), 200
        
    except Exception as e:

        
        if 'conn' in locals():
            conn.rollback()
        print(f'âŒ Razorpay verification error: {str(e)}')
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500
if __name__ == '__main__':
    print("ðŸš€ Starting AR PG Backend Server...")
    print("ðŸ“ Server running at: http://localhost:5000")
    print("ðŸ”— DB Pool: min=2, max=20 connections (supports 500+ concurrent users)")
    print("ðŸ›‘ Press CTRL+C to stop")
    if DEBUG_MODE:
        print("âš ï¸ Running in DEBUG mode")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("âœ… Running in PRODUCTION mode")
        from waitress import serve
        serve(app, host='0.0.0.0', port=5000, threads=20)
