from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from concurrent.futures import ThreadPoolExecutor
from psycopg2 import pool as psycopg2_pool
import json
import random
import re
import base64
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
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)
# ADD this right after the limiter definition:
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'success': False,
        'message': 'Too many attempts. Please wait 1 minute and try again.'
    }), 429
    
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
    print("⚠️ Twilio not installed. SMS features will be disabled.")

# CORS origins — reads from ALLOWED_ORIGINS env var, falls back to safe defaults
_raw_origins = os.getenv(
    'ALLOWED_ORIGINS',
    'https://myarpg.in,https://www.myarpg.in,http://localhost:5000,http://127.0.0.1:5000,https://pg-website2.onrender.com,http://127.0.0.1:5500'
)
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(',') if o.strip()]
print(f"✅ CORS allowed origins: {ALLOWED_ORIGINS}")

CORS(app, resources={
    r"/api/*": {
        "origins": ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": False
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
        
        # Ensure new feature tables exist
        create_new_features_tables()
    except Exception as e:
        print(f"❌ Database pool init failed: {e}")
        DB_POOL = None
        raise

    return DB_POOL

def create_new_features_tables():
    """Ensure student_contracts and student_documents tables exist (and are up to date)."""
    global DB_POOL
    if DB_POOL is None:
        print("⚠️ Database pool not initialized. Cannot create features tables.")
        return
    conn = None
    try:
        conn = DB_POOL.getconn()
        cursor = conn.cursor()
        
        # Create student_contracts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS student_contracts (
                id SERIAL PRIMARY KEY,
                student_phone VARCHAR(20) NOT NULL UNIQUE,
                father_name VARCHAR(100) NOT NULL,
                aadhar_number VARCHAR(20),
                father_aadhar VARCHAR(20),
                passport_photo TEXT,
                admission_date VARCHAR(50) NOT NULL,
                duration_months INTEGER NOT NULL,
                monthly_rent INTEGER NOT NULL,
                security_deposit INTEGER NOT NULL,
                home_address TEXT NOT NULL,
                signature_data TEXT NOT NULL,
                signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''');
        
        # Ensure new columns exist on already created tables
        cursor.execute("ALTER TABLE student_contracts ADD COLUMN IF NOT EXISTS aadhar_number VARCHAR(20);")
        cursor.execute("ALTER TABLE student_contracts ADD COLUMN IF NOT EXISTS father_aadhar VARCHAR(20);")
        cursor.execute("ALTER TABLE student_contracts ADD COLUMN IF NOT EXISTS passport_photo TEXT;")
        
        # Create student_documents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS student_documents (
                id SERIAL PRIMARY KEY,
                student_phone VARCHAR(20) NOT NULL,
                doc_name VARCHAR(100) NOT NULL,
                doc_type VARCHAR(50) NOT NULL,
                doc_data TEXT NOT NULL,
                file_name VARCHAR(255),
                file_size BIGINT DEFAULT 0,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) DEFAULT 'pending'
            )
        ''');

        # Backfill columns for tables created before file_name/file_size existed
        cursor.execute('''
            ALTER TABLE student_documents
            ADD COLUMN IF NOT EXISTS file_name VARCHAR(255)
        ''')
        cursor.execute('''
            ALTER TABLE student_documents
            ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0
        ''')
        
        conn.commit()
        print("✅ New features tables checked/created successfully!")
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"⚠️ Warning: Error creating new feature tables: {e}")
    finally:
        if conn and DB_POOL:
            try:
                DB_POOL.putconn(conn)
            except Exception:
                pass

# Eagerly initialize DB pool at startup to eliminate lag on first request
try:
    init_db_pool()
except Exception as _e:
    print(f"⚠️ Eager database pool initialization skipped/failed: {_e}. (Will retry on first request)")

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
        print("✅ Twilio SMS enabled!")
    except Exception as e:
        print(f"⚠️ Twilio initialization failed: {str(e)}")
else:
    print("⚠️ Twilio SMS disabled (not installed or credentials not found)")

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

        print(f"✅ Email sent to {recipient_email}")
        return True
    except Exception as e:
        print(f"❌ Error sending email: {str(e)}")
        return False

def send_payment_reminder_email(student_name, student_email, amount, due_date):
    """Send payment reminder email"""
    subject = f"Payment Reminder - AR PG Monthly Rent Due"
    
    body = f"""
    <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px;">
                <h2>💳 Payment Reminder</h2>
            </div>
            
            <div style="padding: 20px; background: #f9f9f9;">
                <p>Hello <strong>{student_name}</strong>,</p>
                
                <p>This is a friendly reminder that your monthly rent payment is due.</p>
                
                <div style="background: white; padding: 15px; border-left: 4px solid #667eea; margin: 20px 0;">
                    <p><strong>Payment Details:</strong></p>
                    <p>💰 <strong>Amount:</strong> ₹{amount}</p>
                    <p>📅 <strong>Due Date:</strong> {due_date}</p>
                    <p>🏢 <strong>PG Name:</strong> AR PG</p>
                </div>
                
                <p><strong>Payment Methods:</strong></p>
                <ul>
                    <li>💳 Online Payment (Credit/Debit Card, UPI)</li>
                    <li>🏦 Bank Transfer</li>
                    <li>📱 Mobile Wallet</li>
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
                <h2>📢 {announcement_title}</h2>
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
            print("❌ Twilio not configured")
            return False
        
        # Format phone number (add country code if needed)
        if not phone_number.startswith('+'):
            phone_number = '+91' + phone_number  # India country code
        
        message_obj = twilio_client.messages.create(
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number,
            body=message
        )
        
        print(f"✅ SMS sent to {phone_number}: {message_obj.sid}")
        return True
    except Exception as e:
        print(f"❌ Error sending SMS: {str(e)}")
        return False

def send_payment_reminder_sms(student_name, phone_number, amount, due_date):
    """Send payment reminder SMS"""
    message = f"Hi {student_name}, Your monthly rent of ₹{amount} is due on {due_date}. Please pay at your earliest. AR PG Management"
    return send_sms(phone_number, message)

def send_announcement_sms(student_name, phone_number, announcement):
    """Send announcement SMS"""
    message = f"Hi {student_name}, {announcement} - AR PG Management"
    return send_sms(phone_number, message)

def notify_owner_payment(student_name, student_phone, room_number, amount, payment_method='Online'):
    """Notify owner when student makes payment"""
    try:
        # Send SMS to owner
        sms_message = f"PAYMENT RECEIVED!\nStudent: {student_name}\nPhone: {student_phone}\nRoom: {room_number}\nAmount: ₹{amount}\nMethod: {payment_method}\nDate: {datetime.now().strftime('%d-%b-%Y %H:%M')}"
        
        sms_sent = False
        if twilio_client and OWNER_PHONE:
            sms_sent = send_sms(OWNER_PHONE, sms_message)
        
        # Send email to owner
        email_subject = f"💰 Payment Received - {student_name}"
        email_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <div style="background: linear-gradient(135deg, #27ae60 0%, #229954 100%); color: white; padding: 20px; border-radius: 10px;">
                    <h2>💰 Payment Received!</h2>
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
                                <td style="padding: 8px; color: #27ae60; font-weight: bold; font-size: 1.2em;">₹{amount}</td>
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
            print(f"✅ Owner notified about payment from {student_name}")
            return True
        else:
            print(f"⚠️  Failed to notify owner about payment")
            return False
            
    except Exception as e:
        print(f"❌ Error notifying owner: {str(e)}")
        return False

@app.before_request
def handle_preflight():
    """Handle CORS preflight requests explicitly so OPTIONS never gets blocked."""
    if request.method == "OPTIONS":
        origin = request.headers.get('Origin', '')
        response = jsonify({'status': 'ok'})
        if origin in ALLOWED_ORIGINS:
            response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response, 200

# init_db() — removed: tables are managed directly in PostgreSQL

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
            monthly_rent
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
        identifier = data.get('phone') or data.get('identifier') or data.get('email')
        password = data.get('password')

        if not identifier or not password:
            return jsonify({'success': False, 'message': 'Email/Phone and password are required'}), 400


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

# ==================== STUDENT CONTRACT ROUTES ====================

@app.route('/api/student/<phone>/contract', methods=['POST'])
def save_student_contract(phone):
    """Save student contract details and signature.
    Matches the payload sent by contract.html / dashboard.html saveContract():
    father_name, admission_date, duration_months, monthly_rent, security_deposit,
    home_address, signature_data
    """
    try:
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid student phone number!'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify student exists
        cursor.execute('SELECT phone FROM students WHERE phone = %s', (phone,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
            
        data = request.get_json(silent=True) or {}
        father_name = data.get('father_name')
        aadhar_number = data.get('aadhar_number')
        father_aadhar = data.get('father_aadhar')
        passport_photo = data.get('passport_photo')
        admission_date = data.get('admission_date')
        duration_months = int(data.get('duration_months', 12))
        monthly_rent = int(data.get('monthly_rent', 8500))
        security_deposit = int(data.get('security_deposit', 17000))
        home_address = data.get('home_address')
        signature_data = data.get('signature_data') # base64 string

        if not all([father_name, admission_date, home_address, signature_data]):
            return jsonify({'success': False, 'message': 'Missing required contract fields!'}), 400
            
        # Enforce one-time contract submission per student.
        # Any edits must happen by deleting the previous contract first.
        cursor.execute('SELECT id FROM student_contracts WHERE student_phone = %s', (phone,))
        existing_contract = cursor.fetchone()
        if existing_contract:
            return jsonify({
                'success': False,
                'message': 'Contract already exists. Please delete the previous contract before making changes.'
            }), 409

        cursor.execute('''
            INSERT INTO student_contracts 
            (student_phone, father_name, aadhar_number, father_aadhar, passport_photo, admission_date, duration_months, monthly_rent, security_deposit, home_address, signature_data, signed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        ''', (phone, father_name, aadhar_number, father_aadhar, passport_photo, admission_date, duration_months, monthly_rent, security_deposit, home_address, signature_data))

        # Keep the students table in sync so /api/student/<phone> and admin views reflect the latest rent/deposit agreed in the contract
        cursor.execute('''
            UPDATE students SET monthlyRent = %s WHERE phone = %s
        ''', (monthly_rent, phone))
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Contract signed and saved successfully!'}), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"❌ Error saving contract: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/student/<phone>/contract', methods=['DELETE'])
def delete_student_contract(phone):
    """Delete an existing student contract so a corrected one can be submitted."""
    try:
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid student phone number!'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM student_contracts WHERE student_phone = %s', (phone,))
        existing_contract = cursor.fetchone()
        if not existing_contract:
            return jsonify({'success': False, 'message': 'No contract found to delete.'}), 404

        cursor.execute('DELETE FROM student_contracts WHERE student_phone = %s', (phone,))
        conn.commit()

        return jsonify({'success': True, 'message': 'Previous contract deleted successfully.'}), 200

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/student/<phone>/contract', methods=['GET'])
def get_student_contract(phone):
    """Fetch student contract details"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT father_name, aadhar_number, father_aadhar, passport_photo, admission_date, duration_months, monthly_rent, security_deposit, home_address, signature_data, signed_at 
            FROM student_contracts WHERE student_phone = %s
        ''', (phone,))
        
        row = cursor.fetchone()
        if row:
            return jsonify({
                'success': True,
                'contract': {
                    'father_name': row[0],
                    'aadhar_number': row[1],
                    'father_aadhar': row[2],
                    'passport_photo': row[3],
                    'admission_date': row[4],
                    'duration_months': row[5],
                    'monthly_rent': row[6],
                    'security_deposit': row[7],
                    'home_address': row[8],
                    'signature_data': row[9],
                    'signed_at': row[10].strftime('%d-%b-%Y %I:%M %p') if row[10] else 'N/A'
                }
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Contract not signed yet!'}), 404
            
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# ==================== STUDENT DOCUMENTS ROUTES ====================

def parse_data_url(data_url):
    """Parse a base64 data URL (e.g. 'data:image/png;base64,AAAA...') and
    return (mime_type, file_extension, approximate_size_in_bytes).
    Falls back gracefully if the string isn't a well-formed data URL.
    """
    if not data_url:
        return None, 'dat', 0

    match = re.match(r'^data:([^;,]+);base64,(.+)$', data_url, re.DOTALL)
    if not match:
        # Not a recognizable data URL — just estimate size from raw length
        return None, 'dat', len(data_url)

    mime = match.group(1).strip().lower()
    b64data = match.group(2)

    # Approximate decoded byte size from base64 length (accounting for padding)
    padding = b64data.count('=')
    size = max(0, int(len(b64data) * 3 / 4) - padding)

    ext_map = {
        'application/pdf': 'pdf',
        'image/jpeg': 'jpg',
        'image/jpg': 'jpg',
        'image/png': 'png',
        'image/webp': 'webp',
    }
    ext = ext_map.get(mime, 'dat')
    return mime, ext, size


def build_document_file_name(doc_name, ext):
    """Build a safe, human-friendly file name from the document name + detected extension."""
    base = (doc_name or 'document').strip()
    base = re.sub(r'\s+', '_', base)
    base = re.sub(r'[^A-Za-z0-9_\-\.]', '', base) or 'document'
    return f"{base}.{ext or 'dat'}"


@app.route('/api/student/<phone>/documents', methods=['POST'])
def upload_student_document(phone):
    """Upload a student document.
    Accepts: doc_name, doc_type, doc_data (base64 data URL) — exactly what
    upload-documents.html / dashboard.html's uploadDocument() sends.
    Derives file_name & file_size server-side from the base64 payload so the
    frontend document cards (PDF vs image icon, file size, file name) render correctly.
    """
    try:
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid student phone number!'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify student exists
        cursor.execute('SELECT phone FROM students WHERE phone = %s', (phone,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
            
        data = request.get_json(silent=True) or {}
        doc_name = (data.get('doc_name') or '').strip()
        doc_type = (data.get('doc_type') or '').strip()
        doc_data = data.get('doc_data') # base64 file data URL or string
        
        if not all([doc_name, doc_type, doc_data]):
            return jsonify({'success': False, 'message': 'Missing required document fields!'}), 400

        # 10 MB upload limit, matching the frontend's validation
        mime, ext, file_size = parse_data_url(doc_data)
        max_size = 10 * 1024 * 1024
        if file_size > max_size:
            return jsonify({'success': False, 'message': 'File exceeds the 10 MB limit!'}), 400

        file_name = build_document_file_name(doc_name, ext)

        cursor.execute('''
            INSERT INTO student_documents (student_phone, doc_name, doc_type, doc_data, file_name, file_size, uploaded_at, status)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), 'pending')
            RETURNING id
        ''', (phone, doc_name, doc_type, doc_data, file_name, file_size))

        new_id = cursor.fetchone()[0]
        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Document uploaded successfully!',
            'document': {
                'id': new_id,
                'doc_name': doc_name,
                'doc_type': doc_type,
                'file_name': file_name,
                'file_size': file_size,
                'status': 'pending'
            }
        }), 201
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"❌ Error uploading document: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/student/<phone>/documents', methods=['GET'])
def get_student_documents(phone):
    """Fetch all uploaded documents for a student (metadata only, no base64 payload)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, doc_name, doc_type, uploaded_at, status, file_name, file_size
            FROM student_documents WHERE student_phone = %s
            ORDER BY uploaded_at DESC
        ''', (phone,))
        
        rows = cursor.fetchall()
        documents = [
            {
                'id': row[0],
                'doc_name': row[1],
                'doc_type': row[2],
                'uploaded_at': row[3].isoformat() if row[3] else None,
                'uploaded_at_display': row[3].strftime('%d-%b-%Y %I:%M %p') if row[3] else 'N/A',
                'status': row[4],
                'file_name': row[5] or build_document_file_name(row[1], 'dat'),
                'file_size': row[6] or 0
            }
            for row in rows
        ]
        
        return jsonify({'success': True, 'documents': documents}), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/student/<phone>/documents/<int:doc_id>', methods=['DELETE', 'OPTIONS'])
def delete_student_document(phone, doc_id):
    """Delete a student document"""
    if request.method == 'OPTIONS':
        return '', 200
        
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify document ownership
        cursor.execute('SELECT id FROM student_documents WHERE id = %s AND student_phone = %s', (doc_id, phone))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Document not found or unauthorized!'}), 404
            
        cursor.execute('DELETE FROM student_documents WHERE id = %s', (doc_id,))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'Document deleted successfully!'}), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/student/<phone>/documents/<int:doc_id>/content', methods=['GET'])
def get_document_content(phone, doc_id):
    """Retrieve base64 content of document (used by View/Download buttons)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT doc_data, doc_name, doc_type, file_name, file_size
            FROM student_documents WHERE id = %s AND student_phone = %s
        ''', (doc_id, phone))
        row = cursor.fetchone()
        
        if row:
            return jsonify({
                'success': True,
                'doc_data': row[0],
                'doc_name': row[1],
                'doc_type': row[2],
                'file_name': row[3] or build_document_file_name(row[1], 'dat'),
                'file_size': row[4] or 0
            }), 200
        else:
            return jsonify({'success': False, 'message': 'Document not found!'}), 404
            
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/student/<phone>/screenshots', methods=['POST'])
def upload_student_screenshot(phone):
    """Upload a payment screenshot for a student."""
    try:
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid student phone number!'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify student exists
        cursor.execute('SELECT phone FROM students WHERE phone = %s', (phone,))
        if not cursor.fetchone():
            return jsonify({'success': False, 'message': 'Student not found!'}), 404
            
        data = request.get_json(silent=True) or {}
        doc_name = (data.get('doc_name') or '').strip()
        doc_data = data.get('doc_data') # base64 file data URL or string
        
        if not all([doc_name, doc_data]):
            return jsonify({'success': False, 'message': 'Missing required document fields!'}), 400

        # 10 MB upload limit
        mime, ext, file_size = parse_data_url(doc_data)
        max_size = 10 * 1024 * 1024
        if file_size > max_size:
            return jsonify({'success': False, 'message': 'File exceeds the 10 MB limit!'}), 400

        file_name = build_document_file_name(doc_name, ext)

        cursor.execute('''
            INSERT INTO student_documents (student_phone, doc_name, doc_type, doc_data, file_name, file_size, uploaded_at, status)
            VALUES (%s, %s, 'screenshot', %s, %s, %s, NOW(), 'pending')
            RETURNING id
        ''', (phone, doc_name, doc_data, file_name, file_size))

        new_id = cursor.fetchone()[0]
        conn.commit()
        return jsonify({
            'success': True,
            'message': 'Screenshot uploaded successfully!',
            'document': {
                'id': new_id,
                'doc_name': doc_name,
                'doc_type': 'screenshot',
                'file_name': file_name,
                'file_size': file_size,
                'status': 'pending'
            }
        }), 201
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"❌ Error uploading screenshot: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/student/<phone>/screenshots', methods=['GET'])
def get_student_screenshots(phone):
    """Fetch all screenshots for a student."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, doc_name, doc_type, uploaded_at, status, file_name, file_size
            FROM student_documents 
            WHERE student_phone = %s AND doc_type = 'screenshot'
            ORDER BY uploaded_at DESC
        ''', (phone,))
        
        rows = cursor.fetchall()
        documents = [
            {
                'id': row[0],
                'doc_name': row[1],
                'doc_type': row[2],
                'uploaded_at': row[3].isoformat() if row[3] else None,
                'uploaded_at_display': row[3].strftime('%d-%b-%Y %I:%M %p') if row[3] else 'N/A',
                'status': row[4],
                'file_name': row[5] or build_document_file_name(row[1], 'dat'),
                'file_size': row[6] or 0
            }
            for row in rows
        ]
        
        return jsonify({'success': True, 'screenshots': documents}), 200
        
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
                    'monthlyRent': s[6],
                    'roomType': s[7] 
                }
                for s in students
            ]
        }), 200
    
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/contracts', methods=['GET'])
@require_admin
def get_admin_contracts():
    """Get all student contracts for admin dashboard (list view)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                c.student_phone,
                s.fullName,
                s.email,
                c.father_name,
                c.admission_date,
                c.duration_months,
                c.monthly_rent,
                c.security_deposit,
                c.home_address,
                c.signed_at
            FROM student_contracts c
            LEFT JOIN students s ON s.phone = c.student_phone
            ORDER BY c.signed_at DESC NULLS LAST
        ''')

        rows = cursor.fetchall()
        contracts = [
            {
                'student_phone': row[0],
                'student_name': row[1] or 'N/A',
                'student_email': row[2] or 'N/A',
                'father_name': row[3],
                'admission_date': row[4],
                'duration_months': row[5],
                'monthly_rent': row[6],
                'security_deposit': row[7],
                'home_address': row[8],
                'signed_at': row[9].isoformat() if row[9] else None,
                'signed_at_display': row[9].strftime('%d-%b-%Y %I:%M %p') if row[9] else 'N/A'
            }
            for row in rows
        ]

        return jsonify({'success': True, 'contracts': contracts}), 200

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/contracts/<phone>', methods=['GET'])
@require_admin
def get_admin_contract_detail(phone):
    """Get full contract details (including signature) for one student."""
    try:
        if not phone or not phone.isdigit() or len(phone) != 10:
            return jsonify({'success': False, 'message': 'Invalid student phone number!'}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT 
                c.student_phone,
                s.fullName,
                s.email,
                c.father_name,
                c.aadhar_number,
                c.father_aadhar,
                c.passport_photo,
                c.admission_date,
                c.duration_months,
                c.monthly_rent,
                c.security_deposit,
                c.home_address,
                c.signature_data,
                c.signed_at
            FROM student_contracts c
            LEFT JOIN students s ON s.phone = c.student_phone
            WHERE c.student_phone = %s
            LIMIT 1
        ''', (phone,))

        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Contract not found!'}), 404

        return jsonify({
            'success': True,
            'contract': {
                'student_phone': row[0],
                'student_name': row[1] or 'N/A',
                'student_email': row[2] or 'N/A',
                'father_name': row[3],
                'aadhar_number': row[4],
                'father_aadhar': row[5],
                'passport_photo': row[6],
                'admission_date': row[7],
                'duration_months': row[8],
                'monthly_rent': row[9],
                'security_deposit': row[10],
                'home_address': row[11],
                'signature_data': row[12],
                'signed_at': row[13].isoformat() if row[13] else None,
                'signed_at_display': row[13].strftime('%d-%b-%Y %I:%M %p') if row[13] else 'N/A'
            }
        }), 200

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/documents', methods=['GET'])
@require_admin
def get_admin_documents():
    """Get all uploaded student documents for admin dashboard."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                d.id,
                d.student_phone,
                s.fullName,
                s.email,
                d.doc_name,
                d.doc_type,
                d.uploaded_at,
                d.status,
                d.file_name,
                d.file_size
            FROM student_documents d
            LEFT JOIN students s ON s.phone = d.student_phone
            ORDER BY d.uploaded_at DESC NULLS LAST
        ''')

        rows = cursor.fetchall()
        documents = [
            {
                'id': row[0],
                'student_phone': row[1],
                'student_name': row[2] or 'N/A',
                'student_email': row[3] or 'N/A',
                'doc_name': row[4],
                'doc_type': row[5],
                'uploaded_at': row[6].isoformat() if row[6] else None,
                'uploaded_at_display': row[6].strftime('%d-%b-%Y %I:%M %p') if row[6] else 'N/A',
                'status': row[7] or 'pending',
                'file_name': row[8] or build_document_file_name(row[4], 'dat'),
                'file_size': row[9] or 0
            }
            for row in rows
        ]

        return jsonify({'success': True, 'documents': documents}), 200

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/screenshots', methods=['GET'])
@require_admin
def get_admin_screenshots():
    """Get all uploaded student screenshots for admin dashboard."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                d.id,
                d.student_phone,
                s.fullName,
                s.email,
                d.doc_name,
                d.doc_type,
                d.uploaded_at,
                d.status,
                d.file_name,
                d.file_size
            FROM student_documents d
            LEFT JOIN students s ON s.phone = d.student_phone
            WHERE d.doc_type = 'screenshot'
            ORDER BY d.uploaded_at DESC NULLS LAST
        ''')

        rows = cursor.fetchall()
        documents = [
            {
                'id': row[0],
                'student_phone': row[1],
                'student_name': row[2] or 'N/A',
                'student_email': row[3] or 'N/A',
                'doc_name': row[4],
                'doc_type': row[5],
                'uploaded_at': row[6].isoformat() if row[6] else None,
                'uploaded_at_display': row[6].strftime('%d-%b-%Y %I:%M %p') if row[6] else 'N/A',
                'status': row[7] or 'pending',
                'file_name': row[8] or build_document_file_name(row[4], 'dat'),
                'file_size': row[9] or 0
            }
            for row in rows
        ]

        return jsonify({'success': True, 'screenshots': documents}), 200

    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/screenshots/<int:doc_id>', methods=['DELETE', 'OPTIONS'])
@require_admin
def delete_admin_screenshot(doc_id):
    if request.method == 'OPTIONS':
        return '', 200
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM student_documents WHERE id = %s AND doc_type = \'screenshot\'', (doc_id,))
        conn.commit()
        return jsonify({'success': True, 'message': 'Screenshot deleted successfully!'}), 200
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/documents/<int:doc_id>/content', methods=['GET'])
@require_admin
def get_admin_document_content(doc_id):
    """Get base64 content of a student document by document id (admin only)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            SELECT
                d.doc_data,
                d.doc_name,
                d.doc_type,
                d.file_name,
                d.file_size,
                d.student_phone,
                s.fullName
            FROM student_documents d
            LEFT JOIN students s ON s.phone = d.student_phone
            WHERE d.id = %s
            LIMIT 1
        ''', (doc_id,))

        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Document not found!'}), 404

        return jsonify({
            'success': True,
            'document': {
                'doc_data': row[0],
                'doc_name': row[1],
                'doc_type': row[2],
                'file_name': row[3] or build_document_file_name(row[1], 'dat'),
                'file_size': row[4] or 0,
                'student_phone': row[5],
                'student_name': row[6] or 'N/A'
            }
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
                    <h2>🏠 Welcome to AR PG!</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{student_name}</strong>,</p>
                    
                    <p>Your account has been created by the admin. Here are your login details:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0;">
                        <p><strong>Email/Phone:</strong> {student_email}</p>
                        <p><strong>Temporary Password:</strong> <span style="font-size: 1.3em; color: #667eea; font-weight: bold;">{random_password}</span></p>
                    </div>
                    
                    <p><strong>⚠️ Important:</strong></p>
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
        print(f'❌ Mark paid error: {str(e)}')
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
        
        print(f"✅ Student {data.get('fullName')} updated successfully")
        
        return jsonify({
            'success': True,
            'message': f'Student {data.get("fullName")} updated successfully'
        })
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f'❌ Update student error: {str(e)}')
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

        # Delete student's contract & documents too, so deleting a student fully cleans up
        cursor.execute('DELETE FROM student_contracts WHERE student_phone = %s', (phone,))
        cursor.execute('DELETE FROM student_documents WHERE student_phone = %s', (phone,))
        
        # Delete the student
        cursor.execute('DELETE FROM students WHERE phone = %s', (phone,))
        
        conn.commit()
        
        print(f"✅ Student deleted: {student_name} ({phone})")
        
        return jsonify({
            'success': True,
            'message': f'Student {student_name} deleted successfully'
        }), 200
        
    except Exception as e:
        if 'conn' in locals():
            conn.rollback()
        print(f"❌ Error deleting student: {str(e)}")
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
                    <h2>🔐 Password Reset Request</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>{student_name}</strong>,</p>
                    
                    <p>We received a request to reset your AR PG password. Use the code below to continue:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0; text-align: center;">
                        <h1 style="color: #667eea; font-size: 2.5em; letter-spacing: 6px; margin: 10px 0;">{code}</h1>
                        <p style="color: #999; font-size: 0.9em;">This code is valid for 10 minutes.</p>
                    </div>
                    
                    <p><strong>⚠️ Security tips:</strong></p>
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
    return jsonify({'success': True, 'message': 'Backend is running! ✅'}), 200

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


# ✅ NEW route for Admin Dashboard to view inquiries
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

@app.route('/student/contract.html')
def contract_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'contract.html')

@app.route('/student/upload-documents.html')
def upload_documents_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'upload-documents.html')


@app.route('/student/upload-screenshots.html')
def upload_screenshots_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'student'), 'upload-screenshots.html')


@app.route('/admin/upload-screenshots.html')
def admin_upload_screenshots_page():
    return send_from_directory(os.path.join(PARENT_DIR, 'admin'), 'upload-screenshots.html')

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




# ✅ Serve static files (CSS, JS, images)
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
                    <h2>🔐 Admin Password Reset Request</h2>
                </div>
                
                <div style="padding: 20px; background: #f9f9f9;">
                    <p>Hello <strong>Admin</strong>,</p>
                    
                    <p>We received a request to reset your admin password. Use the code below:</p>
                    
                    <div style="background: white; padding: 20px; border-left: 4px solid #3a2e8a; margin: 20px 0; text-align: center;">
                        <h1 style="color: #3a2e8a; font-size: 2.5em; letter-spacing: 6px; margin: 10px 0;">{code}</h1>
                        <p style="color: #999; font-size: 0.9em;">This code is valid for 10 minutes.</p>
                    </div>
                    
                    <p><strong>⚠️ Security Alert:</strong></p>
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
        print(f"❌ Error in admin login: {str(e)}")
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
        print(f'❌ Error fetching bills: {str(e)}')
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
                    <h2>⚡ Current Bill - {month}</h2>
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
                                <td style="padding: 8px; color: #667eea; font-weight: bold; font-size: 1.2em;">₹200</td>
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
                        <li>Monthly Electricity Charge: ₹200</li>
                        <li>Includes: Room lighting, fan, charging points</li>
                        <li>Late Fee: ₹50 per day after due date</li>
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
        print(f'❌ Email error: {str(e)}')
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

if __name__ == '__main__':
    print("🚀 Starting AR PG Backend Server...")
    print("📍 Server running at: http://localhost:5000")
    print("🔗 DB Pool: min=2, max=20 connections (supports 500+ concurrent users)")
    print("🛑 Press CTRL+C to stop")
    if DEBUG_MODE:
        print("⚠️ Running in DEBUG mode")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("✅ Running in PRODUCTION mode")
        from waitress import serve
        port = int(os.environ.get('PORT', 10000))
        serve(app, host='0.0.0.0', port=port, threads=20)