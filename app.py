"""
Complete AES File Encryption and Decryption System
Enhanced with Password Strength Validation and File Integrity Verification
College Project - Full Implementation
Author: Student
Technology: Flask + AES Cryptography + SQLite Database + SHA-256 Hashing
"""

from flask import Flask, render_template, request, send_file, jsonify
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import secrets
import sqlite3
from datetime import datetime
import hashlib
import re

# Initialize Flask App
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
DATABASE_NAME = 'encryption_database.db'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit

# Create necessary folders
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# =============================================================================
# PASSWORD STRENGTH VALIDATION
# =============================================================================

def validate_password_strength(password):
    """
    Validate password strength based on security criteria
    Returns: (is_valid, strength_score, strength_level, messages)
    """
    messages = []
    strength_score = 0
    
    # Check minimum length
    if len(password) < 8:
        messages.append("Password must be at least 8 characters long")
    else:
        strength_score += 20
        if len(password) >= 12:
            strength_score += 10
            messages.append("✓ Good length")
    
    # Check for uppercase letter
    if re.search(r'[A-Z]', password):
        strength_score += 20
        messages.append("✓ Contains uppercase letter")
    else:
        messages.append("Missing uppercase letter (A-Z)")
    
    # Check for lowercase letter
    if re.search(r'[a-z]', password):
        strength_score += 20
        messages.append("✓ Contains lowercase letter")
    else:
        messages.append("Missing lowercase letter (a-z)")
    
    # Check for number
    if re.search(r'\d', password):
        strength_score += 20
        messages.append("✓ Contains number")
    else:
        messages.append("Missing number (0-9)")
    
    # Check for special character
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength_score += 20
        messages.append("✓ Contains special character")
    else:
        messages.append("Missing special character (!@#$%^&*)")
    
    # Additional bonus for very strong passwords
    if len(password) >= 16 and strength_score >= 80:
        strength_score += 10
    
    # Determine strength level
    if strength_score >= 80:
        strength_level = "Strong"
        is_valid = True
    elif strength_score >= 60:
        strength_level = "Medium"
        is_valid = True
    else:
        strength_level = "Weak"
        is_valid = False
    
    return is_valid, strength_score, strength_level, messages

# =============================================================================
# FILE INTEGRITY VERIFICATION (HASHING)
# =============================================================================

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate cryptographic hash of a file for integrity verification"""
    if algorithm == 'sha256':
        hash_func = hashlib.sha256()
    elif algorithm == 'sha512':
        hash_func = hashlib.sha512()
    elif algorithm == 'md5':
        hash_func = hashlib.md5()
    else:
        hash_func = hashlib.sha256()
    
    # Read file in chunks to handle large files
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Create encryption_history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encryption_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_filename TEXT NOT NULL,
            encrypted_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_type TEXT NOT NULL,
            encryption_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            password_hash TEXT NOT NULL,
            password_strength TEXT NOT NULL,
            salt_hex TEXT NOT NULL,
            iv_hex TEXT NOT NULL,
            original_file_hash TEXT NOT NULL,
            encrypted_file_hash TEXT NOT NULL,
            hash_algorithm TEXT DEFAULT 'sha256',
            status TEXT DEFAULT 'active'
        )
    ''')
    
    # Create encryption_stats table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encryption_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_encryptions INTEGER DEFAULT 0,
            total_decryptions INTEGER DEFAULT 0,
            total_files_size INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize stats if not exists
    cursor.execute('SELECT COUNT(*) FROM encryption_stats')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO encryption_stats (total_encryptions, total_decryptions, total_files_size) VALUES (0, 0, 0)')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def add_encryption_record(original_filename, encrypted_filename, file_size, file_type, 
                          password, password_strength, salt, iv, original_hash, encrypted_hash):
    """Add new encryption record to database"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        salt_hex = salt.hex()
        iv_hex = iv.hex()
        
        cursor.execute('''
            INSERT INTO encryption_history 
            (original_filename, encrypted_filename, file_size, file_type, password_hash, 
             password_strength, salt_hex, iv_hex, original_file_hash, encrypted_file_hash, hash_algorithm)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (original_filename, encrypted_filename, file_size, file_type, password_hash, 
              password_strength, salt_hex, iv_hex, original_hash, encrypted_hash, 'sha256'))
        
        cursor.execute('''
            UPDATE encryption_stats 
            SET total_encryptions = total_encryptions + 1,
                total_files_size = total_files_size + ?,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = 1
        ''', (file_size,))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {str(e)}")
        return False

def update_decryption_stats():
    """Update decryption statistics"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE encryption_stats 
            SET total_decryptions = total_decryptions + 1,
                last_updated = CURRENT_TIMESTAMP
            WHERE id = 1
        ''')
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Database error: {str(e)}")
        return False

def get_encryption_history(limit=10):
    """Get recent encryption history"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, original_filename, encrypted_filename, file_size, file_type, 
                   encryption_date, password_strength, original_file_hash, encrypted_file_hash, status
            FROM encryption_history 
            ORDER BY encryption_date DESC 
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        history = []
        for row in results:
            history.append({
                'id': row[0],
                'original_filename': row[1],
                'encrypted_filename': row[2],
                'file_size': row[3],
                'file_type': row[4],
                'encryption_date': row[5],
                'password_strength': row[6],
                'original_file_hash': row[7],
                'encrypted_file_hash': row[8],
                'status': row[9]
            })
        
        return history
    except Exception as e:
        print(f"Database error: {str(e)}")
        return []

def get_encryption_stats():
    """Get encryption statistics"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute('SELECT total_encryptions, total_decryptions, total_files_size FROM encryption_stats WHERE id = 1')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'total_encryptions': result[0],
                'total_decryptions': result[1],
                'total_files_size': result[2],
                'total_files_size_mb': round(result[2] / (1024 * 1024), 2)
            }
        return {'total_encryptions': 0, 'total_decryptions': 0, 'total_files_size': 0, 'total_files_size_mb': 0}
    except Exception as e:
        print(f"Database error: {str(e)}")
        return {'total_encryptions': 0, 'total_decryptions': 0, 'total_files_size': 0, 'total_files_size_mb': 0}

# =============================================================================
# ENCRYPTION/DECRYPTION HELPER FUNCTIONS
# =============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key_from_password(password, salt):
    """Generate AES encryption key from password using PBKDF2HMAC"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_path, password):
    """Encrypt file using AES-256 in CBC mode"""
    try:
        # Calculate original file hash
        original_file_hash = calculate_file_hash(file_path, 'sha256')
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        salt = secrets.token_bytes(16)
        key = generate_key_from_password(password, salt)
        iv = secrets.token_bytes(16)
        
        padding_length = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_length]) * padding_length
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        base_name = os.path.basename(file_path)
        encrypted_filename = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{base_name}.enc"
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        
        with open(encrypted_path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)
        
        encrypted_file_hash = calculate_file_hash(encrypted_path, 'sha256')
        
        return encrypted_path, encrypted_filename, salt, iv, original_file_hash, encrypted_file_hash
    
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_file(file_path, password):
    """Decrypt AES-256 encrypted file"""
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        salt = file_data[:16]
        iv = file_data[16:32]
        ciphertext = file_data[32:]
        
        key = generate_key_from_password(password, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        original_filename = os.path.basename(file_path).replace('encrypted_', '').replace('.enc', '')
        parts = original_filename.split('_')
        if len(parts) >= 3:
            original_filename = '_'.join(parts[2:])
        
        decrypted_path = os.path.join(DECRYPTED_FOLDER, original_filename)
        
        with open(decrypted_path, 'wb') as f:
            f.write(plaintext)
        
        return decrypted_path, original_filename
    
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def cleanup_old_files():
    """Clean up temporary files older than 1 hour"""
    try:
        current_time = datetime.now().timestamp()
        for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    file_age = current_time - os.path.getmtime(file_path)
                    if file_age > 3600:
                        os.remove(file_path)
    except Exception as e:
        print(f"Cleanup error: {str(e)}")

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route('/')
def index():
    """Home page"""
    cleanup_old_files()
    stats = get_encryption_stats()
    return render_template('index.html', stats=stats)

@app.route('/validate-password', methods=['POST'])
def validate_password():
    """API endpoint to validate password strength"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
        
        is_valid, score, level, messages = validate_password_strength(password)
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'strength_score': score,
            'strength_level': level,
            'messages': messages
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    """Encryption page and handler"""
    if request.method == 'GET':
        return render_template('encrypt.html')
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not password or not confirm_password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
        
        if password != confirm_password:
            return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
        
        # Validate password strength
        is_valid, score, level, messages = validate_password_strength(password)
        if not is_valid:
            return jsonify({
                'success': False, 
                'message': 'Password is too weak. Please use a stronger password.',
                'strength_level': level,
                'strength_score': score,
                'validation_messages': messages
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': 'File type not allowed'}), 400
        
        original_filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, original_filename)
        file.save(upload_path)
        
        file_size = os.path.getsize(upload_path)
        file_type = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else 'unknown'
        
        if file_size > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'message': 'File size exceeds 50MB limit'}), 400
        
        encrypted_path, encrypted_filename, salt, iv, original_hash, encrypted_hash = encrypt_file(upload_path, password)
        
        add_encryption_record(
            original_filename, encrypted_filename, file_size, file_type,
            password, level, salt, iv, original_hash, encrypted_hash
        )
        
        os.remove(upload_path)
        
        return jsonify({
            'success': True,
            'message': f'File encrypted successfully with {level} password!',
            'filename': encrypted_filename,
            'download_url': f'/download/encrypted/{encrypted_filename}',
            'password_strength': level,
            'password_score': score,
            'original_file_hash': original_hash,
            'encrypted_file_hash': encrypted_hash,
            'hash_algorithm': 'SHA-256'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    """Decryption page and handler"""
    if request.method == 'GET':
        return render_template('decrypt.html')
    
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
        
        if not file.filename.endswith('.enc'):
            return jsonify({'success': False, 'message': 'Please upload an encrypted file (.enc)'}), 400
        
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        decrypted_path, decrypted_filename = decrypt_file(upload_path, password)
        
        os.remove(upload_path)
        
        update_decryption_stats()
        
        return jsonify({
            'success': True,
            'message': f'File decrypted successfully!',
            'filename': decrypted_filename,
            'download_url': f'/download/decrypted/{decrypted_filename}'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': 'Decryption failed. Wrong password or corrupted file.'}), 400

@app.route('/download/<file_type>/<filename>')
def download(file_type, filename):
    """Download encrypted or decrypted files"""
    try:
        if file_type == 'encrypted':
            file_path = os.path.join(ENCRYPTED_FOLDER, filename)
        elif file_type == 'decrypted':
            file_path = os.path.join(DECRYPTED_FOLDER, filename)
        else:
            return "Invalid file type", 400
        
        if not os.path.exists(file_path):
            return "File not found", 404
        
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        return str(e), 500

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page"""
    if request.method == 'GET':
        return render_template('contact.html')
    
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')
        
        # Here you can add email sending logic or save to database
        
        return jsonify({
            'success': True,
            'message': 'Message sent successfully! We will get back to you soon.'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@app.route('/history')
def history():
    """View encryption history"""
    history_data = get_encryption_history(limit=50)
    stats = get_encryption_stats()
    return render_template('history.html', history=history_data, stats=stats)

@app.route('/api/stats')
def api_stats():
    """API endpoint for statistics"""
    stats = get_encryption_stats()
    return jsonify({'success': True, 'stats': stats})

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    return render_template('index.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("🔐 COMPLETE AES FILE ENCRYPTION & DECRYPTION SYSTEM")
    print("=" * 70)
    print("✅ Encryption")
    print("✅ Decryption")
    print("✅ Password Strength Validation")
    print("✅ File Integrity Verification (SHA-256)")
    print("✅ Database Tracking")
    print("✅ Contact Page")
    print("=" * 70)
    
    init_database()
    
    print("Server starting...")
    print("Navigate to: http://127.0.0.1:5000")
    print("=" * 70)
    
    app.run(debug=True, host='0.0.0.0', port=5000)