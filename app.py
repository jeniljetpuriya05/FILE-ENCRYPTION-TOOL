"""
Secure File Encryption System using AES with Database
Enhanced with Password Strength Validation and File Integrity Verification
College Project - Backend Implementation
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
DATABASE_NAME = 'encryption_database.db'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit

# Create necessary folders
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# =============================================================================
# PASSWORD STRENGTH VALIDATION
# =============================================================================

def validate_password_strength(password):
    """
    Validate password strength based on security criteria
    Returns: (is_valid, strength_score, messages)
    
    Criteria:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
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
        is_valid = True  # Accept medium strength
    else:
        strength_level = "Weak"
        is_valid = False
    
    return is_valid, strength_score, strength_level, messages

# =============================================================================
# FILE INTEGRITY VERIFICATION (HASHING)
# =============================================================================

def calculate_file_hash(file_path, algorithm='sha256'):
    """
    Calculate cryptographic hash of a file for integrity verification
    Supports: SHA-256, SHA-512, MD5
    
    Returns: hex digest of file hash
    """
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

def verify_file_integrity(file_path, expected_hash, algorithm='sha256'):
    """
    Verify file integrity by comparing calculated hash with expected hash
    Returns: (is_valid, calculated_hash)
    """
    calculated_hash = calculate_file_hash(file_path, algorithm)
    is_valid = calculated_hash == expected_hash
    return is_valid, calculated_hash

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Create encryption_history table (enhanced with file hash)
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
            total_files_size INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Initialize stats if not exists
    cursor.execute('SELECT COUNT(*) FROM encryption_stats')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO encryption_stats (total_encryptions, total_files_size) VALUES (0, 0)')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully!")

def add_encryption_record(original_filename, encrypted_filename, file_size, file_type, 
                          password, password_strength, salt, iv, original_hash, encrypted_hash):
    """Add new encryption record to database with file integrity hashes"""
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        # Hash the password for storage
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Convert salt and IV to hex
        salt_hex = salt.hex()
        iv_hex = iv.hex()
        
        # Insert encryption record
        cursor.execute('''
            INSERT INTO encryption_history 
            (original_filename, encrypted_filename, file_size, file_type, password_hash, 
             password_strength, salt_hex, iv_hex, original_file_hash, encrypted_file_hash, hash_algorithm)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (original_filename, encrypted_filename, file_size, file_type, password_hash, 
              password_strength, salt_hex, iv_hex, original_hash, encrypted_hash, 'sha256'))
        
        # Update statistics
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
        
        cursor.execute('SELECT total_encryptions, total_files_size FROM encryption_stats WHERE id = 1')
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return {
                'total_encryptions': result[0],
                'total_files_size': result[1],
                'total_files_size_mb': round(result[1] / (1024 * 1024), 2)
            }
        return {'total_encryptions': 0, 'total_files_size': 0, 'total_files_size_mb': 0}
    except Exception as e:
        print(f"Database error: {str(e)}")
        return {'total_encryptions': 0, 'total_files_size': 0, 'total_files_size_mb': 0}

# =============================================================================
# ENCRYPTION HELPER FUNCTIONS
# =============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key_from_password(password, salt):
    """Generate AES encryption key from password using PBKDF2HMAC"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES-256
        salt=salt,
        iterations=100000,  # High iteration count for security
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt_file(file_path, password):
    """Encrypt file using AES-256 in CBC mode"""
    try:
        # Calculate original file hash BEFORE encryption
        original_file_hash = calculate_file_hash(file_path, 'sha256')
        
        # Read original file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random salt
        salt = secrets.token_bytes(16)
        
        # Generate encryption key from password
        key = generate_key_from_password(password, salt)
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Pad the data to be multiple of 16 bytes
        padding_length = 16 - (len(plaintext) % 16)
        padded_data = plaintext + bytes([padding_length]) * padding_length
        
        # Create AES cipher in CBC mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create encrypted file path
        base_name = os.path.basename(file_path)
        encrypted_filename = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{base_name}.enc"
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)
        
        # Save: salt (16 bytes) + IV (16 bytes) + encrypted data
        with open(encrypted_path, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)
        
        # Calculate encrypted file hash AFTER encryption
        encrypted_file_hash = calculate_file_hash(encrypted_path, 'sha256')
        
        return encrypted_path, encrypted_filename, salt, iv, original_file_hash, encrypted_file_hash
    
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def cleanup_old_files():
    """Clean up temporary files older than 1 hour"""
    try:
        current_time = datetime.now().timestamp()
        for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    file_age = current_time - os.path.getmtime(file_path)
                    if file_age > 3600:  # 1 hour
                        os.remove(file_path)
    except Exception as e:
        print(f"Cleanup error: {str(e)}")

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route('/')
def index():
    """Home page with statistics"""
    cleanup_old_files()
    stats = get_encryption_stats()
    return render_template('index.html', stats=stats)

@app.route('/validate-password', methods=['POST'])
def validate_password():
    """API endpoint to validate password strength in real-time"""
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
        # Get uploaded file
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
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
        
        # Save uploaded file
        original_filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, original_filename)
        file.save(upload_path)
        
        # Get file info
        file_size = os.path.getsize(upload_path)
        file_type = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else 'unknown'
        
        # Check file size
        if file_size > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'message': 'File size exceeds 50MB limit'}), 400
        
        # Encrypt file (returns file hashes too)
        encrypted_path, encrypted_filename, salt, iv, original_hash, encrypted_hash = encrypt_file(upload_path, password)
        
        # Add to database with file integrity hashes
        db_success = add_encryption_record(
            original_filename, 
            encrypted_filename, 
            file_size, 
            file_type,
            password,
            level,  # password strength level
            salt,
            iv,
            original_hash,  # original file hash
            encrypted_hash  # encrypted file hash
        )
        
        # Delete original uploaded file
        os.remove(upload_path)
        
        # Return success response with integrity information
        return jsonify({
            'success': True,
            'message': f'File encrypted successfully with {level} password!',
            'filename': encrypted_filename,
            'download_url': f'/download/{encrypted_filename}',
            'password_strength': level,
            'password_score': score,
            'original_file_hash': original_hash,
            'encrypted_file_hash': encrypted_hash,
            'hash_algorithm': 'SHA-256',
            'database_saved': db_success
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/download/<filename>')
def download(filename):
    """Download encrypted files"""
    try:
        file_path = os.path.join(ENCRYPTED_FOLDER, filename)
        
        if not os.path.exists(file_path):
            return "File not found", 404
        
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        return str(e), 500

@app.route('/verify-integrity/<filename>')
def verify_integrity(filename):
    """Verify file integrity by checking hash"""
    try:
        file_path = os.path.join(ENCRYPTED_FOLDER, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'message': 'File not found'}), 404
        
        # Calculate current hash
        current_hash = calculate_file_hash(file_path, 'sha256')
        
        # Get expected hash from database
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        cursor.execute('SELECT encrypted_file_hash FROM encryption_history WHERE encrypted_filename = ?', (filename,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'success': False, 'message': 'File record not found in database'}), 404
        
        expected_hash = result[0]
        
        # Verify integrity
        is_valid = current_hash == expected_hash
        
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'current_hash': current_hash,
            'expected_hash': expected_hash,
            'message': 'File integrity verified ✓' if is_valid else 'File has been modified! ✗'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

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
    print("🔐 AES FILE ENCRYPTION SYSTEM - ENHANCED VERSION")
    print("=" * 70)
    print("✅ Password Strength Validation")
    print("✅ File Integrity Verification (SHA-256)")
    print("✅ Database Tracking")
    print("=" * 70)
    
    # Initialize database
    init_database()
    
    print("Server starting...")
    print("Navigate to: http://127.0.0.1:5000")
    print("=" * 70)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)