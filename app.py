"""
Secure File Encryption and Decryption System using AES
College Project - Backend Implementation
Author: Student
Technology: Flask + AES Cryptography
"""

from flask import Flask, render_template, request, send_file, jsonify, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import secrets
import shutil
from datetime import datetime

# Initialize Flask App
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Secret key for session management

# Configuration
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'rar'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit

# Create necessary folders
for folder in [UPLOAD_FOLDER, ENCRYPTED_FOLDER, DECRYPTED_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_key_from_password(password, salt):
    """
    Generate AES encryption key from password using PBKDF2HMAC
    - PBKDF2HMAC: Password-Based Key Derivation Function 2 with HMAC
    - Makes brute-force attacks difficult by adding computational cost
    """
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
    """
    Encrypt file using AES-256 in CBC mode
    Steps:
    1. Generate random salt (16 bytes)
    2. Derive key from password + salt
    3. Generate random IV (Initialization Vector)
    4. Encrypt file data
    5. Save: salt + IV + encrypted_data
    """
    try:
        # Read original file
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        # Generate random salt (used for key derivation)
        salt = secrets.token_bytes(16)
        
        # Generate encryption key from password
        key = generate_key_from_password(password, salt)
        
        # Generate random IV (Initialization Vector) for CBC mode
        iv = secrets.token_bytes(16)
        
        # Pad the data to be multiple of 16 bytes (AES block size)
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
        
        return encrypted_path, encrypted_filename
    
    except Exception as e:
        raise Exception(f"Encryption failed: {str(e)}")

def decrypt_file(file_path, password):
    """
    Decrypt AES-256 encrypted file
    Steps:
    1. Read salt + IV + encrypted_data
    2. Derive key from password + salt
    3. Decrypt data using AES-CBC
    4. Remove padding
    5. Save original file
    """
    try:
        # Read encrypted file
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Extract salt (first 16 bytes)
        salt = file_data[:16]
        
        # Extract IV (next 16 bytes)
        iv = file_data[16:32]
        
        # Extract encrypted data (remaining bytes)
        ciphertext = file_data[32:]
        
        # Regenerate key from password and salt
        key = generate_key_from_password(password, salt)
        
        # Create AES cipher in CBC mode
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        # Create decrypted file path
        original_filename = os.path.basename(file_path).replace('encrypted_', '').replace('.enc', '')
        # Remove timestamp from filename
        parts = original_filename.split('_')
        if len(parts) >= 3:
            original_filename = '_'.join(parts[2:])
        
        decrypted_path = os.path.join(DECRYPTED_FOLDER, original_filename)
        
        # Save decrypted file
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
                    if file_age > 3600:  # 1 hour
                        os.remove(file_path)
    except Exception as e:
        print(f"Cleanup error: {str(e)}")

# =============================================================================
# FLASK ROUTES
# =============================================================================

@app.route('/')
def index():
    """Home page"""
    cleanup_old_files()  # Clean old files on page load
    return render_template('index.html')

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
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'success': False, 'message': 'File type not allowed'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        # Check file size
        if os.path.getsize(upload_path) > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'message': 'File size exceeds 50MB limit'}), 400
        
        # Encrypt file
        encrypted_path, encrypted_filename = encrypt_file(upload_path, password)
        
        # Delete original uploaded file
        os.remove(upload_path)
        
        # Return success response
        return jsonify({
            'success': True,
            'message': f'File encrypted successfully!',
            'filename': encrypted_filename,
            'download_url': f'/download/encrypted/{encrypted_filename}'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    """Decryption page and handler"""
    if request.method == 'GET':
        return render_template('decrypt.html')
    
    try:
        # Get uploaded encrypted file
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['file']
        password = request.form.get('password')
        
        # Validation
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        if not password:
            return jsonify({'success': False, 'message': 'Password is required'}), 400
        
        # Check if file is encrypted (.enc extension)
        if not file.filename.endswith('.enc'):
            return jsonify({'success': False, 'message': 'Please upload an encrypted file (.enc)'}), 400
        
        # Save uploaded encrypted file
        filename = secure_filename(file.filename)
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(upload_path)
        
        # Decrypt file
        decrypted_path, decrypted_filename = decrypt_file(upload_path, password)
        
        # Delete uploaded encrypted file
        os.remove(upload_path)
        
        # Return success response
        return jsonify({
            'success': True,
            'message': f'File decrypted successfully!',
            'filename': decrypted_filename,
            'download_url': f'/download/decrypted/{decrypted_filename}'
        })
    
    except Exception as e:
        # Wrong password or corrupted file
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
        # For now, just return success
        
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
    print("=" * 60)
    print("🔐 AES SECURE FILE ENCRYPTION SYSTEM")
    print("=" * 60)
    print("Server starting...")
    print("Navigate to: http://127.0.0.1:5000")
    print("=" * 60)
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)