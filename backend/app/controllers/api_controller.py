import base64
import os
from datetime import datetime, timedelta
import bcrypt
import re
from flask import jsonify, request, send_file, current_app
from app.database.connection import db
from app.models.models import (
    User, File, EncryptionKey, FileClassification, FileSharing,
    ActivityLog, ClassificationHistory, FileIntegrity, IntegrityHistory,
    SecurityAlert, LoginAttempt
)
from app.encryption.aes_engine import generate_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from app.encryption.rsa_engine import generate_rsa_keypair, encrypt_key_rsa, decrypt_key_rsa
from app.encryption.hybrid_engine import encrypt_file_hybrid, decrypt_file_hybrid, encrypt_by_sensitivity, decrypt_by_sensitivity
from app.AI.predict import classify_document
from app.utils.text_extractor import extract_text
from app.utils.integrity import generate_sha256
from app.utils.auth_middleware import encode_auth_token

def record_login_attempt(user_id, email, success, ip_address='0.0.0.0', failure_reason=None):
    """Record authentication attempt to the persistent LoginAttempts table."""
    try:
        attempt = LoginAttempt(
            user_id=user_id,
            email=email or 'unknown',
            success=success,
            ip_address=ip_address or '0.0.0.0',
            attempted_at=datetime.utcnow(),
            failure_reason=failure_reason
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ==========================================
# 1. Auth Controller
# ==========================================

def register_user():
    data = request.get_json() or {}
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not full_name or not email or not password:
        return jsonify({"error": "Missing required fields (full_name, email, password)"}), 400

    if len(full_name.strip()) < 2:
        return jsonify({"error": "Full name must be at least 2 characters long."}), 400

    # Email format regex validation
    email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    if not re.match(email_regex, email):
        return jsonify({"error": "Invalid email format. Please provide a valid email address."}), 400

    # Password strength validation (min 8 chars, mixture of character types)
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[^A-Za-z0-9]', password)):
        return jsonify({"error": "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters."}), 400

    # Reject common/weak passphrases
    common_passwords = ["password", "12345678", "password123", "admin123", "cipherguard", "passphrase"]
    if password.lower() in common_passwords:
        return jsonify({"error": "Password is too common or weak. Please choose a unique passphrase."}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email identifier already registered"}), 409

    # Generate 2048-bit RSA keys for asymmetric cryptography
    private_pem, public_pem = generate_rsa_keypair(2048)

    # Hash passphrases using bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    new_user = User(
        full_name=full_name,
        email=email,
        password_hash=password_hash,
        role='user',
        status='active',
        rsa_public_key=public_pem.decode('utf-8'),
        rsa_private_key=private_pem.decode('utf-8')
    )

    db.session.add(new_user)
    db.session.commit()

    # Generate token
    token = encode_auth_token(new_user.id)

    # Log registration event
    log_event(
        user_id=new_user.id,
        action='REGISTER',
        module='Authentication',
        file_name=None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"message": f"Security profile established for operator: {full_name}"},
        status='success'
    )

    return jsonify({
        "message": "User registered successfully",
        "token": token,
        "user": {
            "id": new_user.id,
            "full_name": new_user.full_name,
            "email": new_user.email,
            "role": new_user.role
        },
        "public_key": public_pem.decode('utf-8'),
        "private_key": "Secured on Server (Not exposed to client)"
    }), 201

def login_user():
    data = request.get_json() or {}
    email = data.get('email') or data.get('identifier')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing identity credentials"}), 400

    user = User.query.filter_by(email=email).first()

    # Timing countermeasure: dummy salt hash match
    dummy_hash = "$2b$12$e53j/E6L34yO1y8h7k7cOeP8R7Wb4S1e7N5w4E8R9T0Y1U2I3O4P5"

    if not user:
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(None, email, False, request.remote_addr, "User not found")
        log_event(
            user_id=None,
            action='LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"email": email, "message": "Failed login attempt (user not found)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if user.lockout_until and user.lockout_until > datetime.utcnow():
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(user.id, email, False, request.remote_addr, "Account locked out")
        log_event(
            user_id=user.id,
            action='LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed login attempt (account locked out)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if user.status != 'active':
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(user.id, email, False, request.remote_addr, "Account suspended")
        log_event(
            user_id=user.id,
            action='LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed login attempt (user suspended)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 3:
            user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
            trigger_security_alert(
                user_id=user.id,
                alert_type='Multiple failed login attempts',
                severity='HIGH',
                message="Operator account locked due to 3 consecutive authentication failures."
            )
        db.session.commit()

        record_login_attempt(user.id, email, False, request.remote_addr, "Incorrect password")
        log_event(
            user_id=user.id,
            action='LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed login attempt (incorrect password)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # Reset attempts on success
    user.failed_login_attempts = 0
    user.lockout_until = None
    db.session.commit()

    # Record login attempt success
    record_login_attempt(user.id, email, True, request.remote_addr, None)

    # Generate cryptographically signed JWT token
    token = encode_auth_token(user.id)

    log_event(
        user_id=user.id,
        action='LOGIN_SUCCESS',
        module='Authentication',
        file_name=None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"message": f"Operator session initiated for: {user.full_name}"},
        status='success'
    )

    return jsonify({
        "message": "Login successful",
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role
        },
        "token": token
    }), 200

def admin_login_user():
    data = request.get_json() or {}
    email = data.get('email') or data.get('identifier')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing identity credentials"}), 400

    user = User.query.filter_by(email=email).first()

    # Timing countermeasure: dummy salt hash match
    dummy_hash = "$2b$12$e53j/E6L34yO1y8h7k7cOeP8R7Wb4S1e7N5w4E8R9T0Y1U2I3O4P5"

    if not user:
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(None, email, False, request.remote_addr, "Admin user not found")
        log_event(
            user_id=None,
            action='ADMIN_LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"email": email, "message": "Failed admin login attempt (user not found)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if user.lockout_until and user.lockout_until > datetime.utcnow():
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(user.id, email, False, request.remote_addr, "Admin account locked out")
        log_event(
            user_id=user.id,
            action='ADMIN_LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed admin login attempt (account locked out)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if user.status != 'active':
        bcrypt.checkpw(b"dummy", dummy_hash.encode('utf-8'))
        record_login_attempt(user.id, email, False, request.remote_addr, "Admin account suspended")
        log_event(
            user_id=user.id,
            action='ADMIN_LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed admin login attempt (user suspended)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 3:
            user.lockout_until = datetime.utcnow() + timedelta(minutes=15)
            trigger_security_alert(
                user_id=user.id,
                alert_type='Multiple failed login attempts',
                severity='HIGH',
                message="Operator account locked due to 3 consecutive authentication failures."
            )
            log_event(
                user_id=user.id,
                action='ADMIN_ACCOUNT_LOCKED',
                module='Authentication',
                file_name=None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                details={"message": "Admin account locked due to too many failed login attempts."},
                status='failed'
            )
        db.session.commit()

        record_login_attempt(user.id, email, False, request.remote_addr, "Incorrect admin password")
        log_event(
            user_id=user.id,
            action='ADMIN_LOGIN_FAILED',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": "Failed admin login attempt (incorrect password)."},
            status='failed'
        )
        return jsonify({"error": "Invalid credentials"}), 401

    # Verify user.role is actually 'admin'
    if user.role != 'admin':
        record_login_attempt(user.id, email, False, request.remote_addr, "Non-admin attempted admin login")
        log_event(
            user_id=user.id,
            action='ADMIN_UNAUTHORIZED_ACCESS',
            module='Authentication',
            file_name=None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"message": f"Normal user {user.email} attempted to log in through admin gateway."},
            status='failed'
        )
        trigger_security_alert(
            user_id=user.id,
            alert_type='Unauthorized admin login attempt',
            severity='HIGH',
            message=f"Normal operator {user.email} attempted to authenticate through admin gateway."
        )
        return jsonify({"error": "Access denied. Admin privileges required."}), 403

    # Reset attempts on success
    user.failed_login_attempts = 0
    user.lockout_until = None
    db.session.commit()

    # Record login attempt success
    record_login_attempt(user.id, email, True, request.remote_addr, None)

    # Generate cryptographically signed JWT token
    token = encode_auth_token(user.id)

    log_event(
        user_id=user.id,
        action='ADMIN_LOGIN_SUCCESS',
        module='Authentication',
        file_name=None,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"message": f"Administrator session initiated for: {user.full_name}"},
        status='success'
    )

    return jsonify({
        "message": "Admin login successful",
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role
        },
        "token": token
    }), 200


# ==========================================
# 2. Cryptography Controller
# ==========================================

def encrypt_endpoint(current_user):
    data = request.get_json() or {}
    plaintext = data.get('plaintext')
    public_key = data.get('public_key')
    key_size = data.get('key_size', 256)

    if not plaintext or not public_key:
        return jsonify({"error": "Missing plaintext payload or public key KEK"}), 400

    try:
        payload_bytes = plaintext.encode('utf-8')
        result = encrypt_file_hybrid(payload_bytes, public_key.encode('utf-8'), aes_key_size=key_size)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

def decrypt_endpoint(current_user):
    data = request.get_json() or {}
    ciphertext = data.get('ciphertext')
    encrypted_key = data.get('encrypted_file_key')
    iv = data.get('iv_or_nonce')
    tag = data.get('tag')
    private_key = data.get('private_key')

    if not private_key or private_key.startswith("Secured on Server"):
        private_key = current_user.rsa_private_key

    if not all([ciphertext, encrypted_key, iv, tag, private_key]):
        return jsonify({"error": "Missing required hybrid parameters"}), 400

    try:
        decrypted_bytes = decrypt_file_hybrid(
            ciphertext, encrypted_key, iv, tag,
            private_key.encode('utf-8')
        )
        return jsonify({"plaintext": decrypted_bytes.decode('utf-8')}), 200
    except Exception as e:
        return jsonify({"error": "Decryption failed. Invalid keys, corrupted payload, or authentication failure."}), 400

# ==========================================
# 3. DLP & Upload Controller
# ==========================================

def classify_text(current_user):
    filename = None
    file_bytes = b''
    text = None

    if 'file' in request.files:
        file = request.files['file']
        filename = file.filename
        file_bytes = file.read()
    else:
        # Fallback payload scan
        data = request.get_json() or {}
        text = data.get('text')
        filename = data.get('filename', 'raw_text.txt')
        if text:
            file_bytes = text.encode('utf-8')

    if not filename or not file_bytes:
        return jsonify({"error": "Empty file or payload"}), 400

    # Sanitize filename to prevent path traversal or filesystem execution
    from werkzeug.utils import secure_filename
    clean_filename = secure_filename(filename)
    if not clean_filename or clean_filename in ('.', '..'):
        _, ext = os.path.splitext(filename.lower())
        if not ext:
            ext = '.txt'
        clean_filename = f"safe_document{ext}"
    filename = clean_filename

    try:
        if text is None:
            text = extract_text(filename, file_bytes)

        # Classify document
        report = classify_document(text)
        category = report['category']                  # E.g. "CONFIDENTIAL"
        confidence = report['confidence']              # E.g. 94.20
        detected_indicators = report['detected_indicators']
        explanation = report.get('explanation', '')

        # Log prediction to classification history
        # Normalize to database expected values: category title-cased ('Confidential'), confidence as fraction (0.942)
        history_entry = ClassificationHistory(
            user_id=current_user.id,
            filename=filename,
            category=category.title(),
            confidence=float(confidence / 100.0)
        )
        db.session.add(history_entry)
        db.session.commit()

        # Log classification event
        log_event(
            user_id=current_user.id,
            action='FILE_CLASSIFIED',
            module='DLP Classifier',
            file_name=filename,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={
                "filename": filename, 
                "category": category, 
                "confidence": confidence,
                "detected_indicators": detected_indicators,
                "explanation": explanation
            },
            status='success'
        )

        return jsonify({
            "category": category,
            "confidence": confidence,
            "detected_indicators": detected_indicators,
            "explanation": explanation,
            "filename": filename
        }), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"Classification error: {str(e)}"}), 500

def upload_file_endpoint(current_user):
    filename = None
    file_bytes = b''

    if 'file' in request.files:
        file = request.files['file']
        filename = file.filename
        file_bytes = file.read()
    else:
        # Fallback payload scan
        data = request.get_json() or {}
        filename = data.get('filename', 'raw_payload.txt')
        payload = data.get('content', '')
        file_bytes = payload.encode('utf-8')

    if not filename or not file_bytes:
        return jsonify({"error": "Empty file or payload"}), 400

    # Sanitize filename to prevent path traversal or filesystem execution
    from werkzeug.utils import secure_filename
    clean_filename = secure_filename(filename)
    if not clean_filename or clean_filename in ('.', '..'):
        _, ext = os.path.splitext(filename.lower())
        if not ext:
            ext = '.txt'
        clean_filename = f"safe_document{ext}"
    filename = clean_filename

    # 1. Hashing SHA-256 for Integrity checks
    checksum = generate_sha256(file_bytes)

    # 2. Extract Text & Run AI DLP Scan for classification
    try:
        text = extract_text(filename, file_bytes)
        dlp_report = classify_document(text)
        classification_label = dlp_report["category"].title() # Normalize "SECRET" -> "Secret" for DB & backend logic
        risk_score = dlp_report["risk_score"]
    except ValueError as ve:
        # Catch unsupported extensions, size limits, or text extraction errors
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        # Fallback if model fails
        classification_label = 'Confidential'
        risk_score = 5.0
        text = ""
        dlp_report = {"detected_indicators": ["Confidential keywords"]}

    # Block files if classification is Secret and DLP risk score is very high (strict check)
    if classification_label == 'Secret' and risk_score > 9.5:
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='DLP scan blocked',
            severity='HIGH',
            message=f"DLP Block: Document {filename} contains high risk sensitive sequences (Score: {risk_score})",
            category='AI_CLASSIFICATION',
            target_role='user'
        )
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='DLP scan blocked',
            severity='HIGH',
            message=f"DLP Block: Operator {current_user.email} attempted to upload document {filename} with extremely high risk score {risk_score}.",
            category='AI_CLASSIFICATION',
            target_role='admin',
            event_type='DLP_BLOCK'
        )
        log_event(
            user_id=current_user.id,
            action='DLP_BLOCK',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": filename, "checksum": checksum, "risk_score": float(risk_score)},
            status='blocked'
        )
        return jsonify({
            "error": f"DLP Block: Document contains high risk sensitive sequences (Score: {risk_score})",
            "classification": classification_label,
            "risk_score": float(risk_score)
        }), 403

    import os
    try:
        # 3. Handle User RSA Public Key pair if classification is Secret
        if classification_label == 'Secret' and not current_user.rsa_public_key:
            private_pem, public_pem = generate_rsa_keypair(2048)
            current_user.rsa_public_key = public_pem.decode('utf-8')
            current_user.rsa_private_key = private_pem.decode('utf-8')
            db.session.commit()

        # 4. Perform dynamic vault encryption based on sensitivity
        enc_pack = encrypt_by_sensitivity(
            file_bytes=file_bytes,
            sensitivity=classification_label,
            user_public_key_pem=current_user.rsa_public_key
        )

        # 5. Write encrypted ciphertext bytes to disk securely
        vault_dir = os.path.join(current_app.instance_path, 'vault')
        os.makedirs(vault_dir, exist_ok=True)
        disk_path = os.path.join(vault_dir, f"{checksum}.enc")
        with open(disk_path, 'wb') as f:
            f.write(enc_pack["ciphertext"])

        # 6. Save metadata to database
        db_path = f"vault/{checksum}.enc"
        
        new_file = File(
            owner_id=current_user.id,
            filename=filename,
            file_path=db_path,
            file_size=len(file_bytes),
            mime_type=request.files['file'].content_type if 'file' in request.files else 'application/octet-stream',
            checksum=checksum,
            is_encrypted=True
        )
        db.session.add(new_file)
        db.session.flush() # Generate ID

        detected = dlp_report.get("detected_indicators", [])
        has_pii = any(ind in detected for ind in ["Personal information", "Government identifiers", "Financial information", "Account numbers"])
        has_creds = "Credentials" in detected
        has_ip = "Confidential keywords" in detected or 'PATENT' in text or 'blueprint' in text

        new_classification = FileClassification(
            file_id=new_file.id,
            classification_label=classification_label,
            dlp_risk_score=risk_score,
            contains_pii=has_pii,
            contains_credentials=has_creds,
            contains_ip=has_ip
        )
        db.session.add(new_classification)

        new_key = EncryptionKey(
            file_id=new_file.id,
            user_id=current_user.id,
            encrypted_file_key=enc_pack["encrypted_file_key"],
            key_type=enc_pack["key_type"],
            iv_or_nonce=enc_pack["iv_or_nonce"],
            tag=enc_pack["tag"],
            encryption_time_ms=enc_pack["duration_ms"],
            version=2
        )
        db.session.add(new_key)

        # Generate hash of encrypted file payload and save to FileIntegrity
        enc_hash = generate_sha256(enc_pack["ciphertext"])
        new_integrity = FileIntegrity(
            file_id=new_file.id,
            sha256_hash=enc_hash
        )
        db.session.add(new_integrity)
        
        db.session.commit()

        # Trigger classification notifications
        if classification_label in ['Confidential', 'Secret']:
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='File classification warning',
                severity='LOW' if classification_label == 'Confidential' else 'MEDIUM',
                message=f"DLP Scanning Warning: File {filename} classified as {classification_label}.",
                file_id=new_file.id,
                category='AI_CLASSIFICATION',
                target_role='user'
            )
        if has_pii or has_creds:
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='DLP violation warning',
                severity='MEDIUM',
                message=f"DLP Violation: High-risk sensitive information detected in {filename}.",
                file_id=new_file.id,
                category='AI_CLASSIFICATION',
                target_role='user'
            )

        # Log successful upload
        log_event(
            user_id=current_user.id,
            action='FILE_UPLOAD',
            module='Cryptographic Vault',
            file_name=filename,
            file_id=new_file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": filename, "checksum": checksum, "file_size": len(file_bytes)},
            status='success'
        )

        # Log successful classification
        log_event(
            user_id=current_user.id,
            action='FILE_CLASSIFIED',
            module='DLP Classifier',
            file_name=filename,
            file_id=new_file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={
                "filename": filename,
                "classification": classification_label,
                "dlp_risk_score": float(risk_score)
            },
            status='success'
        )

        # Log successful encryption
        log_event(
            user_id=current_user.id,
            action='FILE_ENCRYPTED',
            module='Cryptographic Vault',
            file_name=filename,
            file_id=new_file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={
                "filename": filename,
                "algorithm": enc_pack["key_type"],
                "exec_time_ms": enc_pack["duration_ms"]
            },
            status='success'
        )

        return jsonify({
            "message": "File vaulted successfully",
            "file": {
                "id": new_file.id,
                "filename": new_file.filename,
                "checksum": new_file.checksum,
                "classification": classification_label,
                "risk_score": float(risk_score),
                "algorithm": enc_pack["key_type"],
                "key_size": enc_pack["key_size"],
                "encryption_time_ms": enc_pack["duration_ms"]
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"File vaulting failed: {str(e)}"}), 500

# ==========================================
# 4. Sharing Controller
# ==========================================

def share_file_key(current_user):
    data = request.get_json() or {}
    file_id = data.get('file_id')
    recipient_email = data.get('recipient_email')
    access_level = data.get('access_level', 'view')
    duration_hours = data.get('duration_hours', 1)

    if not file_id or not recipient_email:
        return jsonify({"error": "Missing sharing parameters"}), 400

    file_asset = File.query.get(file_id)
    recipient = User.query.filter_by(email=recipient_email).first()

    if not file_asset:
        return jsonify({"error": "File asset not found"}), 404
    if not recipient:
        return jsonify({"error": "Recipient profile not registered"}), 404

    # Check ownership
    if file_asset.owner_id != current_user.id:
         return jsonify({"error": "Unauthorized. You are not the owner of this file asset."}), 403

    # Simulate re-encrypting symmetric key (Generate a new KEK wrapper for recipient)
    _, recipient_pub_key = generate_rsa_keypair(2048) # Mock target KEK
    
    # Load original key parameters
    orig_key = EncryptionKey.query.filter_by(file_id=file_id, user_id=current_user.id).first()
    if not orig_key:
        return jsonify({"error": "Original file encryption key not found"}), 404

    # Create Sharing entry
    new_share = FileSharing(
        file_id=file_id,
        shared_by_user_id=current_user.id,
        shared_with_user_id=recipient.id,
        access_level=access_level,
        expires_at=datetime.utcnow() + timedelta(hours=duration_hours)
    )
    db.session.add(new_share)

    # Save re-encrypted key for recipient
    recipient_key = EncryptionKey(
        file_id=file_id,
        user_id=recipient.id,
        encrypted_file_key=orig_key.encrypted_file_key, # In mock sharing, reuse wrapped DEK representation
        key_type=orig_key.key_type,
        iv_or_nonce=orig_key.iv_or_nonce,
        tag=orig_key.tag
    )
    db.session.add(recipient_key)
    
    db.session.commit()

    # Log sharing event
    log_event(
        user_id=current_user.id,
        action='SHARE_KEY',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"file_id": file_id, "recipient": recipient.full_name},
        status='success'
    )

    return jsonify({
        "message": "File sharing authorization complete",
        "sharing_id": new_share.id,
        "token": f"cg_share_{new_share.id}_{int(datetime.utcnow().timestamp())}"
    }), 200

# ==========================================
# 5. Audit & Dashboard Controller
# ==========================================

def get_dashboard_summary(current_user):
    is_admin = current_user.role == 'admin'

    # 1. Total users
    total_users = User.query.count()

    # 2. File counts & encryption coverage
    from sqlalchemy import func
    if is_admin:
        total_files = File.query.count()
        total_encrypted = EncryptionKey.query.count()
        total_shared = FileSharing.query.count()
        
        # DLP counts
        pub_count = FileClassification.query.filter_by(classification_label='Public').count()
        conf_count = FileClassification.query.filter_by(classification_label='Confidential').count()
        sec_count = FileClassification.query.filter_by(classification_label='Secret').count()
        
        # High risk indicators
        pii_count = FileClassification.query.filter_by(contains_pii=True).count()
        cred_count = FileClassification.query.filter_by(contains_credentials=True).count()
        ip_count = FileClassification.query.filter_by(contains_ip=True).count()
        
        # Average risk score
        avg_risk = db.session.query(func.avg(FileClassification.dlp_risk_score)).scalar() or 0.0
        avg_risk = float(avg_risk)
        
        # Sharing stats
        active_shares = FileSharing.query.filter_by(status='active').count()
        expired_shares = FileSharing.query.filter_by(status='expired').count()
        revoked_shares = FileSharing.query.filter_by(status='revoked').count()
        total_downloads = db.session.query(func.sum(FileSharing.downloads_count)).scalar() or 0
        failed_share_access = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS').count()
        
        # Failed logins
        failed_logins = ActivityLog.query.filter_by(action='LOGIN_FAILED').count()
        
        # Security alerts
        active_alerts_count = SecurityAlert.query.filter_by(status='unresolved').count()
        total_alerts = SecurityAlert.query.count()
        
        # Encryption operations
        successful_encryptions = ActivityLog.query.filter_by(action='FILE_ENCRYPTED', status='success').count()
        failed_encryptions = ActivityLog.query.filter_by(action='FILE_ENCRYPTED', status='failed').count()
        decryption_failures = ActivityLog.query.filter_by(action='FILE_DECRYPTED', status='failed').count()
    else:
        total_files = File.query.filter_by(owner_id=current_user.id).count()
        total_encrypted = EncryptionKey.query.join(File).filter(File.owner_id == current_user.id).count()
        total_shared = FileSharing.query.filter_by(owner_id=current_user.id).count()
        
        # DLP counts
        pub_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Public').count()
        conf_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Confidential').count()
        sec_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Secret').count()
        
        # High risk indicators
        pii_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.contains_pii==True).count()
        cred_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.contains_credentials==True).count()
        ip_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.contains_ip==True).count()
        
        # Average risk score
        classifications = FileClassification.query.join(File).filter(File.owner_id == current_user.id).all()
        avg_risk = float(sum(c.dlp_risk_score for c in classifications) / len(classifications)) if classifications else 0.0
        
        # Sharing stats
        active_shares = FileSharing.query.filter_by(owner_id=current_user.id, status='active').count()
        expired_shares = FileSharing.query.filter_by(owner_id=current_user.id, status='expired').count()
        revoked_shares = FileSharing.query.filter_by(owner_id=current_user.id, status='revoked').count()
        total_downloads = db.session.query(func.sum(FileSharing.downloads_count)).filter(FileSharing.owner_id == current_user.id).scalar() or 0
        failed_share_access = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS', user_id=current_user.id).count()
        
        # Failed logins
        failed_logins = ActivityLog.query.filter_by(action='LOGIN_FAILED', user_id=current_user.id).count()
        
        # Security alerts
        active_alerts_count = SecurityAlert.query.filter_by(status='unresolved', user_id=current_user.id).count()
        total_alerts = SecurityAlert.query.filter_by(user_id=current_user.id).count()
        
        # Encryption operations
        successful_encryptions = ActivityLog.query.filter_by(action='FILE_ENCRYPTED', status='success', user_id=current_user.id).count()
        failed_encryptions = ActivityLog.query.filter_by(action='FILE_ENCRYPTED', status='failed', user_id=current_user.id).count()
        decryption_failures = ActivityLog.query.filter_by(action='FILE_DECRYPTED', status='failed', user_id=current_user.id).count()

    # Calculate verified and tampered files
    latest_status = {}
    if is_admin:
        history_query = IntegrityHistory.query
    else:
        history_query = IntegrityHistory.query.filter_by(user_id=current_user.id)
        
    for h in history_query.order_by(IntegrityHistory.timestamp.asc()).all():
        latest_status[h.file_id] = h.result

    verified_files = sum(1 for status in latest_status.values() if status == 'VERIFIED')
    tampered_files = sum(1 for status in latest_status.values() if status == 'TAMPERED')

    # Security alerts deductions
    if is_admin:
        critical_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='CRITICAL').count()
        high_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='HIGH').count()
        medium_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='MEDIUM').count()
        low_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='LOW').count()
    else:
        critical_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='CRITICAL', user_id=current_user.id).count()
        high_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='HIGH', user_id=current_user.id).count()
        medium_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='MEDIUM', user_id=current_user.id).count()
        low_alerts = SecurityAlert.query.filter_by(status='unresolved', severity='LOW', user_id=current_user.id).count()

    alerts_deduction = min(40, (critical_alerts * 20) + (high_alerts * 10) + (medium_alerts * 5) + (low_alerts * 2))
    tamper_deduction = min(40, tampered_files * 15)

    enc_coverage_pct = (total_encrypted / total_files * 100) if total_files > 0 else 100.0
    enc_deduction = min(10, (1 - (total_encrypted / total_files)) * 10) if total_files > 0 else 0.0

    if is_admin:
        sig_count = FileIntegrity.query.count()
    else:
        sig_count = FileIntegrity.query.join(File).filter(File.owner_id == current_user.id).count()
        
    sig_coverage_pct = (sig_count / total_files * 100) if total_files > 0 else 100.0
    sig_deduction = min(10, (1 - (sig_count / total_files)) * 10) if total_files > 0 else 0.0

    # Threat Score: Explainable, consistent threat score mapping directly to database metrics.
    threat_score = min(100, int(alerts_deduction + tamper_deduction + enc_deduction + sig_deduction))

    # Security Score (legacy)
    security_score = max(0, 100 - threat_score)

    security_factors = [
        {
            "name": "Security Alerts",
            "status": "Good" if alerts_deduction == 0 else "Action Required",
            "deduction": int(alerts_deduction),
            "contribution": int(alerts_deduction),
            "description": f"Added {int(alerts_deduction)} to threat score for {critical_alerts + high_alerts + medium_alerts + low_alerts} unresolved alert(s)."
        },
        {
            "name": "File Tampering",
            "status": "Good" if tamper_deduction == 0 else "Danger",
            "deduction": int(tamper_deduction),
            "contribution": int(tamper_deduction),
            "description": f"Added {int(tamper_deduction)} to threat score for {tampered_files} tampered file(s) detected."
        },
        {
            "name": "Encryption Coverage",
            "status": "Good" if enc_coverage_pct >= 90 else "Improvement Needed",
            "deduction": int(enc_deduction),
            "contribution": int(enc_deduction),
            "description": f"Added {int(enc_deduction)} to threat score. Current coverage is {round(enc_coverage_pct, 1)}%."
        },
        {
            "name": "Integrity Signatures",
            "status": "Good" if sig_coverage_pct >= 90 else "Improvement Needed",
            "deduction": int(sig_deduction),
            "contribution": int(sig_deduction),
            "description": f"Added {int(sig_deduction)} to threat score. Current signature coverage is {round(sig_coverage_pct, 1)}%."
        }
    ]

    # Recent files
    files = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).limit(5).all()
    files_list = []
    for f in files:
        cls_label = f.classification.classification_label if f.classification else 'Confidential'
        enc_key = EncryptionKey.query.filter_by(file_id=f.id).first()
        algorithm = enc_key.key_type if enc_key else 'AES-256-GCM'
        key_size = 256
        if enc_key and '128' in enc_key.key_type:
            key_size = 128
        enc_time = enc_key.encryption_time_ms if (enc_key and enc_key.encryption_time_ms) else 0.0

        files_list.append({
            "id": f.id,
            "name": f.filename,
            "size": f"{round(f.file_size / 1024, 1)} KB",
            "class": cls_label,
            "date": f.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "status": "Encrypted",
            "algorithm": algorithm,
            "key_size": key_size,
            "encryption_time_ms": enc_time
        })

    # Most Recent Active Share
    recent_share = FileSharing.query.filter_by(owner_id=current_user.id, status='active').order_by(FileSharing.created_at.desc()).first()
    share_details = None
    if recent_share and recent_share.expiry_time > datetime.utcnow():
        integrity = FileIntegrity.query.filter_by(file_id=recent_share.file_id).first()
        share_details = {
            "filename": recent_share.file.filename if recent_share.file else 'Unknown',
            "sha256_hash": integrity.sha256_hash if integrity else 'None',
            "share_token": recent_share.share_token,
            "share_link": f"http://localhost:5173/shared/{recent_share.share_token}",
            "qr_code": recent_share.qr_code,
            "expiry_time": recent_share.expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            "integrity_status": "VERIFIED"
        }
        vault_dir = os.path.join(current_app.instance_path, 'vault')
        file_path = os.path.join(vault_dir, f"{recent_share.file.checksum}.enc") if recent_share.file else ""
        if file_path and os.path.exists(file_path) and integrity:
            with open(file_path, 'rb') as f:
                ciphertext_bytes = f.read()
            from app.utils.integrity import verify_sha256
            if not verify_sha256(ciphertext_bytes, integrity.sha256_hash):
                share_details["integrity_status"] = "TAMPERED"

    return jsonify({
        "stats": {
            "secured_files": total_files,
            "total_users": total_users,
            "encrypted_files": total_encrypted,
            "shared_files": total_shared,
            "verified_files": verified_files,
            "tampered_files": tampered_files,
            "security_alerts": active_alerts_count,
            "total_alerts": total_alerts,
            "vulnerability_index": f"{round(avg_risk / 10, 2)} / 10",
            "security_score": security_score,
            "security_factors": security_factors,
            "threat_score": threat_score,
            "threat_factors": security_factors,
            "avg_compliance_risk": avg_risk,
            
            # Module 5 detailed statistics
            "sensitive_files": pub_count + conf_count + sec_count,
            "active_shares": active_shares,
            "expired_shares": expired_shares,
            "revoked_shares": revoked_shares,
            "total_downloads": total_downloads,
            "failed_share_access": failed_share_access,
            "failed_logins": failed_logins,
            
            "encryption_monitoring": {
                "aes256_count": EncryptionKey.query.join(File).filter(File.owner_id == current_user.id).filter(EncryptionKey.key_type.like('%AES-256%')).count() if not is_admin else EncryptionKey.query.filter(EncryptionKey.key_type.like('%AES-256%')).count(),
                "aes128_count": EncryptionKey.query.join(File).filter(File.owner_id == current_user.id).filter(EncryptionKey.key_type.like('%AES-128%')).count() if not is_admin else EncryptionKey.query.filter(EncryptionKey.key_type.like('%AES-128%')).count(),
                "versions": {
                    "v1": EncryptionKey.query.join(File).filter(File.owner_id == current_user.id).filter(EncryptionKey.version == 1).count() if not is_admin else EncryptionKey.query.filter_by(version=1).count(),
                    "v2": EncryptionKey.query.join(File).filter(File.owner_id == current_user.id).filter(EncryptionKey.version == 2).count() if not is_admin else EncryptionKey.query.filter_by(version=2).count()
                },
                "successful_encryptions": successful_encryptions,
                "failed_encryptions": failed_encryptions,
                "decryption_failures": decryption_failures
            },
            "ai_dlp_monitoring": {
                "public_count": pub_count,
                "confidential_count": conf_count,
                "secret_count": sec_count,
                "pii_count": pii_count,
                "credentials_count": cred_count,
                "ip_count": ip_count,
                "avg_risk_score": avg_risk
            }
        },
        "recent_files": files_list,
        "classification_distribution": {
            "Public": pub_count,
            "Confidential": conf_count,
            "Secret": sec_count
        },
        "recent_share": share_details
    }), 200

def get_activity_logs(current_user):
    search = request.args.get('search', '')
    module = request.args.get('module', 'ALL')
    status = request.args.get('status', 'ALL')
    action_param = request.args.get('action', 'ALL')
    user_id_param = request.args.get('user_id', 'ALL')
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
    except (ValueError, TypeError):
        page = 1
        per_page = 20

    query = ActivityLog.query

    # Enforce role-based access
    if current_user.role == 'admin':
        if user_id_param != 'ALL':
            try:
                query = query.filter_by(user_id=int(user_id_param))
            except ValueError:
                pass
    else:
        query = query.filter_by(user_id=current_user.id)

    # Filter by Module
    if module != 'ALL':
        query = query.filter_by(module=module)

    # Filter by Status
    if status != 'ALL':
        query = query.filter_by(status=status)

    # Filter by Action
    if action_param != 'ALL':
        query = query.filter_by(action=action_param)

    # Filter by Severity
    severity = request.args.get('severity', 'ALL')
    if severity != 'ALL':
        query = query.filter(ActivityLog.details.like(f'%"severity": "{severity}"%'))

    # Filter by Date Range
    if start_date_str:
        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            query = query.filter(ActivityLog.timestamp >= start_date)
        except ValueError:
            pass

    if end_date_str:
        try:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(ActivityLog.timestamp < end_date)
        except ValueError:
            pass

    # Search keyword
    if search:
        query = query.filter(
            (ActivityLog.action.like(f"%{search}%")) |
            (ActivityLog.file_name.like(f"%{search}%")) |
            (ActivityLog.ip_address.like(f"%{search}%"))
        )

    # Pagination
    pagination = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    logs_list = []
    for l in pagination.items:
        username = 'System/Unknown'
        if l.user_id:
            usr = User.query.get(l.user_id)
            if usr:
                username = usr.full_name
        
        logs_list.append({
            "id": l.id,
            "time": l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "user": username,
            "user_id": l.user_id,
            "action": l.action,
            "module": l.module,
            "file_name": l.file_name or 'None',
            "file_id": l.file_id,
            "ip": l.ip_address,
            "agent": l.user_agent,
            "details": l.details.get('message', str(l.details)) if isinstance(l.details, dict) else str(l.details),
            "status": l.status
        })

    return jsonify({
        "logs": logs_list,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": pagination.page,
        "per_page": pagination.per_page
    }), 200

def get_classification_history(current_user):
    history = ClassificationHistory.query.filter_by(user_id=current_user.id).order_by(ClassificationHistory.created_at.desc()).limit(50).all()
    history_list = []
    for h in history:
        history_list.append({
            "id": h.id,
            "filename": h.filename,
            "category": h.category,
            "confidence": h.confidence,
            "date": h.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(history_list), 200

def get_user_profile(current_user):
    return jsonify({
        "username": current_user.full_name,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "role": current_user.role,
        "status": current_user.status,
        "key_fingerprint": "sha256:d8:a1:c5:2b:81:4e:c9:0d:3f:22:1a..."
    }), 200

# ==========================================
# 6. RSA Keys & Download Management (Module 3)
# ==========================================

def keys_generate(current_user):
    try:
        private_pem, public_pem = generate_rsa_keypair(2048)
        current_user.rsa_public_key = public_pem.decode('utf-8')
        current_user.rsa_private_key = private_pem.decode('utf-8')
        db.session.commit()

        log_event(
            user_id=current_user.id,
            action='KEY_GENERATE',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"message": "Generated new 2048-bit RSA system keypair"},
            status='success'
        )

        return jsonify({
            "public_key": current_user.rsa_public_key,
            "private_key": "Secured on Server (Not exposed to client)"
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to generate keypair: {str(e)}"}), 500

def keys_current(current_user):
    try:
        if not current_user.rsa_public_key:
            private_pem, public_pem = generate_rsa_keypair(2048)
            current_user.rsa_public_key = public_pem.decode('utf-8')
            current_user.rsa_private_key = private_pem.decode('utf-8')
            db.session.commit()
            
        return jsonify({
            "public_key": current_user.rsa_public_key,
            "private_key": "Secured on Server (Not exposed to client)"
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve current keys: {str(e)}"}), 500

def download_file_encrypted(current_user, file_id):
    file = File.query.get(file_id)
    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Unauthorized API access',
            severity='HIGH',
            message=f"Operator attempted unauthorized download of encrypted file {file.filename} (ID {file.id})",
            file_id=file.id,
            category='FILE_SECURITY',
            target_role='admin',
            event_type='UNAUTHORIZED_FILE_ACCESS'
        )
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='Cryptographic Vault',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": "Owner mismatch on encrypted file download", "file_id": file_id},
            status='blocked'
        )
        return jsonify({"error": "Access denied"}), 403

    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")

    if not os.path.exists(file_path):
        return jsonify({"error": "Encrypted file payload not found in vault storage"}), 404

    log_event(
        user_id=current_user.id,
        action='FILE_DOWNLOAD_ENC',
        module='Cryptographic Vault',
        file_name=file.filename,
        file_id=file.id,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        details={"filename": file.filename, "checksum": file.checksum},
        status='success'
    )

    return send_file(
        file_path, 
        as_attachment=True, 
        download_name=f"{file.filename}.enc", 
        mimetype='application/octet-stream'
    )

def download_file_decrypted(current_user, file_id):
    file = File.query.get(file_id)
    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Unauthorized API access',
            severity='HIGH',
            message=f"Operator attempted unauthorized decrypted download of file {file.filename} (ID {file.id})",
            file_id=file.id,
            category='FILE_SECURITY',
            target_role='admin',
            event_type='UNAUTHORIZED_FILE_ACCESS'
        )
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='Cryptographic Vault',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": "Owner mismatch on decrypted file download", "file_id": file_id},
            status='blocked'
        )
        return jsonify({"error": "Access denied"}), 403

    # Extract private key (JSON payload or Form data)
    private_key_pem = None
    if request.is_json:
        data = request.get_json() or {}
        private_key_pem = data.get('private_key')
    else:
        private_key_pem = request.form.get('private_key')

    classification = file.classification.classification_label if file.classification else 'Confidential'
    
    # Validation for Secret files
    if classification == 'Secret':
        if not private_key_pem or private_key_pem.startswith("Secured on Server"):
            return jsonify({"error": "RSA Private Decryption Key is required for Secret (Hybrid Encrypted) vault assets"}), 400
    else:
        if not private_key_pem or private_key_pem.startswith("Secured on Server"):
            private_key_pem = current_user.rsa_private_key

    enc_key = EncryptionKey.query.filter_by(file_id=file.id).first()
    if not enc_key:
        return jsonify({"error": "Encryption key metadata not found for this file"}), 404

    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")
    
    if not os.path.exists(file_path):
        return jsonify({"error": "Encrypted file payload not found in vault storage"}), 404

    try:
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        # Enforce file integrity checks before decryption
        integrity = FileIntegrity.query.filter_by(file_id=file.id).first()
        if integrity:
            from app.utils.integrity import verify_sha256
            if not verify_sha256(ciphertext_bytes, integrity.sha256_hash):
                # Trigger user notification
                trigger_security_alert(
                    user_id=current_user.id,
                    alert_type='File tampering detected',
                    severity='CRITICAL',
                    message=f"Integrity signature mismatch: Decryption blocked for your file {file.filename} due to tampering.",
                    file_id=file.id,
                    category='INTEGRITY',
                    target_role='user'
                )
                # Trigger admin alert
                trigger_security_alert(
                    user_id=current_user.id,
                    alert_type='File tampering detected',
                    severity='CRITICAL',
                    message=f"CRITICAL: File integrity tampering detected for file ID {file.id} owned by User {file.owner_id}.",
                    file_id=file.id,
                    category='INTEGRITY',
                    target_role='admin',
                    event_type='FILE_TAMPERING'
                )
                log_event(
                    user_id=current_user.id,
                    action='FILE_TAMPERED',
                    module='Cryptographic Vault',
                    file_name=file.filename,
                    file_id=file.id,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    details={"filename": file.filename, "error": "Integrity signature mismatch. Decryption blocked."},
                    status='failed'
                )
                return jsonify({"error": "Decryption blocked: The encrypted file payload has been tampered with or is corrupted."}), 400

        decrypted_bytes = decrypt_by_sensitivity(
            ciphertext_bytes=ciphertext_bytes,
            sensitivity=classification,
            encrypted_file_key_b64=enc_key.encrypted_file_key,
            iv_b64=enc_key.iv_or_nonce,
            tag_b64=enc_key.tag,
            user_private_key_pem=private_key_pem,
            version=getattr(enc_key, 'version', 1)
        )

        log_event(
            user_id=current_user.id,
            action='FILE_DECRYPTED',
            module='Cryptographic Vault',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": file.filename, "checksum": file.checksum, "classification": classification},
            status='success'
        )

        # Check suspicious download activity (5+ in 5 minutes)
        recent_downloads = ActivityLog.query.filter_by(user_id=current_user.id, status='success').filter(
            ActivityLog.action.in_(['FILE_DECRYPTED', 'FILE_DOWNLOAD_ENC', 'SHARE_ACCESSED'])
        ).filter(ActivityLog.timestamp >= datetime.utcnow() - timedelta(minutes=5)).count()
        if recent_downloads >= 5:
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='Suspicious download activity',
                severity='HIGH',
                message=f"Operator {current_user.email} performed {recent_downloads} successful document downloads within 5 minutes.",
                file_id=file.id,
                category='FILE_SECURITY',
                target_role='admin',
                event_type='SUSPICIOUS_DOWNLOAD_ACTIVITY'
            )

        # Stream decrypted binary file
        from flask import make_response
        response = make_response(decrypted_bytes)
        response.headers['Content-Type'] = file.mime_type or 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename="{file.filename}"'
        return response

    except Exception as e:
        log_event(
            user_id=current_user.id,
            action='FILE_DECRYPTED',
            module='Cryptographic Vault',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": file.filename, "error": str(e)},
            status='failed'
        )

        # Check repeated decryption failures (3+ in 15 minutes)
        recent_failures = ActivityLog.query.filter_by(
            user_id=current_user.id,
            action='FILE_DECRYPTED',
            status='failed'
        ).filter(ActivityLog.timestamp >= datetime.utcnow() - timedelta(minutes=15)).count()
        if recent_failures >= 3:
            # Trigger user notification
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='Repeated decryption failures',
                severity='HIGH',
                message=f"Warning: {recent_failures} failed decryption attempts detected on your account.",
                file_id=file.id,
                category='ENCRYPTION',
                target_role='user'
            )
            # Trigger admin alert
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='Repeated decryption failures',
                severity='HIGH',
                message=f"Operator {current_user.email} generated {recent_failures} consecutive decryption failures within 15 minutes.",
                file_id=file.id,
                category='ENCRYPTION',
                target_role='admin',
                event_type='REPEATED_DECRYPTION_FAILURES'
            )

        return jsonify({"error": "Decryption failed. Invalid keys, corrupted payload, or authentication failure."}), 400

# ==========================================
# 7. File Integrity & Secure Sharing (Module 4)
# ==========================================

import secrets
import qrcode
from io import BytesIO

def generate_hash_endpoint(current_user):
    data = request.get_json() or {}
    file_id = data.get('file_id')

    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400

    file = File.query.filter_by(id=file_id, owner_id=current_user.id).first()
    if not file:
        return jsonify({"error": "File not found or access denied"}), 404

    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")

    if not os.path.exists(file_path):
        return jsonify({"error": "Encrypted file payload not found in vault storage"}), 404

    try:
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        enc_hash = generate_sha256(ciphertext_bytes)

        # Update or create integrity database record
        integrity = FileIntegrity.query.filter_by(file_id=file.id).first()
        if integrity:
            integrity.sha256_hash = enc_hash
        else:
            integrity = FileIntegrity(file_id=file.id, sha256_hash=enc_hash)
            db.session.add(integrity)
        db.session.commit()

        return jsonify({
            "message": "SHA-256 integrity hash generated successfully",
            "file_id": file.id,
            "sha256_hash": enc_hash
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to generate hash: {str(e)}"}), 500

def verify_file_endpoint(current_user):
    data = request.get_json() or {}
    file_id = data.get('file_id')

    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400

    file = File.query.get(file_id)
    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Unauthorized API access',
            severity='MEDIUM',
            message=f"Operator attempted unauthorized integrity verification of file {file.filename} (ID {file.id})",
            file_id=file.id
        )
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='File Integrity',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": "Owner mismatch on file verification", "file_id": file_id},
            status='blocked'
        )
        return jsonify({"error": "Access denied"}), 403

    integrity = FileIntegrity.query.filter_by(file_id=file.id).first()
    if not integrity:
        # Auto-compute if missing
        vault_dir = os.path.join(current_app.instance_path, 'vault')
        file_path = os.path.join(vault_dir, f"{file.checksum}.enc")
        if os.path.exists(file_path):
            try:
                with open(file_path, 'rb') as f:
                    ciphertext_bytes = f.read()
                enc_hash = generate_sha256(ciphertext_bytes)
                integrity = FileIntegrity(file_id=file.id, sha256_hash=enc_hash)
                db.session.add(integrity)
                db.session.commit()
            except Exception as e:
                return jsonify({"error": f"Failed to auto-compute hash: {str(e)}"}), 500
        else:
            # Stored payload missing, can't verify
            # Record audit attempt as TAMPERED (since file is missing)
            history_entry = IntegrityHistory(
                file_id=file.id,
                user_id=current_user.id,
                result='TAMPERED'
            )
            db.session.add(history_entry)
            db.session.commit()

            trigger_security_alert(
                user_id=current_user.id,
                alert_type='File tampering detected',
                severity='CRITICAL',
                message=f"Integrity check failed: Encrypted vault payload missing for file {file.filename} (ID {file.id})",
                file_id=file.id
            )

            log_event(
                user_id=current_user.id,
                action='FILE_TAMPERED',
                module='File Integrity',
                file_name=file.filename,
                file_id=file.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                details={"filename": file.filename, "status": "TAMPERED", "error": "Encrypted file payload missing"},
                status='failed'
            )
            return jsonify({
                "file_id": file.id,
                "filename": file.filename,
                "status": "TAMPERED",
                "stored_hash": "None",
                "computed_hash": "None",
                "verified_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            }), 200

    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")

    if not os.path.exists(file_path):
        # File payload missing -> Tampered
        history_entry = IntegrityHistory(
            file_id=file.id,
            user_id=current_user.id,
            result='TAMPERED'
        )
        db.session.add(history_entry)
        db.session.commit()

        trigger_security_alert(
            user_id=current_user.id,
            alert_type='File tampering detected',
            severity='CRITICAL',
            message=f"Integrity check failed: Encrypted vault payload missing for file {file.filename} (ID {file.id})",
            file_id=file.id
        )

        log_event(
            user_id=current_user.id,
            action='FILE_TAMPERED',
            module='File Integrity',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": file.filename, "status": "TAMPERED", "stored_hash": integrity.sha256_hash, "computed_hash": "None"},
            status='failed'
        )
        return jsonify({
            "file_id": file.id,
            "filename": file.filename,
            "status": "TAMPERED",
            "stored_hash": integrity.sha256_hash,
            "computed_hash": "None",
            "verified_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }), 200

    try:
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        computed_hash = generate_sha256(ciphertext_bytes)
        stored_hash = integrity.sha256_hash

        # Constant-time comparison
        from app.utils.integrity import verify_sha256
        is_intact = verify_sha256(ciphertext_bytes, stored_hash)
        status = "VERIFIED" if is_intact else "TAMPERED"

        # Store verification attempt in IntegrityHistory
        history_entry = IntegrityHistory(
            file_id=file.id,
            user_id=current_user.id,
            result=status
        )
        db.session.add(history_entry)
        db.session.commit()

        if not is_intact:
            trigger_security_alert(
                user_id=current_user.id,
                alert_type='File tampering detected',
                severity='CRITICAL',
                message=f"Integrity check failed: Signature mismatch detected for file {file.filename} (ID {file.id})",
                file_id=file.id
            )

        log_event(
            user_id=current_user.id,
            action='FILE_VERIFIED' if is_intact else 'FILE_TAMPERED',
            module='File Integrity',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": file.filename, "status": status, "stored_hash": stored_hash, "computed_hash": computed_hash},
            status='success' if is_intact else 'failed'
        )

        return jsonify({
            "file_id": file.id,
            "filename": file.filename,
            "status": status,
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "verified_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        }), 200
    except Exception as e:
        return jsonify({"error": f"Integrity verification failed: {str(e)}"}), 500

def share_file_endpoint(current_user):
    data = request.get_json() or {}
    file_id = data.get('file_id')
    expiry_hours = data.get('expiry_hours', 24)
    max_downloads = data.get('max_downloads')

    if not file_id:
        return jsonify({"error": "Missing file_id"}), 400

    file = File.query.get(file_id)
    if not file:
        return jsonify({"error": "File not found"}), 404

    if file.owner_id != current_user.id:
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Unauthorized API access',
            severity='MEDIUM',
            message=f"Operator attempted unauthorized sharing creation of file {file.filename} (ID {file.id})",
            file_id=file.id
        )
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='Delegated Sharing',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"reason": "Owner mismatch on file sharing", "file_id": file_id},
            status='blocked'
        )
        return jsonify({"error": "Access denied"}), 403

    # Validate max_downloads if present
    if max_downloads is not None:
        try:
            max_downloads = int(max_downloads)
            if max_downloads <= 0:
                raise ValueError()
        except (ValueError, TypeError):
            return jsonify({"error": "max_downloads must be a positive integer"}), 400

    try:
        token = secrets.token_urlsafe(32)
        expiry_time = datetime.utcnow() + timedelta(hours=int(expiry_hours))
        
        # Share link points to frontend public SharedResolver page dynamically configured
        share_base = current_app.config.get('SHARE_BASE_URL', 'http://localhost:5173')
        share_link = f"{share_base}/shared/{token}"

        # Generate base64 QR Code
        qr = qrcode.QRCode(version=1, box_size=10, border=3)
        qr.add_data(share_link)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_code_base64 = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode('utf-8')}"

        new_share = FileSharing(
            file_id=file.id,
            owner_id=current_user.id,
            share_token=token,
            qr_code=qr_code_base64,
            expiry_time=expiry_time,
            status='active',
            max_downloads=max_downloads,
            downloads_count=0
        )
        db.session.add(new_share)
        db.session.commit()

        trigger_security_alert(
            user_id=current_user.id,
            alert_type='New share link created',
            severity='INFO',
            message=f"A new secure share link has been created for your file {file.filename}.",
            file_id=file.id,
            category='SHARING',
            target_role='user'
        )

        log_event(
            user_id=current_user.id,
            action='FILE_SHARED',
            module='Delegated Sharing',
            file_name=file.filename,
            file_id=file.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={
                "filename": file.filename, 
                "share_prefix": token[:8] + "...", 
                "expiry_hours": expiry_hours, 
                "max_downloads": max_downloads
            },
            status='success'
        )

        return jsonify({
            "message": "File shared successfully",
            "share_id": new_share.id,
            "share_token": token,
            "share_link": share_link,
            "qr_code": qr_code_base64,
            "expiry_time": expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            "max_downloads": max_downloads,
            "downloads_count": 0
        }), 201
    except Exception as e:
        return jsonify({"error": f"Failed to generate share link: {str(e)}"}), 500

def resolve_shared_link(token):
    share = FileSharing.query.filter_by(share_token=token).with_for_update().first()
    if not share:
        # Log failed access
        log_event(
            user_id=None,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Sharing link is invalid or not found"},
            status='failed'
        )
        return jsonify({"error": "Sharing link is invalid or not found"}), 404

    if share.max_downloads is not None and share.downloads_count >= share.max_downloads:
        share.status = 'expired'
        db.session.commit()
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='Download limit reached',
            severity='LOW',
            message=f"Download limit reached for shared file {share.file.filename if share.file else 'Unknown'}.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Download limit has been exceeded"},
            status='failed'
        )
        return jsonify({"error": "This sharing link has exceeded its download limit"}), 403

    # Validate active state and expiry
    if share.status != 'active':
        alert_type = 'Revoked share link access' if share.status == 'revoked' else 'Expired share link access'
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type=alert_type,
            severity='MEDIUM',
            message=f"Access attempt blocked on share token {token[:8]}... because token status is {share.status}.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": f"This sharing link has been {share.status}"},
            status='failed'
        )
        return jsonify({"error": f"This sharing link has been {share.status}"}), 403

    if share.expiry_time < datetime.utcnow():
        share.status = 'expired'
        db.session.commit()
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='Expired share link access',
            severity='MEDIUM',
            message=f"A secure share link for {share.file.filename if share.file else 'Unknown'} has expired.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "This sharing link has expired"},
            status='failed'
        )
        return jsonify({"error": "This sharing link has expired"}), 403

    file = share.file
    if not file:
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Shared file metadata no longer exists"},
            status='failed'
        )
        return jsonify({"error": "Shared file metadata no longer exists"}), 404

    # Run dynamic integrity check on ciphertext bytes
    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")
    
    if not os.path.exists(file_path):
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='File tampering detected',
            severity='CRITICAL',
            message=f"Integrity check failed: Encrypted vault payload missing for shared file {file.filename} (ID {file.id})",
            file_id=file.id
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=file.id,
            file_name=file.filename,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Encrypted file payload missing from vault storage"},
            status='failed'
        )
        return jsonify({"error": "Encrypted file payload missing from vault storage"}), 404

    try:
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        integrity = FileIntegrity.query.filter_by(file_id=file.id).first()
        stored_hash = integrity.sha256_hash if integrity else ""
        
        from app.utils.integrity import verify_sha256
        is_intact = verify_sha256(ciphertext_bytes, stored_hash) if stored_hash else True
        integrity_status = "VERIFIED" if is_intact else "TAMPERED"

        if not is_intact:
            trigger_security_alert(
                user_id=share.owner_id,
                alert_type='File tampering detected',
                severity='CRITICAL',
                message=f"Integrity check failed: Signature mismatch detected for shared file {file.filename} (ID {file.id})",
                file_id=file.id
            )

        log_event(
            user_id=share.owner_id,
            action='SHARE_ACCESSED',
            module='Delegated Sharing',
            file_id=file.id,
            file_name=file.filename,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "filename": file.filename},
            status='success'
        )

        return jsonify({
            "file": {
                "id": file.id,
                "filename": file.filename,
                "file_size": f"{round(file.file_size / 1024, 1)} KB",
                "classification": file.classification.classification_label if file.classification else 'Confidential',
                "checksum": file.checksum,
                "integrity_status": integrity_status,
                "max_downloads": share.max_downloads,
                "downloads_count": share.downloads_count
            },
            "owner": share.file.owner.full_name,
            "expiry_time": share.expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            "status": share.status
        }), 200
    except Exception as e:
        return jsonify({"error": f"Failed to resolve shared link: {str(e)}"}), 500

def download_shared_file(token):
    share = FileSharing.query.filter_by(share_token=token).with_for_update().first()
    if not share:
        log_event(
            user_id=None,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Sharing link is invalid or not found"},
            status='failed'
        )
        return jsonify({"error": "Sharing link is invalid or not found"}), 404

    if share.max_downloads is not None and share.downloads_count >= share.max_downloads:
        share.status = 'expired'
        db.session.commit()
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='Download limit reached',
            severity='LOW',
            message=f"Download limit reached for shared file {share.file.filename if share.file else 'Unknown'}.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Download limit has been exceeded"},
            status='failed'
        )
        return jsonify({"error": "This sharing link has exceeded its download limit"}), 403

    if share.status != 'active':
        alert_type = 'Revoked share link access' if share.status == 'revoked' else 'Expired share link access'
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type=alert_type,
            severity='MEDIUM',
            message=f"Access attempt blocked on share token {token[:8]}... because token status is {share.status}.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": f"This sharing link has been {share.status}"},
            status='failed'
        )
        return jsonify({"error": f"This sharing link has been {share.status}"}), 403

    if share.expiry_time < datetime.utcnow():
        share.status = 'expired'
        db.session.commit()
        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='Expired share link access',
            severity='MEDIUM',
            message=f"A secure share link for {share.file.filename if share.file else 'Unknown'} has expired.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "This sharing link has expired"},
            status='failed'
        )
        return jsonify({"error": "This sharing link has expired"}), 403

    file = share.file
    if not file:
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Shared file metadata no longer exists"},
            status='failed'
        )
        return jsonify({"error": "Shared file metadata no longer exists"}), 404

    # Extract private key (demo uses fallback in zero-knowledge mode)
    private_key_pem = None
    if request.is_json:
        data = request.get_json() or {}
        private_key_pem = data.get('private_key')
    else:
        private_key_pem = request.form.get('private_key')

    classification = file.classification.classification_label if file.classification else 'Confidential'
    if classification == 'Secret':
        if not private_key_pem or private_key_pem.startswith("Secured on Server"):
            log_event(
                user_id=share.owner_id,
                action='SHARE_FAILED_ACCESS',
                module='Delegated Sharing',
                file_id=file.id,
                file_name=file.filename,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                details={"share_prefix": token[:8] + "..." if token else None, "reason": "Private decryption key is required to decrypt this Secret file"},
                status='failed'
            )
            return jsonify({"error": "Private decryption key is required to decrypt this Secret file"}), 400
    else:
        if not private_key_pem or private_key_pem.startswith("Secured on Server"):
            private_key_pem = file.owner.rsa_private_key

    vault_dir = os.path.join(current_app.instance_path, 'vault')
    file_path = os.path.join(vault_dir, f"{file.checksum}.enc")
    
    if not os.path.exists(file_path):
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=file.id,
            file_name=file.filename,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": "Encrypted file payload missing from vault"},
            status='failed'
        )
        return jsonify({"error": "Encrypted file payload missing from vault"}), 404

    try:
        with open(file_path, 'rb') as f:
            ciphertext_bytes = f.read()

        # Enforce file integrity checks
        integrity = FileIntegrity.query.filter_by(file_id=file.id).first()
        if integrity:
            from app.utils.integrity import verify_sha256
            if not verify_sha256(ciphertext_bytes, integrity.sha256_hash):
                log_event(
                    user_id=file.owner_id,
                    action='SHARE_FAILED_ACCESS',
                    module='Delegated Sharing',
                    file_id=file.id,
                    file_name=file.filename,
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string,
                    details={"filename": file.filename, "share_prefix": token[:8] + "...", "reason": "Security Block: File integrity check failed. Document has been tampered with!"},
                    status='failed'
                )
                return jsonify({"error": "Security Block: File integrity check failed. Document has been tampered with!"}), 400

        # Decrypt payload
        decrypted_bytes = decrypt_by_sensitivity(
            ciphertext_bytes=ciphertext_bytes,
            sensitivity=classification,
            encrypted_file_key_b64=file.keys[0].encrypted_file_key if file.keys else "",
            iv_b64=file.keys[0].iv_or_nonce if file.keys else "",
            tag_b64=file.keys[0].tag if file.keys else "",
            user_private_key_pem=private_key_pem,
            version=getattr(file.keys[0], 'version', 1) if file.keys else 1
        )

        # Increment download counter and auto-expire if limit met
        share.downloads_count += 1
        if share.max_downloads is not None and share.downloads_count >= share.max_downloads:
            share.status = 'expired'
            trigger_security_alert(
                user_id=share.owner_id,
                alert_type='Download limit reached',
                severity='LOW',
                message=f"Download limit reached for shared file {file.filename}.",
                file_id=file.id,
                category='SHARING',
                target_role='user'
            )
            log_event(
                user_id=share.owner_id,
                action='SHARE_EXPIRED',
                module='Delegated Sharing',
                file_id=file.id,
                file_name=file.filename,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                details={"filename": file.filename, "share_prefix": token[:8] + "...", "reason": "Download limit reached"},
                status='success'
            )
        db.session.commit()

        trigger_security_alert(
            user_id=share.owner_id,
            alert_type='Shared file accessed',
            severity='INFO',
            message=f"Shared file {file.filename} was successfully accessed and downloaded.",
            file_id=file.id,
            category='SHARING',
            target_role='user'
        )

        log_event(
            user_id=file.owner_id,
            action='SHARE_ACCESSED',
            module='Delegated Sharing',
            file_id=file.id,
            file_name=file.filename,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"filename": file.filename, "share_prefix": token[:8] + "...", "downloads_count": share.downloads_count},
            status='success'
        )

        from flask import make_response
        response = make_response(decrypted_bytes)
        response.headers['Content-Type'] = file.mime_type or 'application/octet-stream'
        response.headers['Content-Disposition'] = f'attachment; filename="{file.filename}"'
        return response

    except Exception as e:
        log_event(
            user_id=share.owner_id,
            action='SHARE_FAILED_ACCESS',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_prefix": token[:8] + "..." if token else None, "reason": f"Decryption failed: {str(e)}"},
            status='failed'
        )
        return jsonify({"error": "Decryption failed. Invalid keys, corrupted payload, or authentication failure."}), 400

def revoke_shared_link(current_user, share_id):
    share = FileSharing.query.filter_by(id=share_id, owner_id=current_user.id).first()
    if not share:
        return jsonify({"error": "Share link not found or access denied"}), 404

    try:
        share.status = 'revoked'
        db.session.commit()

        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Share link revoked',
            severity='LOW',
            message=f"A secure share link for {share.file.filename if share.file else 'Unknown'} has been revoked.",
            file_id=share.file_id,
            category='SHARING',
            target_role='user'
        )

        log_event(
            user_id=current_user.id,
            action='SHARE_REVOKED',
            module='Delegated Sharing',
            file_id=share.file_id,
            file_name=share.file.filename if share.file else None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            details={"share_id": share_id, "file_id": share.file_id},
            status='success'
        )

        return jsonify({"message": "Sharing link revoked successfully"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to revoke share link: {str(e)}"}), 500

def get_shared_history(current_user):
    sharings = FileSharing.query.filter_by(owner_id=current_user.id).order_by(FileSharing.created_at.desc()).all()
    history = []
    for s in sharings:
        status = s.status
        if status == 'active':
            if s.expiry_time < datetime.utcnow():
                s.status = 'expired'
                db.session.commit()
                status = 'expired'
            elif s.max_downloads is not None and s.downloads_count >= s.max_downloads:
                s.status = 'expired'
                db.session.commit()
                status = 'expired'

        share_base = current_app.config.get('SHARE_BASE_URL', 'http://localhost:5173')
        share_link = f"{share_base}/shared/{s.share_token}"

        history.append({
            "id": s.id,
            "file_id": s.file_id,
            "filename": s.file.filename if s.file else 'Unknown File',
            "share_token": s.share_token,
            "share_link": share_link,
            "qr_code": s.qr_code,
            "expiry_time": s.expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
            "status": status,
            "max_downloads": s.max_downloads,
            "downloads_count": s.downloads_count,
            "created_at": s.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(history), 200

# ==========================================
# 8. Cybersecurity Analytics & Reports (Module 5)
# ==========================================

def get_security_alerts_endpoint(current_user):
    severity = request.args.get('severity', 'ALL')
    status = request.args.get('status', 'ALL')
    
    if current_user.role == 'admin':
        query = SecurityAlert.query
    else:
        query = SecurityAlert.query.filter_by(user_id=current_user.id)
        
    if severity != 'ALL':
        query = query.filter_by(severity=severity)
    if status != 'ALL':
        query = query.filter_by(status=status)
        
    alerts = query.order_by(SecurityAlert.created_at.desc()).all()
    
    alerts_data = []
    for a in alerts:
        alerts_data.append({
            "id": a.id,
            "user_id": a.user_id,
            "type": a.alert_type,
            "severity": a.severity,
            "message": a.message,
            "status": 'active' if a.status == 'unresolved' else 'resolved',
            "timestamp": a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "ip_address": a.ip_address or '0.0.0.0',
            "created_at": a.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "resolved_at": a.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if a.resolved_at else None
        })
        
    return jsonify(alerts_data), 200

def get_statistics_endpoint(current_user):
    is_admin = current_user.role == 'admin'

    # 1. Classification distribution
    if is_admin:
        pub_count = FileClassification.query.filter_by(classification_label='Public').count()
        conf_count = FileClassification.query.filter_by(classification_label='Confidential').count()
        sec_count = FileClassification.query.filter_by(classification_label='Secret').count()
    else:
        pub_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Public').count()
        conf_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Confidential').count()
        sec_count = FileClassification.query.join(File).filter(File.owner_id == current_user.id, FileClassification.classification_label == 'Secret').count()

    # 2. Key algorithms distribution
    if is_admin:
        aes128_count = EncryptionKey.query.filter(EncryptionKey.key_type.like('%AES-128%')).count()
        aes256_count = EncryptionKey.query.filter(EncryptionKey.key_type.like('%AES-256%')).count()
        hybrid_count = EncryptionKey.query.filter(EncryptionKey.key_type.like('%Hybrid%')).count()
    else:
        aes128_count = EncryptionKey.query.join(File).filter(File.owner_id == current_user.id, EncryptionKey.key_type.like('%AES-128%')).count()
        aes256_count = EncryptionKey.query.join(File).filter(File.owner_id == current_user.id, EncryptionKey.key_type.like('%AES-256%')).count()
        hybrid_count = EncryptionKey.query.join(File).filter(File.owner_id == current_user.id, EncryptionKey.key_type.like('%Hybrid%')).count()

    # 3. Daily File Uploads (past 7 days)
    from sqlalchemy import func
    if is_admin:
        upload_stats = db.session.query(
            func.date(File.created_at).label('upload_date'),
            func.count(File.id).label('file_count')
        ).group_by(func.date(File.created_at)).order_by(func.date(File.created_at).desc()).limit(7).all()
    else:
        upload_stats = db.session.query(
            func.date(File.created_at).label('upload_date'),
            func.count(File.id).label('file_count')
        ).filter(File.owner_id == current_user.id).group_by(func.date(File.created_at)).order_by(func.date(File.created_at).desc()).limit(7).all()
    
    daily_uploads = {}
    for i in range(7):
        d = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        daily_uploads[d] = 0
        
    for stat in upload_stats:
        date_str = str(stat.upload_date)
        if date_str in daily_uploads:
            daily_uploads[date_str] = stat.file_count
            
    sorted_days = sorted(daily_uploads.keys())
    upload_trend = [daily_uploads[day] for day in sorted_days]

    # 4. Integrity audit statistics
    verified_count = 0
    tampered_count = 0
    
    if is_admin:
        integrities = FileIntegrity.query.all()
    else:
        integrities = FileIntegrity.query.join(File).filter(File.owner_id == current_user.id).all()
        
    vault_dir = os.path.join(current_app.instance_path, 'vault')
    for item in integrities:
        file = item.file
        if file:
            file_path = os.path.join(vault_dir, f"{file.checksum}.enc")
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    ciphertext_bytes = f.read()
                from app.utils.integrity import verify_sha256
                if verify_sha256(ciphertext_bytes, item.sha256_hash):
                    verified_count += 1
                else:
                    tampered_count += 1
            else:
                tampered_count += 1
                
    # 5. Sharing activity (FILE_SHARED or SHARE_ACCESSED events over past 7 days)
    if is_admin:
        share_stats = db.session.query(
            func.date(ActivityLog.timestamp).label('share_date'),
            func.count(ActivityLog.id).label('share_count')
        ).filter(ActivityLog.action.in_(['FILE_SHARED', 'SHARE_ACCESSED'])).group_by(func.date(ActivityLog.timestamp)).order_by(func.date(ActivityLog.timestamp).desc()).limit(7).all()
    else:
        share_stats = db.session.query(
            func.date(ActivityLog.timestamp).label('share_date'),
            func.count(ActivityLog.id).label('share_count')
        ).filter(ActivityLog.user_id == current_user.id).filter(ActivityLog.action.in_(['FILE_SHARED', 'SHARE_ACCESSED'])).group_by(func.date(ActivityLog.timestamp)).order_by(func.date(ActivityLog.timestamp).desc()).limit(7).all()
    
    daily_shares = {day: 0 for day in sorted_days}
    for stat in share_stats:
        date_str = str(stat.share_date)
        if date_str in daily_shares:
            daily_shares[date_str] = stat.share_count
            
    share_trend = [daily_shares[day] for day in sorted_days]

    # 6. Failed login attempts (LOGIN_FAILED events over past 7 days)
    if is_admin:
        login_fail_stats = db.session.query(
            func.date(ActivityLog.timestamp).label('fail_date'),
            func.count(ActivityLog.id).label('fail_count')
        ).filter(ActivityLog.action == 'LOGIN_FAILED').group_by(func.date(ActivityLog.timestamp)).order_by(func.date(ActivityLog.timestamp).desc()).limit(7).all()
    else:
        login_fail_stats = db.session.query(
            func.date(ActivityLog.timestamp).label('fail_date'),
            func.count(ActivityLog.id).label('fail_count')
        ).filter(ActivityLog.user_id == current_user.id).filter(ActivityLog.action == 'LOGIN_FAILED').group_by(func.date(ActivityLog.timestamp)).order_by(func.date(ActivityLog.timestamp).desc()).limit(7).all()
    
    daily_login_fails = {day: 0 for day in sorted_days}
    for stat in login_fail_stats:
        date_str = str(stat.fail_date)
        if date_str in daily_login_fails:
            daily_login_fails[date_str] = stat.fail_count
            
    login_fail_trend = [daily_login_fails[day] for day in sorted_days]

    return jsonify({
        "classification_pie": {
            "labels": ["Public", "Confidential", "Secret"],
            "data": [pub_count, conf_count, sec_count]
        },
        "algorithms_bar": {
            "labels": ["AES-128-GCM", "AES-256-GCM", "Hybrid (AES+RSA)"],
            "data": [aes128_count, aes256_count, hybrid_count]
        },
        "uploads_line": {
            "labels": sorted_days,
            "data": upload_trend
        },
        "integrity_doughnut": {
            "labels": ["Verified Intact", "Tampered/Missing"],
            "data": [verified_count, tampered_count]
        },
        "sharing_line": {
            "labels": sorted_days,
            "data": share_trend
        },
        "failed_logins_line": {
            "labels": sorted_days,
            "data": login_fail_trend
        }
    }), 200

# ==========================================
# Helpers
# ==========================================

def log_event(user_id, action, module='General', file_name=None, file_id=None, ip_address='0.0.0.0', user_agent=None, details=None, status='success'):
    # Security requirement: Sanitise sensitive properties from details
    sanitized_details = None
    if details:
        if isinstance(details, dict):
            sanitized_details = details.copy()
            sensitive_keys = ['password', 'private_key', 'token', 'aes_key', 'key', 'password_hash', 'secret']
            for k in list(sanitized_details.keys()):
                if any(sec in k.lower() for sec in sensitive_keys):
                    sanitized_details[k] = "[REDACTED_FOR_SECURITY]"
        else:
            sanitized_details = details

    log = ActivityLog(
        user_id=user_id,
        action=action,
        module=module,
        file_name=file_name,
        file_id=file_id,
        ip_address=ip_address,
        user_agent=user_agent,
        details=sanitized_details,
        status=status
    )
    db.session.add(log)
    db.session.commit()

def logout_endpoint(current_user):
    log_event(
        user_id=current_user.id,
        action='LOGOUT',
        module='Authentication',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"message": f"Operator session terminated for: {current_user.full_name}"},
        status='success'
    )
    return jsonify({"message": "Logout successful"}), 200

def get_users_list(current_user):
    if current_user.role != 'admin':
        trigger_security_alert(
            user_id=current_user.id,
            alert_type='Unauthorized API access',
            severity='HIGH',
            message=f"Non-admin user {current_user.email} attempted to query system-wide operators list"
        )
        # Log unauthorized access try
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='Authentication',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"reason": "Non-admin attempted to retrieve list of users"},
            status='blocked'
        )
        return jsonify({"error": "Unauthorized Access"}), 403

    users = User.query.order_by(User.full_name).all()
    users_data = [{"id": u.id, "full_name": u.full_name, "email": u.email} for u in users]
    return jsonify(users_data), 200

def trigger_security_alert(user_id, alert_type, severity, message, file_id=None, category='SYSTEM_SECURITY', event_type=None, target_role='user', title=None, related_audit_id=None):
    ip_addr = '0.0.0.0'
    u_agent = 'Unknown'
    try:
        if request:
            ip_addr = request.remote_addr or '0.0.0.0'
            u_agent = request.headers.get('User-Agent', 'Unknown')
    except RuntimeError:
        pass

    # Deduplication: check if an identical unresolved alert was created in the last 5 minutes
    from datetime import datetime, timedelta
    recent = SecurityAlert.query.filter_by(
        user_id=user_id,
        alert_type=alert_type,
        status='unresolved',
        target_role=target_role
    ).filter(SecurityAlert.created_at >= datetime.utcnow() - timedelta(minutes=5)).first()

    if recent:
        return recent

    alert = SecurityAlert(
        user_id=user_id,
        title=title or alert_type,
        alert_type=alert_type,
        severity=severity,
        message=message,
        category=category,
        event_type=event_type,
        target_role=target_role,
        is_read=False,
        ip_address=ip_addr,
        status='unresolved',
        related_file_id=file_id,
        related_audit_id=related_audit_id
    )
    db.session.add(alert)
    db.session.commit()

    # Log integration
    log_event(
        user_id=user_id,
        action='SECURITY_ALERT',
        module=category,
        file_id=file_id,
        ip_address=ip_addr,
        user_agent=u_agent,
        details={
            "alert_id": alert.id,
            "alert_type": alert_type,
            "severity": severity,
            "message": message
        },
        status='failed'
    )
    return alert

def get_user_notifications(current_user):
    alerts = SecurityAlert.query.filter_by(user_id=current_user.id, target_role='user').order_by(SecurityAlert.created_at.desc()).all()
    
    alerts_list = []
    for a in alerts:
        alerts_list.append({
            "id": a.id,
            "title": a.title or a.alert_type,
            "alert_type": a.alert_type,
            "message": a.message,
            "severity": a.severity,
            "category": a.category,
            "event_type": a.event_type,
            "is_read": a.is_read,
            "created_at": a.created_at.strftime('%Y-%m-%d %H:%M:%S') if a.created_at else None,
            "read_at": a.read_at.strftime('%Y-%m-%d %H:%M:%S') if a.read_at else None,
            "related_file_id": a.related_file_id
        })
    
    unread_count = SecurityAlert.query.filter_by(user_id=current_user.id, target_role='user', is_read=False).count()
    
    return jsonify({
        "notifications": alerts_list,
        "unread_count": unread_count
    }), 200

def get_user_unread_count(current_user):
    unread_count = SecurityAlert.query.filter_by(user_id=current_user.id, target_role='user', is_read=False).count()
    return jsonify({"unread_count": unread_count}), 200

def mark_notification_read(current_user, alert_id):
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({"error": "Notification not found"}), 404
    
    if alert.user_id != current_user.id:
        return jsonify({"error": "Access denied"}), 403
    
    alert.is_read = True
    alert.read_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Notification marked as read successfully"}), 200

def mark_all_notifications_read(current_user):
    unread_alerts = SecurityAlert.query.filter_by(user_id=current_user.id, target_role='user', is_read=False).all()
    for a in unread_alerts:
        a.is_read = True
        a.read_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "All notifications marked as read successfully"}), 200

def get_admin_alerts(current_user):
    if current_user.role != 'admin':
        return jsonify({"error": "Access denied"}), 403
        
    severity = request.args.get('severity', 'ALL')
    category = request.args.get('category', 'ALL')
    status = request.args.get('status', 'ALL')
    event_type = request.args.get('event_type', 'ALL')

    query = SecurityAlert.query.filter_by(target_role='admin')

    if severity != 'ALL':
        query = query.filter_by(severity=severity)
    if category != 'ALL':
        query = query.filter_by(category=category)
    if status != 'ALL':
        query = query.filter_by(status=status)
    if event_type != 'ALL':
        query = query.filter_by(event_type=event_type)

    alerts = query.order_by(SecurityAlert.created_at.desc()).all()
    
    alerts_list = []
    for a in alerts:
        alerts_list.append({
            "id": a.id,
            "title": a.title or a.alert_type,
            "alert_type": a.alert_type,
            "message": a.message,
            "severity": a.severity,
            "category": a.category,
            "event_type": a.event_type,
            "is_read": a.is_read,
            "status": a.status,
            "created_at": a.created_at.strftime('%Y-%m-%d %H:%M:%S') if a.created_at else None,
            "read_at": a.read_at.strftime('%Y-%m-%d %H:%M:%S') if a.read_at else None,
            "resolved_at": a.resolved_at.strftime('%Y-%m-%d %H:%M:%S') if a.resolved_at else None,
            "resolved_by": a.resolved_by,
            "ip_address": a.ip_address,
            "user_id": a.user_id,
            "related_file_id": a.related_file_id
        })
        
    return jsonify(alerts_list), 200

def get_admin_unread_count(current_user):
    if current_user.role != 'admin':
        return jsonify({"error": "Access denied"}), 403
    unread_count = SecurityAlert.query.filter_by(target_role='admin', is_read=False).count()
    return jsonify({"unread_count": unread_count}), 200

def mark_admin_alert_read(current_user, alert_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Access denied"}), 403
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
        
    alert.is_read = True
    alert.read_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"message": "Alert marked as read successfully"}), 200

def resolve_admin_alert(current_user, alert_id):
    if current_user.role != 'admin':
        log_event(
            user_id=current_user.id,
            action='UNAUTHORIZED_ACCESS',
            module='General',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', 'Unknown'),
            details={"reason": "Attempted to resolve security alert as non-admin", "alert_id": alert_id},
            status='blocked'
        )
        return jsonify({"error": "Access denied"}), 403
        
    alert = db.session.get(SecurityAlert, alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
        
    alert.status = 'resolved'
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = current_user.id
    db.session.commit()

    log_event(
        user_id=current_user.id,
        action='ALERT_RESOLVED',
        module='General',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        details={"alert_id": alert_id, "alert_type": alert.alert_type},
        status='success'
    )
    return jsonify({
        "message": "Alert marked as resolved successfully",
        "alert": {
            "id": alert.id,
            "status": "resolved",
            "resolved_at": alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    }), 200

resolve_security_alert_endpoint = resolve_admin_alert
