from datetime import datetime
from app.database.connection import db

class User(db.Model):
    __tablename__ = 'Users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    two_factor_secret = db.Column(db.String(100), nullable=True)
    role = db.Column(db.Enum('admin', 'user'), nullable=False, default='user')
    status = db.Column(db.Enum('active', 'suspended'), nullable=False, default='active')
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Cryptographic Vault Keypair (zero-knowledge or demo)
    rsa_public_key = db.Column(db.Text, nullable=True)
    rsa_private_key = db.Column(db.Text, nullable=True)


    # Relationships
    files = db.relationship('File', backref='owner', cascade='all, delete-orphan')
    encryption_keys = db.relationship('EncryptionKey', backref='user', cascade='all, delete-orphan')
    classifications = db.relationship('ClassificationHistory', backref='user', cascade='all, delete-orphan')


class File(db.Model):
    __tablename__ = 'Files'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    checksum = db.Column(db.String(64), nullable=False) # SHA-256
    is_encrypted = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    classification = db.relationship('FileClassification', backref='file', uselist=False, cascade='all, delete-orphan')
    keys = db.relationship('EncryptionKey', backref='file', cascade='all, delete-orphan')
    shares = db.relationship('FileSharing', backref='file', cascade='all, delete-orphan')

class EncryptionKey(db.Model):
    __tablename__ = 'EncryptionKeys'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    encrypted_file_key = db.Column(db.Text, nullable=False)
    key_type = db.Column(db.String(100), nullable=False, default='AES-256-GCM')
    iv_or_nonce = db.Column(db.String(100), nullable=False)
    tag = db.Column(db.String(100), nullable=True)
    encryption_time_ms = db.Column(db.Float, nullable=True, default=0.0)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class FileClassification(db.Model):
    __tablename__ = 'FileClassification'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, unique=True)
    classification_label = db.Column(db.Enum('Public', 'Confidential', 'Secret'), nullable=False, default='Confidential')
    dlp_risk_score = db.Column(db.Numeric(5, 2), nullable=False, default=0.00)
    contains_pii = db.Column(db.Boolean, nullable=False, default=False)
    contains_credentials = db.Column(db.Boolean, nullable=False, default=False)
    contains_ip = db.Column(db.Boolean, nullable=False, default=False)
    classified_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class FileIntegrity(db.Model):
    __tablename__ = 'FileIntegrity'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, unique=True)
    sha256_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationships
    file = db.relationship('File', backref=db.backref('integrity', uselist=False, cascade='all, delete-orphan'))

class FileSharing(db.Model):
    __tablename__ = 'FileSharing'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    share_token = db.Column(db.String(100), unique=True, nullable=False)
    qr_code = db.Column(db.Text, nullable=True)
    expiry_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum('active', 'revoked', 'expired'), nullable=False, default='active')
    max_downloads = db.Column(db.Integer, nullable=True)
    downloads_count = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class ActivityLog(db.Model):
    __tablename__ = 'ActivityLogs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    module = db.Column(db.String(100), nullable=False, default='General')
    file_name = db.Column(db.String(255), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='SET NULL'), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    status = db.Column(db.Enum('success', 'failed', 'blocked'), nullable=False, default='success')
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class ClassificationHistory(db.Model):
    __tablename__ = 'ClassificationHistory'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    category = db.Column(db.Enum('Public', 'Confidential', 'Secret'), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class IntegrityHistory(db.Model):
    __tablename__ = 'IntegrityHistory'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    result = db.Column(db.Enum('VERIFIED', 'TAMPERED'), nullable=False)

    # Relationships
    file = db.relationship('File', backref=db.backref('integrity_history', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('integrity_history', cascade='all, delete-orphan'))


