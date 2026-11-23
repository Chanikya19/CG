from datetime import datetime
from app.database.connection import db

class User(db.Model):
    __tablename__ = 'Users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    two_factor_secret = db.Column(db.String(100), nullable=True)
    role = db.Column(db.Enum('admin', 'user'), nullable=False, default='user')
    status = db.Column(db.Enum('active', 'suspended'), nullable=False, default='active')
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Cryptographic Vault Keypair (zero-knowledge key management)
    rsa_public_key = db.Column(db.Text, nullable=True)
    _rsa_private_key = db.Column('rsa_private_key', db.Text, nullable=True)

    # Property Aliases for schema compatibility
    @property
    def name(self):
        return self.full_name

    @name.setter
    def name(self, val):
        self.full_name = val

    @property
    def is_active(self):
        return self.status == 'active'

    @is_active.setter
    def is_active(self, val):
        self.status = 'active' if val else 'suspended'

    @property
    def failed_login_count(self):
        return self.failed_login_attempts

    @failed_login_count.setter
    def failed_login_count(self, val):
        self.failed_login_attempts = val

    @property
    def locked_until(self):
        return self.lockout_until

    @locked_until.setter
    def locked_until(self, val):
        self.lockout_until = val

    @property
    def rsa_private_key(self):
        if not self._rsa_private_key:
            return None
        from app.encryption.hybrid_engine import get_server_master_key
        from app.encryption.aes_engine import decrypt_aes_gcm
        import base64
        try:
            packed = base64.b64decode(self._rsa_private_key)
            iv = packed[:12]
            tag = packed[12:28]
            ciphertext = packed[28:]
            server_key = get_server_master_key()
            decrypted = decrypt_aes_gcm(server_key, ciphertext, iv, tag)
            return decrypted.decode('utf-8')
        except Exception:
            # Fallback for unencrypted legacy keys during testing or migration
            return self._rsa_private_key

    @rsa_private_key.setter
    def rsa_private_key(self, val):
        if not val:
            self._rsa_private_key = None
            return
        from app.encryption.hybrid_engine import get_server_master_key
        from app.encryption.aes_engine import encrypt_aes_gcm
        import base64
        try:
            server_key = get_server_master_key()
            ciphertext, iv, tag = encrypt_aes_gcm(server_key, val.encode('utf-8'))
            self._rsa_private_key = base64.b64encode(iv + tag + ciphertext).decode('utf-8')
        except Exception:
            self._rsa_private_key = val

    # Relationships
    files = db.relationship('File', backref='owner', cascade='all, delete-orphan')
    encryption_keys = db.relationship('EncryptionKey', backref='user', cascade='all, delete-orphan')
    classifications = db.relationship('ClassificationHistory', backref='user', cascade='all, delete-orphan')
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy='dynamic')


class File(db.Model):
    __tablename__ = 'Files'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    checksum = db.Column(db.String(64), nullable=False) # SHA-256
    is_encrypted = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Property Aliases for schema compatibility
    @property
    def user_id(self):
        return self.owner_id

    @user_id.setter
    def user_id(self, val):
        self.owner_id = val

    @property
    def original_filename(self):
        return self.filename

    @original_filename.setter
    def original_filename(self, val):
        self.filename = val

    @property
    def stored_filename(self):
        return self.file_path

    @stored_filename.setter
    def stored_filename(self, val):
        self.file_path = val

    @property
    def uploaded_at(self):
        return self.created_at

    @property
    def sha256_hash(self):
        return self.checksum

    @sha256_hash.setter
    def sha256_hash(self, val):
        self.checksum = val

    @property
    def sensitivity_level(self):
        if self.classification:
            return self.classification.classification_label
        return 'Confidential'

    @property
    def status(self):
        return 'encrypted' if self.is_encrypted else 'active'

    # Relationships
    classification = db.relationship('FileClassification', backref='file', uselist=False, cascade='all, delete-orphan')
    keys = db.relationship('EncryptionKey', backref='file', cascade='all, delete-orphan')
    shares = db.relationship('FileSharing', backref='file', cascade='all, delete-orphan')


class EncryptionKey(db.Model):
    __tablename__ = 'EncryptionKeys'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False, index=True)
    encrypted_file_key = db.Column(db.Text, nullable=False)
    key_type = db.Column(db.String(100), nullable=False, default='AES-256-GCM')
    iv_or_nonce = db.Column(db.String(100), nullable=False)
    tag = db.Column(db.String(100), nullable=True)
    encryption_time_ms = db.Column(db.Float, nullable=True, default=0.0)
    version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Property Aliases for schema compatibility
    @property
    def algorithm(self):
        return self.key_type

    @algorithm.setter
    def algorithm(self, val):
        self.key_type = val

    @property
    def key_reference(self):
        return self.encrypted_file_key

    @key_reference.setter
    def key_reference(self, val):
        self.encrypted_file_key = val

    @property
    def iv(self):
        return self.iv_or_nonce

    @iv.setter
    def iv(self, val):
        self.iv_or_nonce = val


class FileClassification(db.Model):
    __tablename__ = 'FileClassification'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    classification_label = db.Column(db.Enum('Public', 'Confidential', 'Secret'), nullable=False, default='Confidential')
    dlp_risk_score = db.Column(db.Numeric(5, 2), nullable=False, default=0.00)
    model_version = db.Column(db.String(50), nullable=False, default='1.0.0')
    contains_pii = db.Column(db.Boolean, nullable=False, default=False)
    contains_credentials = db.Column(db.Boolean, nullable=False, default=False)
    contains_ip = db.Column(db.Boolean, nullable=False, default=False)
    classified_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Property Aliases for schema compatibility
    @property
    def classification(self):
        return self.classification_label

    @classification.setter
    def classification(self, val):
        self.classification_label = val

    @property
    def confidence_score(self):
        return float(self.dlp_risk_score)

    @confidence_score.setter
    def confidence_score(self, val):
        self.dlp_risk_score = val


class FileIntegrity(db.Model):
    __tablename__ = 'FileIntegrity'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    sha256_hash = db.Column(db.String(64), nullable=False)
    integrity_status = db.Column(db.String(50), nullable=False, default='VALID')
    last_verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    file = db.relationship('File', backref=db.backref('integrity', uselist=False, cascade='all, delete-orphan'))


class FileSharing(db.Model):
    __tablename__ = 'FileSharing'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False, index=True)
    share_token = db.Column(db.String(100), unique=True, nullable=False, index=True)
    qr_code = db.Column(db.Text, nullable=True)
    expiry_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum('active', 'revoked', 'expired'), nullable=False, default='active')
    max_downloads = db.Column(db.Integer, nullable=True)
    downloads_count = db.Column(db.Integer, nullable=False, default=0)
    last_accessed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Property Aliases for schema compatibility
    @property
    def token(self):
        return self.share_token

    @token.setter
    def token(self, val):
        self.share_token = val

    @property
    def expires_at(self):
        return self.expiry_time

    @expires_at.setter
    def expires_at(self, val):
        self.expiry_time = val

    @property
    def download_count(self):
        return self.downloads_count

    @download_count.setter
    def download_count(self, val):
        self.downloads_count = val

    @property
    def is_active(self):
        return self.status == 'active'

    @is_active.setter
    def is_active(self, val):
        self.status = 'active' if val else 'revoked'


class ActivityLog(db.Model):
    __tablename__ = 'ActivityLogs'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='SET NULL'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    module = db.Column(db.String(100), nullable=False, default='General')
    file_name = db.Column(db.String(255), nullable=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.JSON, nullable=True)
    status = db.Column(db.Enum('success', 'failed', 'blocked'), nullable=False, default='success')
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Property Aliases for schema compatibility
    @property
    def event_type(self):
        return self.module

    @event_type.setter
    def event_type(self, val):
        self.module = val

    @property
    def description(self):
        return self.details

    @description.setter
    def description(self, val):
        self.details = val

    @property
    def created_at(self):
        return self.timestamp

    @created_at.setter
    def created_at(self, val):
        self.timestamp = val


class ClassificationHistory(db.Model):
    __tablename__ = 'ClassificationHistory'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    category = db.Column(db.Enum('Public', 'Confidential', 'Secret'), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class IntegrityHistory(db.Model):
    __tablename__ = 'IntegrityHistory'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='CASCADE'), nullable=False, index=True)
    previous_hash = db.Column(db.String(64), nullable=True)
    current_hash = db.Column(db.String(64), nullable=True)
    result = db.Column(db.Enum('VERIFIED', 'TAMPERED'), nullable=False)
    remarks = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Property Aliases for schema compatibility
    @property
    def status(self):
        return self.result

    @status.setter
    def status(self, val):
        self.result = val

    @property
    def verified_at(self):
        return self.timestamp

    @verified_at.setter
    def verified_at(self, val):
        self.timestamp = val

    # Relationships
    file = db.relationship('File', backref=db.backref('integrity_history', cascade='all, delete-orphan'))
    user = db.relationship('User', backref=db.backref('integrity_history', cascade='all, delete-orphan'))


class SecurityAlert(db.Model):
    __tablename__ = 'SecurityAlerts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='SET NULL'), nullable=True, index=True)
    title = db.Column(db.String(150), nullable=True)
    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(50), nullable=False, default='MEDIUM', index=True)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100), nullable=False, default='SYSTEM_SECURITY', index=True)
    event_type = db.Column(db.String(100), nullable=True)
    target_role = db.Column(db.String(50), nullable=False, default='user')
    is_read = db.Column(db.Boolean, nullable=False, default=False, index=True)
    read_at = db.Column(db.DateTime, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True, default='0.0.0.0')
    status = db.Column(db.String(50), nullable=False, default='unresolved', index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='SET NULL'), nullable=True)
    related_file_id = db.Column(db.Integer, db.ForeignKey('Files.id', ondelete='SET NULL'), nullable=True)
    related_audit_id = db.Column(db.Integer, db.ForeignKey('ActivityLogs.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)

    # Property Aliases for schema compatibility
    @property
    def audience(self):
        return self.target_role

    @audience.setter
    def audience(self, val):
        self.target_role = val

    @property
    def file_id(self):
        return self.related_file_id

    @file_id.setter
    def file_id(self, val):
        self.related_file_id = val

    # Relationship
    user_rel = db.relationship('User', foreign_keys=[user_id], backref=db.backref('alerts', cascade='all, delete-orphan'))


class LoginAttempt(db.Model):
    __tablename__ = 'LoginAttempts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id', ondelete='SET NULL'), nullable=True, index=True)
    email = db.Column(db.String(100), nullable=False, index=True)
    success = db.Column(db.Boolean, nullable=False, default=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, default='0.0.0.0')
    attempted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    failure_reason = db.Column(db.String(255), nullable=True)


# Relational Model Aliases matching entity requirements
users = User
files = File
file_classifications = FileClassification
encryption_metadata = EncryptionKey
file_integrity = FileIntegrity
integrity_history = IntegrityHistory
share_links = FileSharing
audit_logs = ActivityLog
alerts = SecurityAlert
login_attempts = LoginAttempt
