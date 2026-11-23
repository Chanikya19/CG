from flask import Flask, jsonify
from flask_cors import CORS
from app.config.settings import Config
from app.database.connection import db
from app.routes.api import api_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Raise startup exception for hardcoded secrets in production/development runtime mode
    if not app.config.get('TESTING'):
        if app.config.get('JWT_SECRET') == 'cipherguard-jwt-token-signing-secret':
            raise RuntimeError("CRITICAL CONFIGURATION ERROR: You must configure a secure JWT_SECRET environment variable.")
        if app.config.get('SECRET_KEY') == 'cipherguard-super-secret-key-2026':
            raise RuntimeError("CRITICAL CONFIGURATION ERROR: You must configure a secure SECRET_KEY environment variable.")

    # Enable CORS for frontend requests
    CORS(app)

    # Initialize SQLAlchemy database instance
    db.init_app(app)

    # Register API blueprint routes under prefix /api
    app.register_blueprint(api_bp, url_prefix='/api')

    # Register 413 Request Entity Too Large error handler
    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({"error": "File size exceeds the maximum limit of 10MB"}), 413

    # Default root homepage route
    @app.route('/')
    def index():
        return "CipherGuard Backend Running"

    # Automatically create and migrate database tables safely
    with app.app_context():
        db.create_all()

        # List of incremental non-destructive column migrations (MySQL & SQLite compatible)
        migrations = [
            ("EncryptionKeys", "version INT DEFAULT 1"),
            ("Users", "failed_login_attempts INT DEFAULT 0"),
            ("Users", "lockout_until DATETIME DEFAULT NULL"),
            ("FileSharing", "max_downloads INT DEFAULT NULL"),
            ("FileSharing", "downloads_count INT DEFAULT 0"),
            ("FileSharing", "last_accessed_at DATETIME DEFAULT NULL"),
            ("FileClassification", "model_version VARCHAR(50) DEFAULT '1.0.0'"),
            ("FileIntegrity", "integrity_status VARCHAR(50) DEFAULT 'VALID'"),
            ("FileIntegrity", "last_verified_at DATETIME DEFAULT NULL"),
            ("FileIntegrity", "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"),
            ("IntegrityHistory", "previous_hash VARCHAR(64) DEFAULT NULL"),
            ("IntegrityHistory", "current_hash VARCHAR(64) DEFAULT NULL"),
            ("IntegrityHistory", "remarks VARCHAR(255) DEFAULT NULL"),
            ("ActivityLogs", "file_id INT DEFAULT NULL"),
            ("SecurityAlerts", "ip_address VARCHAR(45) DEFAULT '0.0.0.0'"),
            ("SecurityAlerts", "resolved_at DATETIME DEFAULT NULL"),
            ("SecurityAlerts", "title VARCHAR(150) DEFAULT NULL"),
            ("SecurityAlerts", "category VARCHAR(100) DEFAULT 'SYSTEM_SECURITY'"),
            ("SecurityAlerts", "event_type VARCHAR(100) DEFAULT NULL"),
            ("SecurityAlerts", "target_role VARCHAR(50) DEFAULT 'user'"),
            ("SecurityAlerts", "is_read BOOLEAN DEFAULT 0"),
            ("SecurityAlerts", "read_at DATETIME DEFAULT NULL"),
            ("SecurityAlerts", "resolved_by INT DEFAULT NULL"),
            ("SecurityAlerts", "related_file_id INT DEFAULT NULL"),
            ("SecurityAlerts", "related_audit_id INT DEFAULT NULL"),
        ]

        for table_name, col_def in migrations:
            try:
                column_name = col_def.split()[0]
                if db.engine.dialect.name == 'sqlite':
                    rows = db.session.execute(
                        db.text(f"PRAGMA table_info('{table_name}')")
                    ).mappings().all()
                    existing_columns = {row['name'] for row in rows}
                else:
                    from sqlalchemy import inspect
                    existing_columns = {
                        column['name']
                        for column in inspect(db.engine).get_columns(table_name)
                    }

                if column_name not in existing_columns:
                    sqlite_col_def = col_def
                    if db.engine.dialect.name == 'sqlite' and 'DEFAULT CURRENT_TIMESTAMP' in col_def:
                        sqlite_col_def = col_def.replace('DEFAULT CURRENT_TIMESTAMP', 'DEFAULT NULL')
                    db.session.execute(db.text(f"ALTER TABLE {table_name} ADD COLUMN {sqlite_col_def}"))
                    db.session.commit()
            except Exception:
                db.session.rollback()

        # Add indexes for high-performance querying
        indexes = [
            # SecurityAlerts
            ('idx_alerts_user_id', 'SecurityAlerts', 'user_id'),
            ('idx_alerts_is_read', 'SecurityAlerts', 'is_read'),
            ('idx_alerts_severity', 'SecurityAlerts', 'severity'),
            ('idx_alerts_status', 'SecurityAlerts', 'status'),
            ('idx_alerts_created_at', 'SecurityAlerts', 'created_at'),
            ('idx_alerts_category', 'SecurityAlerts', 'category'),
            # Users
            ('idx_users_email', 'Users', 'email'),
            ('idx_users_created_at', 'Users', 'created_at'),
            # Files
            ('idx_files_owner_id', 'Files', 'owner_id'),
            ('idx_files_created_at', 'Files', 'created_at'),
            # FileSharing
            ('idx_sharing_file_id', 'FileSharing', 'file_id'),
            ('idx_sharing_owner_id', 'FileSharing', 'owner_id'),
            ('idx_sharing_token', 'FileSharing', 'share_token'),
            # ActivityLogs
            ('idx_activity_user_id', 'ActivityLogs', 'user_id'),
            ('idx_activity_file_id', 'ActivityLogs', 'file_id'),
            ('idx_activity_action', 'ActivityLogs', 'action'),
            ('idx_activity_timestamp', 'ActivityLogs', 'timestamp'),
            # IntegrityHistory
            ('idx_integrity_file_id', 'IntegrityHistory', 'file_id'),
            ('idx_integrity_user_id', 'IntegrityHistory', 'user_id'),
            ('idx_integrity_timestamp', 'IntegrityHistory', 'timestamp'),
            # LoginAttempts
            ('idx_login_user_id', 'LoginAttempts', 'user_id'),
            ('idx_login_email', 'LoginAttempts', 'email'),
            ('idx_login_attempted_at', 'LoginAttempts', 'attempted_at'),
        ]

        for index_name, table_name, column_name in indexes:
            try:
                db.session.execute(db.text(f"CREATE INDEX {index_name} ON {table_name} ({column_name})"))
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Bootstrap admin user from environment variables
        from app.utils.bootstrap import bootstrap_admin
        bootstrap_admin(app)

    return app
