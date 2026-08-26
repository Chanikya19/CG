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

    # Automatically create database tables locally
    with app.app_context():
        db.create_all()
        # Gracefully add version column to EncryptionKeys if not present (SQLite & MySQL compatible)
        try:
            db.session.execute(db.text("ALTER TABLE EncryptionKeys ADD COLUMN version INT DEFAULT 1"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Gracefully add failed_login_attempts and lockout_until to Users if not present
        try:
            db.session.execute(db.text("ALTER TABLE Users ADD COLUMN failed_login_attempts INT DEFAULT 0"))
            db.session.execute(db.text("ALTER TABLE Users ADD COLUMN lockout_until DATETIME"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Gracefully add max_downloads and downloads_count to FileSharing if not present
        try:
            db.session.execute(db.text("ALTER TABLE FileSharing ADD COLUMN max_downloads INT DEFAULT NULL"))
            db.session.execute(db.text("ALTER TABLE FileSharing ADD COLUMN downloads_count INT DEFAULT 0"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Gracefully add file_id to ActivityLogs if not present
        try:
            db.session.execute(db.text("ALTER TABLE ActivityLogs ADD COLUMN file_id INT DEFAULT NULL"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Gracefully add ip_address to SecurityAlerts if not present
        try:
            db.session.execute(db.text("ALTER TABLE SecurityAlerts ADD COLUMN ip_address VARCHAR(45) DEFAULT '0.0.0.0'"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # Gracefully add resolved_at to SecurityAlerts if not present
        try:
            db.session.execute(db.text("ALTER TABLE SecurityAlerts ADD COLUMN resolved_at DATETIME DEFAULT NULL"))
            db.session.commit()
        except Exception:
            db.session.rollback()

    return app
