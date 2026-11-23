import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cipherguard-super-secret-key-2026')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'cipherguard-jwt-token-signing-secret')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    
    # Determine Database URI from unified URL or discrete environment parameters
    _db_url = os.environ.get('DATABASE_URL')
    if not _db_url:
        _db_user = os.environ.get('DB_USER') or os.environ.get('DATABASE_USER')
        _db_pass = os.environ.get('DB_PASSWORD') or os.environ.get('DATABASE_PASSWORD')
        _db_host = os.environ.get('DB_HOST') or os.environ.get('DATABASE_HOST')
        _db_port = os.environ.get('DB_PORT') or os.environ.get('DATABASE_PORT', '3306')
        _db_name = os.environ.get('DB_NAME') or os.environ.get('DATABASE_NAME')
        
        if _db_host and _db_name and _db_user:
            # URL-encode password if needed
            from urllib.parse import quote_plus
            encoded_pass = quote_plus(_db_pass) if _db_pass else ""
            _db_url = f"mysql+pymysql://{_db_user}:{encoded_pass}@{_db_host}:{_db_port}/{_db_name}?charset=utf8mb4"
        else:
            _db_url = 'sqlite:///cipherguard.db'

    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Production-grade connection pooling and health-check options
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 3600,
    }
    # Only configure pool size options on non-sqlite databases
    if not _db_url.startswith('sqlite'):
        SQLALCHEMY_ENGINE_OPTIONS.update({
            "pool_size": int(os.environ.get('DB_POOL_SIZE', '10')),
            "max_overflow": int(os.environ.get('DB_MAX_OVERFLOW', '20')),
        })
    
    # Upload size limit (10 MB)
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    
    # Base URL for secure file share links
    SHARE_BASE_URL = os.environ.get('SHARE_BASE_URL', 'http://localhost:5173')
    
    # AI Classification Model settings
    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        'AI', 
        'classifier.pkl'
    )

