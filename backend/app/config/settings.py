import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cipherguard-super-secret-key-2026')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'cipherguard-jwt-token-signing-secret')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    
    # Configure database URI pointing to MySQL or local SQLite fallback
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        'sqlite:///cipherguard.db'
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
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
