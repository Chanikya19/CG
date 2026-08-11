import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cipherguard-super-secret-key-2026')
    JWT_SECRET = os.environ.get('JWT_SECRET', 'cipherguard-jwt-token-signing-secret')
    
    # Configure database URI pointing to MySQL or local SQLite fallback
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        'sqlite:///cipherguard.db'
    )
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # AI Classification Model settings
    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        'AI', 
        'classifier.pkl'
    )
