from flask import Flask
from flask_cors import CORS
from app.config.settings import Config
from app.database.connection import db
from app.routes.api import api_bp

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Enable CORS for frontend requests
    CORS(app)

    # Initialize SQLAlchemy database instance
    db.init_app(app)

    # Register API blueprint routes under prefix /api
    app.register_blueprint(api_bp, url_prefix='/api')

    # Default root homepage route
    @app.route('/')
    def index():
        return "CipherGuard Backend Running"

    # Automatically create database tables locally
    with app.app_context():
        db.create_all()

    return app
