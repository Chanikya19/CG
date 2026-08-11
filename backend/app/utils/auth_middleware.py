from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta, timezone
from app.models.models import User
from app.database.connection import db

def encode_auth_token(user_id):
    """
    Generates a cryptographically signed secure JSON Web Token (JWT).
    """
    try:
        payload = {
            'exp': datetime.now(timezone.utc) + timedelta(days=1),
            'iat': datetime.now(timezone.utc),
            'sub': str(user_id)
        }
        return jwt.encode(
            payload,
            current_app.config['JWT_SECRET'],
            algorithm='HS256'
        )
    except Exception as e:
        return None

def decode_auth_token(token):
    """
    Decodes and verifies the JSON Web Token (JWT).
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET'],
            algorithms=['HS256']
        )
        return int(payload['sub'])
    except:
        return None

def token_required(f):
    """
    Flask endpoint decorator that verifies the token inside the Authorization header.
    Passes current_user object to the wrapped route handler.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Look for token in Authorization header (Bearer <token>)
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Session token missing. Authorization required."}), 401

        user_id = decode_auth_token(token)
        if not user_id:
            return jsonify({"error": "Session token invalid or expired."}), 401

        current_user = db.session.get(User, user_id)
        if not current_user:
            return jsonify({"error": "User profile associated with token not found."}), 401

        if current_user.status != 'active':
            return jsonify({"error": "User account has been suspended."}), 403

        return f(current_user, *args, **kwargs)

    return decorated
