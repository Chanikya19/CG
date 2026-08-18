from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta, timezone
from app.models.models import User, ActivityLog, SecurityAlert
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
            alert = SecurityAlert(
                user_id=None,
                alert_type='Unauthorized API access',
                severity='LOW',
                message="API request rejected due to missing Authorization header token.",
                ip_address=request.remote_addr,
                status='unresolved'
            )
            db.session.add(alert)
            log = ActivityLog(
                user_id=None,
                action='UNAUTHORIZED_ACCESS',
                module='Authentication',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='blocked',
                details={"reason": "Session token missing"}
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({"error": "Session token missing. Authorization required."}), 401

        user_id = decode_auth_token(token)
        if not user_id:
            alert = SecurityAlert(
                user_id=None,
                alert_type='Unauthorized API access',
                severity='LOW',
                message="API request rejected due to invalid or expired JWT token.",
                ip_address=request.remote_addr,
                status='unresolved'
            )
            db.session.add(alert)
            log = ActivityLog(
                user_id=None,
                action='UNAUTHORIZED_ACCESS',
                module='Authentication',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='blocked',
                details={"reason": "Session token invalid or expired"}
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({"error": "Session token invalid or expired."}), 401

        current_user = db.session.get(User, user_id)
        if not current_user:
            alert = SecurityAlert(
                user_id=None,
                alert_type='Unauthorized API access',
                severity='MEDIUM',
                message=f"API request rejected: user profile associated with token (ID {user_id}) not found.",
                ip_address=request.remote_addr,
                status='unresolved'
            )
            db.session.add(alert)
            log = ActivityLog(
                user_id=None,
                action='UNAUTHORIZED_ACCESS',
                module='Authentication',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='blocked',
                details={"reason": f"User profile association failed for ID {user_id}"}
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({"error": "User profile associated with token not found."}), 401

        if current_user.status != 'active':
            alert = SecurityAlert(
                user_id=current_user.id,
                alert_type='Unauthorized API access',
                severity='HIGH',
                message=f"Suspended operator {current_user.email} attempted to access protected API route.",
                ip_address=request.remote_addr,
                status='unresolved'
            )
            db.session.add(alert)
            log = ActivityLog(
                user_id=current_user.id,
                action='UNAUTHORIZED_ACCESS',
                module='Authentication',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', 'Unknown'),
                status='blocked',
                details={"reason": "User account suspended"}
            )
            db.session.add(log)
            db.session.commit()
            return jsonify({"error": "User account has been suspended."}), 403

        return f(current_user, *args, **kwargs)

    return decorated
