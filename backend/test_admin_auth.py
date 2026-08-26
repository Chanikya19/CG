import unittest
import os
import sys
import tempfile
import shutil
import json
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, FileSharing, FileClassification, FileIntegrity, ActivityLog, SecurityAlert, EncryptionKey
from app.utils.auth_middleware import encode_auth_token
from app.utils.bootstrap import bootstrap_admin

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-321'
    JWT_SECRET = 'test-jwt-secret-321'
    ADMIN_EMAIL = 'admin_bootstrap@cipherguard.test'
    ADMIN_PASSWORD = 'BootstrapPassword123!'

class TestCipherGuardAdminAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.app = create_app(TestConfig)
        cls.app.instance_path = cls.temp_dir
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        db.session.remove()
        db.drop_all()
        db.create_all()

        self.client = self.app.test_client()

        # Seed password hash for standard tests
        self.plain_password = "Password123!"
        self.hashed_password = bcrypt.hashpw(self.plain_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create Admin
        self.admin = User(
            full_name="System Admin",
            email="admin@cipherguard.test",
            password_hash=self.hashed_password,
            role="admin",
            status="active"
        )
        db.session.add(self.admin)

        # Create User A
        self.user_a = User(
            full_name="User A",
            email="usera@cipherguard.test",
            password_hash=self.hashed_password,
            role="user",
            status="active"
        )
        db.session.add(self.user_a)
        db.session.commit()

        # Tokens
        self.admin_token = encode_auth_token(self.admin.id)
        self.usera_token = encode_auth_token(self.user_a.id)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    # ==========================================
    # AUTHENTICATION TESTS
    # ==========================================

    def test_admin_registration_not_possible(self):
        # 1. Admin registration is NOT possible through normal registration
        res = self.client.post("/api/register", json={
            "full_name": "Attacker Admin",
            "email": "attacker@cipherguard.test",
            "password": "AttackerPassword123!",
            "role": "admin"
        })
        self.assertEqual(res.status_code, 201)
        data = json.loads(res.data)
        # Role must be 'user' regardless of request payload
        self.assertEqual(data["user"]["role"], "user")
        user = User.query.filter_by(email="attacker@cipherguard.test").first()
        self.assertEqual(user.role, "user")

    def test_admin_login_success(self):
        # 2. Admin can log in using valid credentials
        res = self.client.post("/api/admin/login", json={
            "email": "admin@cipherguard.test",
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("token", data)
        self.assertEqual(data["user"]["role"], "admin")

    def test_admin_incorrect_password_rejected(self):
        # 3. Incorrect admin password is rejected
        res = self.client.post("/api/admin/login", json={
            "email": "admin@cipherguard.test",
            "password": "WrongPassword!"
        })
        self.assertEqual(res.status_code, 401)

    def test_normal_user_cannot_login_as_admin(self):
        # 4. Normal user cannot log in through admin login
        res = self.client.post("/api/admin/login", json={
            "email": "usera@cipherguard.test",
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 403)
        self.assertEqual(json.loads(res.data)["error"], "Access denied. Admin privileges required.")

    def test_missing_token_rejected(self):
        # 5. Missing token is rejected
        res = self.client.get("/api/admin/dashboard")
        self.assertEqual(res.status_code, 401)

    def test_invalid_token_rejected(self):
        # 6. Invalid token is rejected
        res = self.client.get("/api/admin/dashboard", headers={"Authorization": "Bearer invalidtoken"})
        self.assertEqual(res.status_code, 401)

    def test_expired_token_rejected(self):
        # 7. Expired token is rejected
        expired_payload = {
            'exp': datetime.now(timezone.utc) - timedelta(days=1),
            'iat': datetime.now(timezone.utc) - timedelta(days=2),
            'sub': str(self.admin.id)
        }
        expired_token = jwt.encode(expired_payload, self.app.config['JWT_SECRET'], algorithm='HS256')
        res = self.client.get("/api/admin/dashboard", headers={"Authorization": f"Bearer {expired_token}"})
        self.assertEqual(res.status_code, 401)

    # ==========================================
    # AUTHORIZATION TESTS
    # ==========================================

    def test_admin_access_dashboard_api(self):
        # 8. Admin can access admin dashboard API
        res = self.client.get("/api/admin/dashboard", headers={"Authorization": f"Bearer {self.admin_token}"})
        self.assertEqual(res.status_code, 200)

    def test_normal_user_receives_403_from_admin_api(self):
        # 9. Normal user receives 403 from admin API
        res = self.client.get("/api/admin/dashboard", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 403)

    def test_unauthenticated_receives_401(self):
        # 10. Unauthenticated request receives 401
        res = self.client.get("/api/admin/dashboard")
        self.assertEqual(res.status_code, 401)

    def test_normal_user_cannot_resolve_security_alerts(self):
        # 14. Normal user cannot resolve security alerts
        alert = SecurityAlert(user_id=self.user_a.id, alert_type="Intrusion", severity="HIGH", message="Intrusion message")
        db.session.add(alert)
        db.session.commit()
        res = self.client.post(f"/api/admin/alerts/{alert.id}/resolve", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 403)

    # ==========================================
    # PRIVILEGE ESCALATION TESTS
    # ==========================================

    def test_jwt_role_manipulation_has_no_effect(self):
        # 19. User cannot become admin by modifying JWT claims
        forged_payload = {
            'exp': datetime.now(timezone.utc) + timedelta(days=1),
            'iat': datetime.now(timezone.utc),
            'sub': str(self.user_a.id),
            'role': 'admin'
        }
        forged_token = jwt.encode(forged_payload, "wrong_secret", algorithm='HS256')
        res = self.client.get("/api/admin/dashboard", headers={"Authorization": f"Bearer {forged_token}"})
        self.assertEqual(res.status_code, 401)

    def test_admin_bootstrap_idempotency(self):
        # 20. Admin bootstrap does not overwrite an existing admin
        bootstrap_admin(self.app)
        seeded_admin = User.query.filter_by(role='admin').first()
        self.assertIsNotNone(seeded_admin)

        seeded_admin.password_hash = "custom-hash"
        db.session.commit()

        bootstrap_admin(self.app)
        updated_admin = User.query.filter_by(role='admin').first()
        self.assertEqual(updated_admin.password_hash, "custom-hash")

    # ==========================================
    # REGRESSION TESTS
    # ==========================================

    def test_regression_user_login(self):
        # 21. Existing user login still works
        res = self.client.post("/api/login", json={
            "email": "usera@cipherguard.test",
            "password": "Password123!"
        })
        self.assertEqual(res.status_code, 200)

    def test_regression_user_registration(self):
        # 22. Existing user registration still works
        res = self.client.post("/api/register", json={
            "full_name": "New User",
            "email": "newuser@cipherguard.test",
            "password": "NewPassword123!"
        })
        self.assertEqual(res.status_code, 201)

    def test_regression_user_protected_routes(self):
        # 23. Existing protected user routes still work
        res = self.client.get("/api/profile", headers={"Authorization": f"Bearer {self.usera_token}"})
        self.assertEqual(res.status_code, 200)
