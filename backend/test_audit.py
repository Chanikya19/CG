import unittest
import os
import sys
import tempfile
import shutil
import json
from datetime import datetime, timedelta

# Add app path to sys.path to resolve imports when running standalone
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, ActivityLog
from app.controllers.api_controller import log_event
from app.utils.auth_middleware import encode_auth_token

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-789'
    JWT_SECRET = 'test-jwt-secret-789'

class TestCipherGuardAudit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.app = create_app(TestConfig)
        cls.app.instance_path = cls.temp_dir
        
        cls.app_context = cls.app.app_context()
        cls.app_context.push()
        
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        # Drop and recreate tables to isolate each test run
        db.session.remove()
        db.drop_all()
        db.create_all()

        self.client = self.app.test_client()

        # Create Admin Operator
        self.admin_user = User(
            full_name="Admin Operator",
            email="admin@cipherguard.test",
            password_hash="fake-hash",
            role="admin",
            status="active"
        )
        db.session.add(self.admin_user)

        # Create Normal User
        self.normal_user = User(
            full_name="Normal Operator",
            email="user@cipherguard.test",
            password_hash="fake-hash",
            role="user",
            status="active"
        )
        db.session.add(self.normal_user)
        db.session.commit()

        # Sign JWT Tokens
        self.admin_token = encode_auth_token(self.admin_user.id)
        self.user_token = encode_auth_token(self.normal_user.id)

    def test_log_sanitization(self):
        """Verifies log details dictionary redacts sensitive credentials / secrets."""
        details = {
            "username": "admin",
            "password": "SecretPassword123!",
            "aes_key": "4a5f6e...",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
            "token": "bearer.token.string",
            "normal_field": "Non-sensitive details payload"
        }
        
        # Call log_event inside active application context
        log_event(
            user_id=self.normal_user.id,
            action="TEST_LOG",
            module="General",
            details=details
        )
        
        # Verify from database
        log_record = ActivityLog.query.order_by(ActivityLog.id.desc()).first()
        self.assertIsNotNone(log_record)
        self.assertEqual(log_record.action, "TEST_LOG")
        
        logged_details = log_record.details
        self.assertEqual(logged_details["username"], "admin")
        self.assertEqual(logged_details["normal_field"], "Non-sensitive details payload")
        self.assertEqual(logged_details["password"], "[REDACTED_FOR_SECURITY]")
        self.assertEqual(logged_details["aes_key"], "[REDACTED_FOR_SECURITY]")
        self.assertEqual(logged_details["private_key"], "[REDACTED_FOR_SECURITY]")
        self.assertEqual(logged_details["token"], "[REDACTED_FOR_SECURITY]")

    def test_logout_audit(self):
        """Checks that hitting the logout route records a LOGOUT event."""
        headers = {"Authorization": f"Bearer {self.user_token}"}
        res = self.client.post("/api/logout", headers=headers)
        self.assertEqual(res.status_code, 200)

        # Asserts logout audit log exists
        log = ActivityLog.query.filter_by(action="LOGOUT").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user_id, self.normal_user.id)
        self.assertEqual(log.module, "Authentication")
        self.assertEqual(log.status, "success")

    def test_admin_user_list_access(self):
        """Validates that only admin role can query user records."""
        # 1. Admin requests list -> 200 OK
        headers_admin = {"Authorization": f"Bearer {self.admin_token}"}
        res_admin = self.client.get("/api/admin/users", headers=headers_admin)
        self.assertEqual(res_admin.status_code, 200)
        data_admin = json.loads(res_admin.data)
        self.assertEqual(len(data_admin), 2)
        
        # 2. Normal user requests list -> 403 Forbidden + UNAUTHORIZED_ACCESS log
        headers_user = {"Authorization": f"Bearer {self.user_token}"}
        res_user = self.client.get("/api/admin/users", headers=headers_user)
        self.assertEqual(res_user.status_code, 403)
        
        # Verify unauthorized attempt logged
        log = ActivityLog.query.filter_by(action="UNAUTHORIZED_ACCESS").first()
        self.assertIsNotNone(log)
        self.assertEqual(log.user_id, self.normal_user.id)
        self.assertEqual(log.status, "blocked")

    def test_get_activity_logs_pagination_and_role_access(self):
        """Verifies role-based visibility, query filtering, and page size parameters."""
        # Populate dummy logs
        # Admin action
        log_event(self.admin_user.id, "FILE_UPLOAD", "Cryptographic Vault")
        # Normal user actions
        log_event(self.normal_user.id, "FILE_CLASSIFIED", "DLP Classifier")
        log_event(self.normal_user.id, "FILE_DECRYPTED", "Cryptographic Vault")
        log_event(self.normal_user.id, "LOGIN_FAILED", "Authentication", status="failed")

        # 1. User queries logs -> receives only their 3 logs
        headers_user = {"Authorization": f"Bearer {self.user_token}"}
        res_user = self.client.get("/api/logs", headers=headers_user)
        self.assertEqual(res_user.status_code, 200)
        data_user = json.loads(res_user.data)
        
        self.assertIn("logs", data_user)
        self.assertEqual(len(data_user["logs"]), 3)
        self.assertEqual(data_user["total"], 3)
        for l in data_user["logs"]:
            self.assertEqual(l["user_id"], self.normal_user.id)

        # 2. Admin queries logs -> receives all 4 logs (system-wide)
        headers_admin = {"Authorization": f"Bearer {self.admin_token}"}
        res_admin = self.client.get("/api/logs", headers=headers_admin)
        self.assertEqual(res_admin.status_code, 200)
        data_admin = json.loads(res_admin.data)
        self.assertEqual(data_admin["total"], 4)
        self.assertEqual(len(data_admin["logs"]), 4)

        # 3. Admin filters by module=DLP Classifier
        res_filtered = self.client.get("/api/logs?module=DLP%20Classifier", headers=headers_admin)
        self.assertEqual(res_filtered.status_code, 200)
        data_filtered = json.loads(res_filtered.data)
        self.assertEqual(data_filtered["total"], 1)
        self.assertEqual(data_filtered["logs"][0]["action"], "FILE_CLASSIFIED")

        # 4. Admin filters by user_id
        res_user_filt = self.client.get(f"/api/logs?user_id={self.normal_user.id}", headers=headers_admin)
        self.assertEqual(res_user_filt.status_code, 200)
        data_user_filt = json.loads(res_user_filt.data)
        self.assertEqual(data_user_filt["total"], 3)

        # 5. Pagination page limits
        res_paginated = self.client.get("/api/logs?per_page=2", headers=headers_admin)
        self.assertEqual(res_paginated.status_code, 200)
        data_paginated = json.loads(res_paginated.data)
        self.assertEqual(data_paginated["per_page"], 2)
        self.assertEqual(data_paginated["pages"], 2)
        self.assertEqual(len(data_paginated["logs"]), 2)

    def test_get_activity_logs_date_filters(self):
        """Verifies start_date and end_date filtering constraint parameters."""
        # Insert log events with simulated timestamps
        log1 = ActivityLog(user_id=self.normal_user.id, action="LOGIN_SUCCESS", module="Authentication", ip_address="127.0.0.1", timestamp=datetime.utcnow() - timedelta(days=5))
        log2 = ActivityLog(user_id=self.normal_user.id, action="FILE_DECRYPTED", module="Cryptographic Vault", ip_address="127.0.0.1", timestamp=datetime.utcnow() - timedelta(days=2))
        log3 = ActivityLog(user_id=self.normal_user.id, action="FILE_UPLOAD", module="Cryptographic Vault", ip_address="127.0.0.1", timestamp=datetime.utcnow())
        
        db.session.add_all([log1, log2, log3])
        db.session.commit()

        # Query range from 3 days ago to today
        start = (datetime.utcnow() - timedelta(days=3)).strftime('%Y-%m-%d')
        end = datetime.utcnow().strftime('%Y-%m-%d')
        
        headers = {"Authorization": f"Bearer {self.user_token}"}
        res = self.client.get(f"/api/logs?start_date={start}&end_date={end}", headers=headers)
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        # Should include log2 and log3, but exclude log1 (5 days ago)
        self.assertEqual(data["total"], 2)
        actions = [l["action"] for l in data["logs"]]
        self.assertIn("FILE_DECRYPTED", actions)
        self.assertIn("FILE_UPLOAD", actions)
        self.assertNotIn("LOGIN_SUCCESS", actions)

if __name__ == '__main__':
    unittest.main()
