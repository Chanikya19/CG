import unittest
import os
import sys
import tempfile
import shutil
import json
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, FileSharing, FileClassification, FileIntegrity, ActivityLog, SecurityAlert, EncryptionKey, IntegrityHistory
from app.utils.auth_middleware import encode_auth_token

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-321'
    JWT_SECRET = 'test-jwt-secret-321'

class TestCipherGuardDashboard(unittest.TestCase):
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

        # Create Admin
        self.admin = User(
            full_name="System Admin",
            email="admin@cipherguard.test",
            password_hash="fake-hash",
            role="admin",
            status="active"
        )
        db.session.add(self.admin)

        # Create User A
        self.user_a = User(
            full_name="User A",
            email="usera@cipherguard.test",
            password_hash="fake-hash",
            role="user",
            status="active"
        )
        db.session.add(self.user_a)
        db.session.commit()

        # Token
        self.usera_token = encode_auth_token(self.user_a.id)

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_dashboard_endpoint_statistics_and_score(self):
        # 1. Seed some files
        file1 = File(
            filename="doc1.txt",
            file_path="vault/checksum_1.enc",
            mime_type="text/plain",
            file_size=512,
            checksum="checksum_1",
            owner_id=self.user_a.id,
            is_encrypted=True
        )
        file2 = File(
            filename="doc2.txt",
            file_path="vault/checksum_2.enc",
            mime_type="text/plain",
            file_size=1024,
            checksum="checksum_2",
            owner_id=self.user_a.id,
            is_encrypted=True
        )
        db.session.add_all([file1, file2])
        db.session.commit()

        # Seed classifications
        fc1 = FileClassification(file_id=file1.id, classification_label="Public", dlp_risk_score=0.1)
        fc2 = FileClassification(file_id=file2.id, classification_label="Secret", dlp_risk_score=0.9)
        db.session.add_all([fc1, fc2])

        # Seed encryption keys
        ek1 = EncryptionKey(file_id=file1.id, user_id=self.user_a.id, encrypted_file_key="key1", iv_or_nonce="iv1", tag="tag1", key_type="AES-128-GCM")
        ek2 = EncryptionKey(file_id=file2.id, user_id=self.user_a.id, encrypted_file_key="key2", iv_or_nonce="iv2", tag="tag2", key_type="AES-256-GCM")
        db.session.add_all([ek1, ek2])

        # Seed share link
        share = FileSharing(file_id=file1.id, owner_id=self.user_a.id, share_token="sharetoken123", status="active", expiry_time=datetime.utcnow() + timedelta(days=1))
        db.session.add(share)

        # Seed file integrity
        fi1 = FileIntegrity(file_id=file1.id, sha256_hash="hash1")
        fi2 = FileIntegrity(file_id=file2.id, sha256_hash="hash2")
        db.session.add_all([fi1, fi2])
        db.session.commit()

        # Seed integrity history
        ih1 = IntegrityHistory(file_id=file1.id, user_id=self.user_a.id, result="VERIFIED", timestamp=datetime.utcnow() - timedelta(hours=1))
        ih2 = IntegrityHistory(file_id=file2.id, user_id=self.user_a.id, result="TAMPERED", timestamp=datetime.utcnow())
        db.session.add_all([ih1, ih2])

        # Seed unresolved security alerts
        alert1 = SecurityAlert(user_id=self.user_a.id, alert_type="File tampering detected", severity="CRITICAL", message="Tampered!", status="unresolved")
        db.session.add(alert1)
        db.session.commit()

        # Fetch dashboard summary
        headers = {"Authorization": f"Bearer {self.usera_token}"}
        res = self.client.get("/api/dashboard", headers=headers)
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data)
        stats = data.get("stats")

        # Verify stats cards counts
        self.assertEqual(stats.get("total_users"), 2)
        self.assertEqual(stats.get("secured_files"), 2)
        self.assertEqual(stats.get("encrypted_files"), 2)
        self.assertEqual(stats.get("shared_files"), 1)
        self.assertEqual(stats.get("verified_files"), 1)
        self.assertEqual(stats.get("tampered_files"), 1)
        self.assertEqual(stats.get("security_alerts"), 1)

        # Verify Security Score logic
        # deductions: CRITICAL alert = 20 pts, tampered file = 15 pts.
        # encryption coverage = 2/2 = 100%, deduction = 0.
        # integrity signatures = 2/2 = 100%, deduction = 0.
        # Expected score: 100 - 20 - 15 = 65
        self.assertEqual(stats.get("security_score"), 65)

        # Verify factors structure
        factors = stats.get("security_factors")
        self.assertEqual(len(factors), 4)
        self.assertEqual(factors[0]["name"], "Security Alerts")
        self.assertEqual(factors[0]["deduction"], 20)
        self.assertEqual(factors[1]["name"], "File Tampering")
        self.assertEqual(factors[1]["deduction"], 15)

    def test_statistics_endpoint_charts_telemetry(self):
        # Seed daily activity logs
        log1 = ActivityLog(user_id=self.user_a.id, action="FILE_SHARED", module="Sharing", status="success", ip_address="127.0.0.1", timestamp=datetime.utcnow())
        log2 = ActivityLog(user_id=self.user_a.id, action="LOGIN_FAILED", module="Auth", status="failed", ip_address="127.0.0.1", timestamp=datetime.utcnow())
        db.session.add_all([log1, log2])
        db.session.commit()

        headers = {"Authorization": f"Bearer {self.usera_token}"}
        res = self.client.get("/api/statistics", headers=headers)
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data)

        # Assert all 6 chart arrays exist
        self.assertIn("classification_pie", data)
        self.assertIn("algorithms_bar", data)
        self.assertIn("uploads_line", data)
        self.assertIn("integrity_doughnut", data)
        self.assertIn("sharing_line", data)
        self.assertIn("failed_logins_line", data)

        # Check line activity length (7 days)
        self.assertEqual(len(data["sharing_line"]["labels"]), 7)
        self.assertEqual(len(data["failed_logins_line"]["labels"]), 7)

        # Check seeded values in the telemetry
        self.assertEqual(sum(data["sharing_line"]["data"]), 1)
        self.assertEqual(sum(data["failed_logins_line"]["data"]), 1)

if __name__ == '__main__':
    unittest.main()
