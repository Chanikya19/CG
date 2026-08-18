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
from app.models.models import User, File, FileSharing, FileClassification, FileIntegrity, ActivityLog, SecurityAlert, EncryptionKey
from app.utils.auth_middleware import encode_auth_token

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-321'
    JWT_SECRET = 'test-jwt-secret-321'

class TestCipherGuardAlerts(unittest.TestCase):

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
        db.session.remove()
        db.drop_all()
        db.create_all()

        self.client = self.app.test_client()

        import bcrypt
        hashed_pw = bcrypt.hashpw(b"password", bcrypt.gensalt()).decode('utf-8')

        # Create Admin
        self.admin = User(
            full_name="System Admin",
            email="admin@cipherguard.test",
            password_hash=hashed_pw,
            role="admin",
            status="active"
        )
        db.session.add(self.admin)

        # Create User A
        self.user_a = User(
            full_name="User A",
            email="usera@cipherguard.test",
            password_hash=hashed_pw,
            role="user",
            status="active"
        )
        db.session.add(self.user_a)

        # Create User B (attacker / unauthorized operator)
        self.user_b = User(
            full_name="User B",
            email="userb@cipherguard.test",
            password_hash=hashed_pw,
            role="user",
            status="active"
        )
        db.session.add(self.user_b)
        db.session.commit()

        # Generate RSA keypair for User A
        from app.encryption.rsa_engine import generate_rsa_keypair
        priv, pub = generate_rsa_keypair(2048)
        self.user_a.rsa_public_key = pub.decode('utf-8')
        self.user_a.rsa_private_key = priv.decode('utf-8')
        db.session.commit()

        # Tokens
        self.admin_token = encode_auth_token(self.admin.id)
        self.usera_token = encode_auth_token(self.user_a.id)
        self.userb_token = encode_auth_token(self.user_b.id)

        # Create a File owned by User A
        self.file_a = File(
            filename="confidential.txt",
            file_path="vault/checksum_123.enc",
            mime_type="text/plain",
            file_size=1024,
            checksum="checksum_123",
            owner_id=self.user_a.id,
            is_encrypted=True
        )
        db.session.add(self.file_a)
        db.session.commit()

        # Add Classification
        self.class_a = FileClassification(
            file_id=self.file_a.id,
            classification_label="Confidential",
            dlp_risk_score=0.95
        )
        db.session.add(self.class_a)

        # Add Integrity
        self.integ_a = FileIntegrity(
            file_id=self.file_a.id,
            sha256_hash="stored_hash_sha256_xyz"
        )
        db.session.add(self.integ_a)

        # Add EncryptionKey metadata
        self.enc_key_a = EncryptionKey(
            file_id=self.file_a.id,
            user_id=self.user_a.id,
            encrypted_file_key="dummy_aes_key",
            iv_or_nonce="dummy_iv",
            tag="dummy_tag",
            version=1
        )
        db.session.add(self.enc_key_a)
        db.session.commit()

        # Create dummy encrypted file payload
        vault_dir = os.path.join(self.app.instance_path, 'vault')
        os.makedirs(vault_dir, exist_ok=True)
        self.vault_file_path = os.path.join(vault_dir, "checksum_123.enc")
        with open(self.vault_file_path, "wb") as f:
            f.write(b"fake encrypted payload bytes")

    def test_alert_condition_multiple_failed_logins(self):
        """1. Tests that 3 failed login attempts locks account and triggers alert."""
        email = self.user_a.email
        # Trigger 3 failed login attempts
        for _ in range(3):
            res = self.client.post("/api/login", json={
                "email": email,
                "password": "wrong-password"
            })
            self.assertEqual(res.status_code, 401)

        # Check account lockout
        res_lock = self.client.post("/api/login", json={
            "email": email,
            "password": "wrong-password"
        })
        self.assertEqual(res_lock.status_code, 403)
        self.assertIn("locked", json.loads(res_lock.data)["error"].lower())

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="Multiple failed login attempts").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_a.id)
        self.assertEqual(alert.severity, "HIGH")
        self.assertIn("locked", alert.message)

    def test_alert_condition_unauthorized_api_access(self):
        """2. Tests that unauthorized resource requests (owner mismatch) trigger alert."""
        # User B attempts to verify User A's file
        headers = {"Authorization": f"Bearer {self.userb_token}"}
        res = self.client.post("/api/verify-file", json={"file_id": self.file_a.id}, headers=headers)
        self.assertEqual(res.status_code, 403)

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="Unauthorized API access").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_b.id)
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertIn("unauthorized", alert.message.lower())

    def test_alert_condition_expired_share_link_access(self):
        """3. Tests expired share link access attempts trigger alert."""
        # Create an expired share
        expired_share = FileSharing(
            file_id=self.file_a.id,
            owner_id=self.user_a.id,
            share_token="expired_token",
            expiry_time=datetime.utcnow() - timedelta(hours=1),
            status="active"
        )
        db.session.add(expired_share)
        db.session.commit()

        # Access expired link
        res = self.client.get("/api/shared/expired_token")
        self.assertEqual(res.status_code, 403)

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="Expired share link access").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_a.id)
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertIn("expired", alert.message.lower())

    def test_alert_condition_revoked_share_link_access(self):
        """4. Tests revoked share link access attempts trigger alert."""
        # Create a revoked share
        revoked_share = FileSharing(
            file_id=self.file_a.id,
            owner_id=self.user_a.id,
            share_token="revoked_token",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status="revoked"
        )
        db.session.add(revoked_share)
        db.session.commit()

        # Access revoked link
        res = self.client.get("/api/shared/revoked_token")
        self.assertEqual(res.status_code, 403)

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="Revoked share link access").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_a.id)
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertIn("revoked", alert.message.lower())

    def test_alert_condition_file_tampering_detected(self):
        """5. Tests missing payload or signature verification mismatch triggers tamper alert."""
        # 1. Missing payload check
        # Delete dummy file payload
        if os.path.exists(self.vault_file_path):
            os.remove(self.vault_file_path)

        headers = {"Authorization": f"Bearer {self.usera_token}"}
        res = self.client.post("/api/verify-file", json={"file_id": self.file_a.id}, headers=headers)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(json.loads(res.data)["status"], "TAMPERED")

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="File tampering detected").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_a.id)
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertIn("missing", alert.message.lower())

    def test_alert_condition_repeated_decryption_failures(self):
        """6. Tests that 3 consecutive decryption failures triggers alert."""
        # Seed 3 failed decrypt operations to ActivityLogs
        for _ in range(3):
            log = ActivityLog(
                user_id=self.user_a.id,
                action="FILE_DECRYPTED",
                module="Cryptographic Vault",
                status="failed",
                ip_address="127.0.0.1",
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
        db.session.commit()

        # Trigger one decryption attempt (which fails on the controller due to dummy payload missing or error)
        headers = {"Authorization": f"Bearer {self.usera_token}"}
        res = self.client.post(f"/api/files/{self.file_a.id}/download/decrypted", headers=headers)
        self.assertEqual(res.status_code, 400) # Decryption failed

        # Assert SecurityAlert created
        alert = SecurityAlert.query.filter_by(alert_type="Repeated decryption failures").first()
        self.assertIsNotNone(alert)
        self.assertEqual(alert.user_id, self.user_a.id)
        self.assertEqual(alert.severity, "HIGH")

    def test_alert_condition_suspicious_download_activity(self):
        """7. Tests that 5 downloads within a 5-minute window triggers alert."""
        # Seed 4 successful download events
        for _ in range(4):
            log = ActivityLog(
                user_id=self.user_a.id,
                action="FILE_DECRYPTED",
                module="Cryptographic Vault",
                status="success",
                ip_address="127.0.0.1",
                timestamp=datetime.utcnow()
            )
            db.session.add(log)
        db.session.commit()

        # Setup dummy file for decryption
        with open(self.vault_file_path, "wb") as f:
            f.write(b"fake payload")

        # Mock the decrypt_file_hybrid to return fake bytes
        import unittest.mock as mock
        with mock.patch('app.controllers.api_controller.decrypt_by_sensitivity', return_value=b"decrypted text"):
            headers = {"Authorization": f"Bearer {self.usera_token}"}
            # Trigger the 5th successful decryption download
            res = self.client.post(f"/api/files/{self.file_a.id}/download/decrypted", headers=headers)
            
            # Check alert
            alert = SecurityAlert.query.filter_by(alert_type="Suspicious download activity").first()
            self.assertIsNotNone(alert)
            self.assertEqual(alert.user_id, self.user_a.id)
            self.assertEqual(alert.severity, "HIGH")

    def test_admin_alerts_filtering_and_resolution(self):
        """Tests that admin can view, filter, and resolve security alerts."""
        # Create some alerts
        alert1 = SecurityAlert(user_id=self.user_a.id, alert_type="File tampering detected", severity="CRITICAL", message="tamper message", status="unresolved")
        alert2 = SecurityAlert(user_id=self.user_b.id, alert_type="Unauthorized API access", severity="HIGH", message="unauthorized message", status="unresolved")
        db.session.add_all([alert1, alert2])
        db.session.commit()

        # 1. Admin views all alerts
        headers_admin = {"Authorization": f"Bearer {self.admin_token}"}
        res_all = self.client.get("/api/security-alerts", headers=headers_admin)
        self.assertEqual(res_all.status_code, 200)
        data_all = json.loads(res_all.data)
        self.assertEqual(len(data_all), 2)

        # 2. Admin filters by severity=CRITICAL
        res_filt = self.client.get("/api/security-alerts?severity=CRITICAL", headers=headers_admin)
        self.assertEqual(res_filt.status_code, 200)
        data_filt = json.loads(res_filt.data)
        self.assertEqual(len(data_filt), 1)
        self.assertEqual(data_filt[0]["type"], "File tampering detected")

        # 3. Normal user gets alerts -> gets empty list (since no alerts were triggered by token invalidity or associated with User B's profile yet, or returns only User B's alert)
        headers_user = {"Authorization": f"Bearer {self.userb_token}"}
        res_user = self.client.get("/api/security-alerts", headers=headers_user)
        self.assertEqual(res_user.status_code, 200)
        data_user = json.loads(res_user.data)
        # Should only get alert2 (associated with User B's id)
        self.assertEqual(len(data_user), 1)
        self.assertEqual(data_user[0]["user_id"], self.user_b.id)

        # 4. Admin marks alert1 as resolved
        res_resolve = self.client.post(f"/api/admin/alerts/{alert1.id}/resolve", headers=headers_admin)
        self.assertEqual(res_resolve.status_code, 200)
        
        # Verify status is resolved in database
        updated_alert = SecurityAlert.query.get(alert1.id)
        self.assertEqual(updated_alert.status, "resolved")

        # 5. Non-admin attempts to resolve alert2 -> 403 Forbidden
        res_resolve_fail = self.client.post(f"/api/admin/alerts/{alert2.id}/resolve", headers=headers_user)
        self.assertEqual(res_resolve_fail.status_code, 403)

if __name__ == '__main__':
    unittest.main()
