import unittest
import os
import sys
import tempfile
import shutil
from datetime import datetime, timedelta

# Add app path to sys.path to resolve imports when running standalone
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, FileSharing, FileClassification, EncryptionKey, ActivityLog
from app.controllers.api_controller import share_file_endpoint, resolve_shared_link, download_shared_file, revoke_shared_link
from app.utils.integrity import generate_sha256
from app.encryption.hybrid_engine import encrypt_by_sensitivity
from app.encryption.rsa_engine import generate_rsa_keypair

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-456'
    JWT_SECRET = 'test-jwt-secret-456'
    SHARE_BASE_URL = 'https://share.cipherguard.test'

class TestCipherGuardSharing(unittest.TestCase):

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

        # Create a test user
        self.test_user = User(
            full_name="Alice Sharer",
            email="alice@cipherguard.test",
            password_hash="dummy"
        )
        db.session.add(self.test_user)
        db.session.commit()

        # Generate RSA keypair for hybrid encryption
        priv, pub = generate_rsa_keypair(2048)
        self.test_user.rsa_public_key = pub.decode('utf-8')
        self.test_user.rsa_private_key = priv.decode('utf-8')
        db.session.commit()

        # Create dummy file record
        self.test_file = File(
            owner_id=self.test_user.id,
            filename="confidential_sales.docx",
            file_path="vault/sales_checksum.enc",
            file_size=120,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            checksum="sales_checksum",
            is_encrypted=True
        )
        db.session.add(self.test_file)
        db.session.commit()

        # Write dummy ciphertext to disk
        self.vault_path = os.path.join(self.temp_dir, "vault")
        os.makedirs(self.vault_path, exist_ok=True)
        self.file_disk_path = os.path.join(self.vault_path, "sales_checksum.enc")
        
        # Setup classifications
        self.classification = FileClassification(
            file_id=self.test_file.id,
            classification_label="Confidential",
            dlp_risk_score=3.5
        )
        db.session.add(self.classification)

        self.enc_key = EncryptionKey(
            file_id=self.test_file.id,
            user_id=self.test_user.id,
            encrypted_file_key="dummy_aes_key",
            iv_or_nonce="dummy_iv",
            tag="dummy_tag",
            version=1
        )
        db.session.add(self.enc_key)
        db.session.commit()

        # Mock encrypt bytes on disk
        plaintext = b"Sales Q3 targets and achievements blueprint"
        enc_pack = encrypt_by_sensitivity(
            file_bytes=plaintext,
            sensitivity="Confidential",
            user_public_key_pem=self.test_user.rsa_public_key
        )
        with open(self.file_disk_path, 'wb') as f:
            f.write(enc_pack["ciphertext"])

        # Also store the key data in enc_key
        self.enc_key.encrypted_file_key = enc_pack["encrypted_file_key"]
        self.enc_key.iv_or_nonce = enc_pack["iv_or_nonce"]
        self.enc_key.tag = enc_pack["tag"]
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        if os.path.exists(self.file_disk_path):
            os.remove(self.file_disk_path)

    def test_share_creation_and_qr_code(self):
        # Create share link with max 5 downloads
        with self.app.test_request_context(
            json={"file_id": self.test_file.id, "expiry_hours": 24, "max_downloads": 5},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = share_file_endpoint(self.test_user)
            self.assertEqual(response[1], 201)
            data = response[0].get_json()
            
            # Assert dynamic SHARE_BASE_URL is used
            self.assertTrue(data["share_link"].startswith("https://share.cipherguard.test/shared/"))
            self.assertEqual(data["max_downloads"], 5)
            self.assertEqual(data["downloads_count"], 0)
            
            # Assert QR Code contains base64 image data
            self.assertTrue(data["qr_code"].startswith("data:image/png;base64,"))

        # Assert share creation logged
        log = ActivityLog.query.filter_by(action='FILE_SHARED').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details["max_downloads"], 5)

    def test_resolve_valid_link(self):
        # Manually create sharing link
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="valid_token_xyz",
            expiry_time=datetime.utcnow() + timedelta(hours=24),
            status='active'
        )
        db.session.add(share)
        db.session.commit()

        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = resolve_shared_link("valid_token_xyz")
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["file"]["filename"], "confidential_sales.docx")

        # Assert SHARE_ACCESSED log generated
        log = ActivityLog.query.filter_by(action='SHARE_ACCESSED').first()
        self.assertIsNotNone(log)

    def test_resolve_invalid_link(self):
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = resolve_shared_link("bogus_token")
            self.assertEqual(response[1], 404)

        # Assert SHARE_FAILED_ACCESS log generated
        log = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details["reason"], "Sharing link is invalid or not found")

    def test_resolve_expired_link(self):
        # Create share link expired 2 hours ago
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="expired_token_123",
            expiry_time=datetime.utcnow() - timedelta(hours=2),
            status='active'
        )
        db.session.add(share)
        db.session.commit()

        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = resolve_shared_link("expired_token_123")
            self.assertEqual(response[1], 403)

        # Assert share marked as expired
        self.assertEqual(share.status, 'expired')

        # Assert failed access log generated
        log = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details["reason"], "This sharing link has expired")

    def test_resolve_revoked_link(self):
        # Create share link and revoke it
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="revoked_token_456",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status='active'
        )
        db.session.add(share)
        db.session.commit()

        # Revoke
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = revoke_shared_link(self.test_user, share.id)
            self.assertEqual(response[1], 200)

        # Confirm revoked
        self.assertEqual(share.status, 'revoked')

        # Try to resolve revoked link
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response2 = resolve_shared_link("revoked_token_456")
            self.assertEqual(response2[1], 403)

        # Assert SHARE_REVOKED and failed access logged
        rev_log = ActivityLog.query.filter_by(action='SHARE_REVOKED').first()
        self.assertIsNotNone(rev_log)

    def test_download_limit_enforced(self):
        # Create share link with limit = 2
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="limit_token_789",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status='active',
            max_downloads=2,
            downloads_count=0
        )
        db.session.add(share)
        db.session.commit()

        # Download 1
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res1 = download_shared_file("limit_token_789")
            self.assertEqual(res1.status_code, 200)
            self.assertEqual(share.downloads_count, 1)
            self.assertEqual(share.status, 'active')

        # Download 2
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res2 = download_shared_file("limit_token_789")
            self.assertEqual(res2.status_code, 200)
            self.assertEqual(share.downloads_count, 2)
            self.assertEqual(share.status, 'expired')

        # Download 3 (should fail)
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res3 = download_shared_file("limit_token_789")
            self.assertEqual(res3[1], 403)

        # Assert failed access and expired logging
        fail_log = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS', user_id=share.owner_id).first()
        self.assertIsNotNone(fail_log)
        self.assertEqual(fail_log.details["reason"], "Download limit has been exceeded")

    def test_one_time_link(self):
        # Create one-time share link (max_downloads = 1)
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="onetime_token_abc",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status='active',
            max_downloads=1,
            downloads_count=0
        )
        db.session.add(share)
        db.session.commit()

        # Download 1 (should succeed and expire link)
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res1 = download_shared_file("onetime_token_abc")
            self.assertEqual(res1.status_code, 200)
            self.assertEqual(share.downloads_count, 1)
            self.assertEqual(share.status, 'expired')

        # Download 2 (should fail)
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res2 = download_shared_file("onetime_token_abc")
            self.assertEqual(res2[1], 403)

    def test_unauthorized_access_missing_file(self):
        # Remove file from disk
        if os.path.exists(self.file_disk_path):
            os.remove(self.file_disk_path)

        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="missing_file_token",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status='active'
        )
        db.session.add(share)
        db.session.commit()

        # Try to resolve missing file share link
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = resolve_shared_link("missing_file_token")
            self.assertEqual(response[1], 404)

        # Assert SHARE_FAILED_ACCESS log generated
        log = ActivityLog.query.filter_by(action='SHARE_FAILED_ACCESS').first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details["reason"], "Encrypted file payload missing from vault storage")

    def test_sharing_token_not_logged_raw(self):
        # Create share link
        with self.app.test_request_context(
            json={"file_id": self.test_file.id, "expiry_hours": 24, "max_downloads": 5},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = share_file_endpoint(self.test_user)
            self.assertEqual(response[1], 201)
            data = response[0].get_json()
            token = data["share_token"]
            
        # Verify FILE_SHARED log contains masked token instead of raw token
        log_shared = ActivityLog.query.filter_by(action='FILE_SHARED').first()
        self.assertIsNotNone(log_shared)
        self.assertNotIn("token", log_shared.details)
        self.assertIn("share_prefix", log_shared.details)
        self.assertEqual(log_shared.details["share_prefix"], token[:8] + "...")

        # Access share link
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            resolve_shared_link(token)
            
        # Verify SHARE_ACCESSED log contains masked token instead of raw token
        log_accessed = ActivityLog.query.filter_by(action='SHARE_ACCESSED').first()
        self.assertIsNotNone(log_accessed)
        self.assertNotIn("token", log_accessed.details)
        self.assertIn("share_prefix", log_accessed.details)
        self.assertEqual(log_accessed.details["share_prefix"], token[:8] + "...")

    def test_shared_file_tampering_detection(self):
        # Create FileIntegrity entry for test_file
        from app.models.models import FileIntegrity
        with open(self.file_disk_path, 'rb') as f:
            content_bytes = f.read()
        original_hash = generate_sha256(content_bytes)
        
        integrity = FileIntegrity(file_id=self.test_file.id, sha256_hash=original_hash)
        db.session.add(integrity)
        db.session.commit()

        # Create share link
        share = FileSharing(
            file_id=self.test_file.id,
            owner_id=self.test_user.id,
            share_token="tamper_check_token",
            expiry_time=datetime.utcnow() + timedelta(hours=2),
            status='active'
        )
        db.session.add(share)
        db.session.commit()

        # Resolve sharing link before tampering -> should be VERIFIED
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res1 = resolve_shared_link("tamper_check_token")
            self.assertEqual(res1[1], 200)
            self.assertEqual(res1[0].get_json()["file"]["integrity_status"], "VERIFIED")

        # Now, tamper with the file on disk
        with open(self.file_disk_path, 'wb') as f:
            f.write(b"TAMPERED_CIPHERTEXT_BYTES_HERE")

        # Resolve sharing link after tampering -> status should be TAMPERED
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res2 = resolve_shared_link("tamper_check_token")
            self.assertEqual(res2[1], 200)
            self.assertEqual(res2[0].get_json()["file"]["integrity_status"], "TAMPERED")

        # Attempting to download/decrypt the tampered shared file should block with 400
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res3 = download_shared_file("tamper_check_token")
            self.assertEqual(res3[1], 400)
            self.assertIn("integrity check failed", res3[0].get_json()["error"].lower())

    def test_path_traversal_on_share_link_resolver(self):
        # Passing relative path traversal token should fail cleanly with 404
        with self.app.test_request_context(
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            res = resolve_shared_link("../../../etc/passwd")
            self.assertEqual(res[1], 404)

if __name__ == '__main__':
    unittest.main()
