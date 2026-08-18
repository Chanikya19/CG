import unittest
import os
import sys
import tempfile
import shutil
from datetime import datetime

# Add app path to sys.path to resolve imports when running standalone
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from app.database.connection import db
from app.models.models import User, File, FileIntegrity, IntegrityHistory, FileClassification, EncryptionKey
from app.controllers.api_controller import verify_file_endpoint
from app.utils.integrity import generate_sha256
from app.encryption.hybrid_engine import encrypt_by_sensitivity, decrypt_by_sensitivity
from app.encryption.rsa_engine import generate_rsa_keypair

class TestConfig:
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'test-key-123'
    JWT_SECRET = 'test-jwt-secret-123'

class TestCipherGuardIntegrity(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.app = create_app(TestConfig)
        cls.app.instance_path = cls.temp_dir
        
        cls.app_context = cls.app.app_context()
        cls.app_context.push()
        
        # Create tables
        db.create_all()

    @classmethod
    def tearDownClass(cls):
        db.session.remove()
        db.drop_all()
        cls.app_context.pop()
        shutil.rmtree(cls.temp_dir)

    def setUp(self):
        # Create a test user
        self.test_user = User(
            full_name="Audit Auditor",
            email="auditor@cipherguard.test",
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
            filename="financials.pdf",
            file_path="vault/dummy_checksum.enc",
            file_size=100,
            mime_type="application/pdf",
            checksum="dummy_checksum",
            is_encrypted=True
        )
        db.session.add(self.test_file)
        db.session.commit()

        # Write dummy ciphertext to disk
        self.vault_path = os.path.join(self.temp_dir, "vault")
        os.makedirs(self.vault_path, exist_ok=True)
        self.file_disk_path = os.path.join(self.vault_path, "dummy_checksum.enc")
        self.original_content = b"Encrypted financial report data"
        with open(self.file_disk_path, 'wb') as f:
            f.write(self.original_content)

        # Store initial integrity hash
        self.original_hash = generate_sha256(self.original_content)
        self.integrity = FileIntegrity(
            file_id=self.test_file.id,
            sha256_hash=self.original_hash
        )
        db.session.add(self.integrity)

        self.classification = FileClassification(
            file_id=self.test_file.id,
            classification_label="Confidential",
            dlp_risk_score=5.0
        )
        db.session.add(self.classification)
        db.session.commit()

    def tearDown(self):
        db.session.query(IntegrityHistory).delete()
        db.session.query(FileClassification).delete()
        db.session.query(FileIntegrity).delete()
        db.session.query(EncryptionKey).delete()
        db.session.query(File).delete()
        db.session.query(User).delete()
        db.session.commit()

        if os.path.exists(self.file_disk_path):
            os.remove(self.file_disk_path)

    def test_integrity_original_verified(self):
        # Run verification on unchanged file
        with self.app.test_request_context(
            json={"file_id": self.test_file.id},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = verify_file_endpoint(self.test_user)
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["status"], "VERIFIED")
            self.assertEqual(data["computed_hash"], self.original_hash)
            self.assertEqual(data["stored_hash"], self.original_hash)

        # Assert history attempt was logged
        history = IntegrityHistory.query.filter_by(file_id=self.test_file.id).all()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].result, 'VERIFIED')
        self.assertEqual(history[0].user_id, self.test_user.id)

    def test_integrity_modified_tampered(self):
        # Modify one byte of the file on disk
        with open(self.file_disk_path, 'wb') as f:
            f.write(b"Tampered financial report data")

        # Run verification
        with self.app.test_request_context(
            json={"file_id": self.test_file.id},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = verify_file_endpoint(self.test_user)
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["status"], "TAMPERED")
            self.assertNotEqual(data["computed_hash"], self.original_hash)

        # Assert history was logged as TAMPERED
        history = IntegrityHistory.query.filter_by(file_id=self.test_file.id).all()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].result, 'TAMPERED')

    def test_integrity_corrupted_tampered(self):
        # Truncate or corrupt file to 0 bytes
        with open(self.file_disk_path, 'wb') as f:
            f.write(b"")

        # Run verification
        with self.app.test_request_context(
            json={"file_id": self.test_file.id},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = verify_file_endpoint(self.test_user)
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["status"], "TAMPERED")

        # Assert history log
        history = IntegrityHistory.query.filter_by(file_id=self.test_file.id).all()
        self.assertEqual(history[0].result, 'TAMPERED')

    def test_integrity_missing_file_tampered(self):
        # Delete file entirely
        if os.path.exists(self.file_disk_path):
            os.remove(self.file_disk_path)

        # Run verification
        with self.app.test_request_context(
            json={"file_id": self.test_file.id},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = verify_file_endpoint(self.test_user)
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["status"], "TAMPERED")

        # Assert history log
        history = IntegrityHistory.query.filter_by(file_id=self.test_file.id).all()
        self.assertEqual(history[0].result, 'TAMPERED')

    def test_integrity_wrong_file_tampered(self):
        # Wrong stored hash
        self.integrity.sha256_hash = "wrong_hash_signature_value_12345678"
        db.session.commit()

        # Run verification
        with self.app.test_request_context(
            json={"file_id": self.test_file.id},
            environ_base={"REMOTE_ADDR": "127.0.0.1", "HTTP_USER_AGENT": "TestAgent"}
        ):
            response = verify_file_endpoint(self.test_user)
            self.assertEqual(response[1], 200)
            data = response[0].get_json()
            self.assertEqual(data["status"], "TAMPERED")

    def test_encryption_decryption_not_broken(self):
        # Verify encryption and decryption operations still work perfectly
        plaintext = b"Highly confidential business operations blueprint"
        
        # Encrypt
        enc_pack = encrypt_by_sensitivity(
            file_bytes=plaintext,
            sensitivity="Confidential",
            user_public_key_pem=self.test_user.rsa_public_key
        )
        self.assertIsNotNone(enc_pack["ciphertext"])

        # Decrypt
        decrypted = decrypt_by_sensitivity(
            ciphertext_bytes=enc_pack["ciphertext"],
            sensitivity="Confidential",
            encrypted_file_key_b64=enc_pack["encrypted_file_key"],
            iv_b64=enc_pack["iv_or_nonce"],
            tag_b64=enc_pack["tag"],
            user_private_key_pem=self.test_user.rsa_private_key,
            version=2
        )
        self.assertEqual(decrypted, plaintext)

if __name__ == '__main__':
    unittest.main()
