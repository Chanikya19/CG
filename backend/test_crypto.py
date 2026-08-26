import unittest
import base64
import os
from cryptography.exceptions import InvalidTag

# Add app path to sys.path to resolve imports when running standalone
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.encryption.aes_engine import generate_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from app.encryption.rsa_engine import generate_rsa_keypair, encrypt_key_rsa, decrypt_key_rsa
from app.encryption.hybrid_engine import encrypt_file_hybrid, decrypt_file_hybrid, encrypt_by_sensitivity, decrypt_by_sensitivity

class TestCipherGuardCrypto(unittest.TestCase):

    def setUp(self):
        # Generate dummy keys for testing
        self.private_pem, self.public_pem = generate_rsa_keypair(2048)

    def test_aes_encryption_decryption(self):
        # 1. AES Key Generation
        key = generate_aes_key(256)
        self.assertEqual(len(key), 32)

        # 2. AES Encryption / Decryption
        plaintext = b"Top secret intelligence report payload"
        ciphertext, iv, tag = encrypt_aes_gcm(key, plaintext)
        
        self.assertIsNotNone(ciphertext)
        self.assertEqual(len(iv), 12)
        self.assertEqual(len(tag), 16)

        decrypted = decrypt_aes_gcm(key, ciphertext, iv, tag)
        self.assertEqual(decrypted, plaintext)

    def test_rsa_key_generation_and_padding(self):
        private_pem, public_pem = generate_rsa_keypair(2048)
        self.assertTrue(private_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(public_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_rsa_aes_key_wrapping_unwrapping(self):
        aes_key = generate_aes_key(256)
        
        # Wrap AES key
        wrapped_key = encrypt_key_rsa(self.public_pem, aes_key)
        self.assertIsNotNone(wrapped_key)
        
        # Unwrap AES key
        unwrapped_key = decrypt_key_rsa(self.private_pem, wrapped_key)
        self.assertEqual(unwrapped_key, aes_key)

    def test_hybrid_encryption_decryption(self):
        plaintext = b"Hybrid Cryptosystem Payload"
        
        # Encrypt hybrid
        res = encrypt_file_hybrid(plaintext, self.public_pem)
        self.assertIn("ciphertext", res)
        self.assertIn("encrypted_file_key", res)
        self.assertIn("iv_or_nonce", res)
        self.assertIn("tag", res)

        # Decrypt hybrid
        decrypted = decrypt_file_hybrid(
            res["ciphertext"],
            res["encrypted_file_key"],
            res["iv_or_nonce"],
            res["tag"],
            self.private_pem
        )
        self.assertEqual(decrypted, plaintext)

    def test_wrong_rsa_key_decryption_failure(self):
        plaintext = b"Sensitive User Data"
        res = encrypt_file_hybrid(plaintext, self.public_pem)

        # Generate a different keypair
        wrong_private_pem, _ = generate_rsa_keypair(2048)

        # Attempt decryption and assert exception
        with self.assertRaises((ValueError, Exception)):
            decrypt_file_hybrid(
                res["ciphertext"],
                res["encrypted_file_key"],
                res["iv_or_nonce"],
                res["tag"],
                wrong_private_pem
            )

    def test_modified_ciphertext_authentication_failure(self):
        aes_key = generate_aes_key(256)
        plaintext = b"Important ledger records"
        ciphertext, iv, tag = encrypt_aes_gcm(aes_key, plaintext)

        # Tamper with the ciphertext (flip a bit)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 1
        tampered_ciphertext = bytes(tampered_ciphertext)

        # Attempt decryption and assert tag validation fails
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(aes_key, tampered_ciphertext, iv, tag)

    def test_modified_authentication_tag_failure(self):
        aes_key = generate_aes_key(256)
        plaintext = b"Important ledger records"
        ciphertext, iv, tag = encrypt_aes_gcm(aes_key, plaintext)

        # Tamper with the tag (flip a bit)
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 1
        tampered_tag = bytes(tampered_tag)

        # Attempt decryption and assert tag validation fails
        with self.assertRaises(InvalidTag):
            decrypt_aes_gcm(aes_key, ciphertext, iv, tampered_tag)

    def test_invalid_metadata_handling(self):
        # Test base64 parsing or length checks
        with self.assertRaises(Exception):
            decrypt_file_hybrid(
                "invalid_b64_ciphertext!!!",
                "invalid_b64_key!!!",
                "invalid_b64_iv!!!",
                "invalid_b64_tag!!!",
                self.private_pem
            )

    def test_sensitivity_level_v2_backward_compatibility(self):
        plaintext = b"Compatibility payload text"

        # 1. Test Version 2 Public Sensitivity (Uses AES-256-GCM)
        res_v2 = encrypt_by_sensitivity(plaintext, 'Public', self.public_pem)
        self.assertEqual(res_v2["key_size"], 256)
        self.assertEqual(res_v2["version"], 2)

        # Decrypt Public sensitivity (should unwrap DEK correctly via server master key)
        decrypted_v2 = decrypt_by_sensitivity(
            ciphertext_bytes=res_v2["ciphertext"],
            sensitivity='Public',
            encrypted_file_key_b64=res_v2["encrypted_file_key"],
            iv_b64=res_v2["iv_or_nonce"],
            tag_b64=res_v2["tag"],
            user_private_key_pem=self.private_pem,
            version=2
        )
        self.assertEqual(decrypted_v2, plaintext)

        # 2. Test Version 1 Compatibility (If key wrapping of AES-128 is passed)
        # We manually construct a v1 Public payload (AES-128 key)
        from app.encryption.hybrid_engine import get_server_master_key
        server_master_key = get_server_master_key()
        v1_dek = generate_aes_key(128) # 16 bytes key
        v1_ciphertext, v1_iv, v1_tag = encrypt_aes_gcm(v1_dek, plaintext)
        v1_wrapped_dek, v1_wrap_iv, v1_wrap_tag = encrypt_aes_gcm(server_master_key, v1_dek)
        v1_encrypted_file_key_b64 = base64.b64encode(v1_wrap_iv + v1_wrap_tag + v1_wrapped_dek).decode('utf-8')

        # Decrypt simulating v1 data (version=1, Public sensitivity)
        decrypted_v1 = decrypt_by_sensitivity(
            ciphertext_bytes=v1_ciphertext,
            sensitivity='Public',
            encrypted_file_key_b64=v1_encrypted_file_key_b64,
            iv_b64=base64.b64encode(v1_iv).decode('utf-8'),
            tag_b64=base64.b64encode(v1_tag).decode('utf-8'),
            user_private_key_pem=self.private_pem,
            version=1
        )
        self.assertEqual(decrypted_v1, plaintext)

    def test_nonce_uniqueness(self):
        # Asserts that consecutive encryptions using GCM produce unique nonces
        key = generate_aes_key(256)
        plaintext = b"Payload sample text"
        _, iv1, _ = encrypt_aes_gcm(key, plaintext)
        _, iv2, _ = encrypt_aes_gcm(key, plaintext)
        self.assertNotEqual(iv1, iv2)

    def test_insecure_rsa_key_size_rejection(self):
        # Generates a weak 1024-bit RSA key directly (bypassing generate_rsa_keypair check)
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        
        weak_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend()
        )
        weak_pub_pem = weak_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        weak_priv_pem = weak_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        aes_key = generate_aes_key(256)
        
        # Wrapping with a weak public key must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            encrypt_key_rsa(weak_pub_pem, aes_key)
        self.assertIn("insecure rsa key size", str(ctx.exception).lower())

        # Unwrapping with a weak private key must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            decrypt_key_rsa(weak_priv_pem, b"dummy encrypted key bytes")
        self.assertIn("insecure rsa key size", str(ctx.exception).lower())

    def test_unsupported_version_rejection(self):
        # Version 3 is not supported, must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            decrypt_by_sensitivity(
                ciphertext_bytes=b"dummy",
                sensitivity='Public',
                encrypted_file_key_b64="YQ==",
                iv_b64="YQ==",
                tag_b64="YQ==",
                user_private_key_pem=self.private_pem,
                version=3
            )
        self.assertIn("unsupported payload encryption version", str(ctx.exception).lower())

    def test_empty_and_large_file_encryption(self):
        # Empty payload
        empty_plain = b""
        res_empty = encrypt_by_sensitivity(empty_plain, 'Public', self.public_pem)
        dec_empty = decrypt_by_sensitivity(
            ciphertext_bytes=res_empty["ciphertext"],
            sensitivity='Public',
            encrypted_file_key_b64=res_empty["encrypted_file_key"],
            iv_b64=res_empty["iv_or_nonce"],
            tag_b64=res_empty["tag"],
            user_private_key_pem=self.private_pem,
            version=2
        )
        self.assertEqual(dec_empty, empty_plain)

        # Large payload (1MB)
        large_plain = b"X" * (1024 * 1024)
        res_large = encrypt_by_sensitivity(large_plain, 'Public', self.public_pem)
        dec_large = decrypt_by_sensitivity(
            ciphertext_bytes=res_large["ciphertext"],
            sensitivity='Public',
            encrypted_file_key_b64=res_large["encrypted_file_key"],
            iv_b64=res_large["iv_or_nonce"],
            tag_b64=res_large["tag"],
            user_private_key_pem=self.private_pem,
            version=2
        )
        self.assertEqual(dec_large, large_plain)

if __name__ == '__main__':
    unittest.main()
