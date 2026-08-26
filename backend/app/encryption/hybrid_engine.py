import base64
import time
import hashlib
import os
from app.encryption.aes_engine import generate_aes_key, encrypt_aes_gcm, decrypt_aes_gcm
from app.encryption.rsa_engine import encrypt_key_rsa, decrypt_key_rsa
from app.encryption.constants import (
    AES_KEY_SIZE_BITS,
    CURRENT_ENCRYPTION_VERSION,
    LEGACY_ENCRYPTION_VERSION
)

def encrypt_file_hybrid(file_bytes, recipient_public_key_pem, aes_key_size=AES_KEY_SIZE_BITS):
    """
    Symmetrically encrypts file_bytes using AES GCM and wraps the DEK using RSA.
    All return parameters are base64 string formatted for DB compatibility.
    """
    # 1. Generate symmetric DEK
    dek = generate_aes_key(aes_key_size)
    
    # 2. Encrypt the file payload
    ciphertext, iv, tag = encrypt_aes_gcm(dek, file_bytes)
    
    # 3. Encrypt the symmetric key with recipient's public key
    encrypted_dek = encrypt_key_rsa(recipient_public_key_pem, dek)
    
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "encrypted_file_key": base64.b64encode(encrypted_dek).decode('utf-8'),
        "iv_or_nonce": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "key_type": f"AES-{aes_key_size}-GCM"
    }

def decrypt_file_hybrid(ciphertext_b64, encrypted_key_b64, iv_b64, tag_b64, recipient_private_key_pem, aes_key_size=AES_KEY_SIZE_BITS):
    """
    Decrypts the envelope DEK using RSA, then decrypts the AES payload.
    All inputs (except the private key) are expected to be base64 strings.
    """
    # 1. Decode base64 inputs
    ciphertext = base64.b64decode(ciphertext_b64)
    encrypted_dek = base64.b64decode(encrypted_key_b64)
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    
    # 2. Asymmetrically decrypt the DEK
    dek = decrypt_key_rsa(recipient_private_key_pem, encrypted_dek)
    
    # 3. Decrypt the file payload
    return decrypt_aes_gcm(dek, ciphertext, iv, tag)

def get_server_master_key():
    import sys
    is_testing = False
    try:
        from flask import current_app
        secret = current_app.config.get('SECRET_KEY')
        is_testing = current_app.config.get('TESTING') or False
        if not secret:
            secret = os.environ.get('SECRET_KEY', 'cipherguard-super-secret-key-2026')
    except Exception:
        secret = os.environ.get('SECRET_KEY', 'cipherguard-super-secret-key-2026')
        is_testing = ('pytest' in sys.modules) or ('unittest' in sys.modules)

    if secret == 'cipherguard-super-secret-key-2026' and not is_testing:
        raise RuntimeError("CRITICAL CONFIGURATION ERROR: You must configure a secure SECRET_KEY in production.")

    return hashlib.sha256(secret.encode('utf-8')).digest()

def encrypt_by_sensitivity(file_bytes, sensitivity, user_public_key_pem):
    """
    Encrypts file bytes based on sensitivity classification:
    - Public -> AES-256 GCM, key wrapped with server master key.
    - Confidential -> AES-256 GCM, key wrapped with server master key.
    - Secret -> AES-256 GCM, key wrapped with user RSA-2048 public key.
    """
    start_time = time.time()
    server_master_key = get_server_master_key()

    if sensitivity == 'Public':
        key_size = AES_KEY_SIZE_BITS
        dek = generate_aes_key(key_size)
        ciphertext, iv, tag = encrypt_aes_gcm(dek, file_bytes)
        # Wrap DEK using server master key
        wrapped_dek, wrap_iv, wrap_tag = encrypt_aes_gcm(server_master_key, dek)
        encrypted_file_key_b64 = base64.b64encode(wrap_iv + wrap_tag + wrapped_dek).decode('utf-8')
        key_type = 'AES-256-GCM'
    elif sensitivity == 'Confidential':
        key_size = AES_KEY_SIZE_BITS
        dek = generate_aes_key(key_size)
        ciphertext, iv, tag = encrypt_aes_gcm(dek, file_bytes)
        # Wrap DEK using server master key
        wrapped_dek, wrap_iv, wrap_tag = encrypt_aes_gcm(server_master_key, dek)
        encrypted_file_key_b64 = base64.b64encode(wrap_iv + wrap_tag + wrapped_dek).decode('utf-8')
        key_type = 'AES-256-GCM'
    elif sensitivity == 'Secret':
        key_size = AES_KEY_SIZE_BITS
        dek = generate_aes_key(key_size)
        ciphertext, iv, tag = encrypt_aes_gcm(dek, file_bytes)
        # Wrap DEK using user's RSA public key
        if not user_public_key_pem:
            raise ValueError("RSA Public Key is required for Secret sensitivity level (Hybrid Encryption).")
        wrapped_dek = encrypt_key_rsa(user_public_key_pem, dek)
        encrypted_file_key_b64 = base64.b64encode(wrapped_dek).decode('utf-8')
        key_type = 'Hybrid (AES-256 + RSA-2048)'
    else:
        raise ValueError(f"Unknown sensitivity classification level: '{sensitivity}'")

    duration_ms = round((time.time() - start_time) * 1000, 3)

    return {
        "ciphertext": ciphertext, # Raw bytes to write to vault storage on disk
        "encrypted_file_key": encrypted_file_key_b64,
        "iv_or_nonce": base64.b64encode(iv).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "key_type": key_type,
        "key_size": key_size,
        "duration_ms": duration_ms,
        "version": CURRENT_ENCRYPTION_VERSION
    }

def decrypt_by_sensitivity(ciphertext_bytes, sensitivity, encrypted_file_key_b64, iv_b64, tag_b64, user_private_key_pem, version=LEGACY_ENCRYPTION_VERSION):
    """
    Decrypts ciphertext bytes based on sensitivity:
    - Public/Confidential -> DEK unwrapped with server master key.
    - Secret -> DEK unwrapped with user RSA private key.
    """
    if version not in [CURRENT_ENCRYPTION_VERSION, LEGACY_ENCRYPTION_VERSION]:
        raise ValueError(f"Unsupported payload encryption version: {version}")

    server_master_key = get_server_master_key()
    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)

    if sensitivity in ['Public', 'Confidential']:
        # Packed format: wrap_iv (12 bytes) + wrap_tag (16 bytes) + wrapped_dek (remainder)
        packed_dek = base64.b64decode(encrypted_file_key_b64)
        wrap_iv = packed_dek[:12]
        wrap_tag = packed_dek[12:28]
        wrapped_dek = packed_dek[28:]
        dek = decrypt_aes_gcm(server_master_key, wrapped_dek, wrap_iv, wrap_tag)
    elif sensitivity == 'Secret':
        if not user_private_key_pem:
            raise ValueError("RSA Private Decryption Key is required for Secret (Hybrid Encrypted) vault assets.")
        encrypted_dek = base64.b64decode(encrypted_file_key_b64)
        dek = decrypt_key_rsa(user_private_key_pem, encrypted_dek)
    else:
        raise ValueError(f"Unknown sensitivity classification level: '{sensitivity}'")

    return decrypt_aes_gcm(dek, ciphertext_bytes, iv, tag)

