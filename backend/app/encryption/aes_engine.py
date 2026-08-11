import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_aes_key(key_size_bits=256):
    """
    Generates a cryptographically secure random AES key.
    Supported sizes: 128 or 256 bits.
    """
    if key_size_bits not in [128, 256]:
        raise ValueError("Unsupported AES key size. Must be 128 or 256 bits.")
    return os.urandom(key_size_bits // 8)

def encrypt_aes_gcm(key, plaintext_bytes, associated_data=None):
    """
    Encrypts data using AES-GCM mode.
    Returns: (ciphertext, iv, tag) in raw bytes.
    """
    # 12 bytes IV is standard for GCM
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    if associated_data:
        encryptor.authenticate_additional_data(associated_data)

    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return ciphertext, iv, encryptor.tag

def decrypt_aes_gcm(key, ciphertext, iv, tag, associated_data=None):
    """
    Decrypts data using AES-GCM mode.
    Returns: decrypted plaintext bytes.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    if associated_data:
        decryptor.authenticate_additional_data(associated_data)

    return decryptor.update(ciphertext) + decryptor.finalize()
