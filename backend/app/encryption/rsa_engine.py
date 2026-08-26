from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from app.encryption.constants import RSA_KEY_SIZE_BITS, OAEP_HASH_ALGORITHM, MGF1_HASH_ALGORITHM

def generate_rsa_keypair(key_size_bits=RSA_KEY_SIZE_BITS):
    """
    Generates a new RSA public/private keypair.
    Enforces minimum key size of 2048 bits to prevent algorithm downgrades.
    """
    if key_size_bits < RSA_KEY_SIZE_BITS:
        raise ValueError(f"Insecure RSA key size requested. Minimum supported key size is {RSA_KEY_SIZE_BITS} bits.")
        
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
        backend=default_backend()
    )
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key to PEM format
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem

def encrypt_key_rsa(public_key_pem, session_key_bytes):
    """
    Encrypts a symmetric key using an RSA public key.
    Uses OAEP padding with SHA-256 (configured via constants).
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
        
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    # Validate public key size meets minimum security requirements
    if public_key.key_size < RSA_KEY_SIZE_BITS:
        raise ValueError(f"Insecure RSA key size. Minimum supported key size is {RSA_KEY_SIZE_BITS} bits.")
        
    encrypted_key = public_key.encrypt(
        session_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=MGF1_HASH_ALGORITHM),
            algorithm=OAEP_HASH_ALGORITHM,
            label=None
        )
    )
    return encrypted_key

def decrypt_key_rsa(private_key_pem, encrypted_key_bytes):
    """
    Decrypts a symmetric key using an RSA private key.
    Uses OAEP padding with SHA-256 (configured via constants).
    """
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')
        
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Validate private key size meets minimum security requirements
    if private_key.key_size < RSA_KEY_SIZE_BITS:
        raise ValueError(f"Insecure RSA key size. Minimum supported key size is {RSA_KEY_SIZE_BITS} bits.")
        
    session_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=MGF1_HASH_ALGORITHM),
            algorithm=OAEP_HASH_ALGORITHM,
            label=None
        )
    )
    return session_key
