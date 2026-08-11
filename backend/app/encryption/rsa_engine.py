from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size_bits=2048):
    """
    Generates a new RSA public/private keypair.
    Default key size: 2048 bits.
    """
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
    Uses OAEP padding with SHA-256.
    """
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode('utf-8')
        
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    
    encrypted_key = public_key.encrypt(
        session_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_key_rsa(private_key_pem, encrypted_key_bytes):
    """
    Decrypts a symmetric key using an RSA private key.
    Uses OAEP padding with SHA-256.
    """
    if isinstance(private_key_pem, str):
        private_key_pem = private_key_pem.encode('utf-8')
        
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    session_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key
