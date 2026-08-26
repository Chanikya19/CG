from cryptography.hazmat.primitives import hashes

# Central Cryptographic Parameter Configurations
AES_KEY_SIZE_BITS = 256
GCM_NONCE_SIZE_BYTES = 12
GCM_TAG_SIZE_BYTES = 16
RSA_KEY_SIZE_BITS = 2048

# Cryptographically Secure Hashing parameters
OAEP_HASH_ALGORITHM = hashes.SHA256()
MGF1_HASH_ALGORITHM = hashes.SHA256()

# Supported Versioning
CURRENT_ENCRYPTION_VERSION = 2
LEGACY_ENCRYPTION_VERSION = 1
