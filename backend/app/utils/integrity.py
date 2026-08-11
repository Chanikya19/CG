import hashlib
import hmac
from datetime import datetime

def generate_sha256(data_bytes):
    """
    Generates the SHA-256 hash signature of the given data bytes.
    Returns: The hex string representation of the hash.
    """
    if not isinstance(data_bytes, bytes):
        raise TypeError("Input data must be of type bytes.")
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data_bytes)
    return sha256_hash.hexdigest()

def verify_sha256(data_bytes, expected_hash):
    """
    Verifies if the SHA-256 hash of the given data matches the expected hash.
    Uses hmac.compare_digest for constant-time comparison to prevent side-channel timing attacks.
    """
    if not isinstance(expected_hash, str):
        raise TypeError("Expected hash must be a hex string.")
        
    actual_hash = generate_sha256(data_bytes)
    # Timing-attack resilient comparison
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())

def detect_tampering(data_bytes, expected_hash):
    """
    Checks if the data has been altered.
    Returns True if tampered (hashes do not match), False if intact (hashes match).
    """
    return not verify_sha256(data_bytes, expected_hash)

def generate_verification_report(filename, data_bytes, expected_hash):
    """
    Generates a detailed integrity audit verification report.
    Returns: A dictionary mapping the verification status and diagnostic hashes.
    """
    try:
        actual_hash = generate_sha256(data_bytes)
        is_valid = hmac.compare_digest(actual_hash.lower(), expected_hash.lower())
        status = "PASSED" if is_valid else "FAILED - INTEGRITY_VIOLATION"
    except Exception as e:
        actual_hash = None
        is_valid = False
        status = f"ERROR - {str(e)}"

    return {
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "expected_hash": expected_hash,
        "computed_hash": actual_hash,
        "integrity_verified": is_valid,
        "status": status
    }
