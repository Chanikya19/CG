-- CipherGuard Database Schema Definition
-- Target Database System: MySQL 8.x

CREATE DATABASE IF NOT EXISTS cipherguard;
USE cipherguard;

-- 1. Users Table
CREATE TABLE IF NOT EXISTS Users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    two_factor_secret VARCHAR(100) NULL,
    role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    status ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    failed_login_attempts INT DEFAULT 0,
    lockout_until DATETIME NULL,
    rsa_public_key TEXT NULL,
    rsa_private_key TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Files Table
CREATE TABLE IF NOT EXISTS Files (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    owner_id INT UNSIGNED NOT NULL,
    filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(512) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    checksum VARCHAR(64) NOT NULL, -- SHA-256
    is_encrypted BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES Users(id) ON DELETE CASCADE,
    INDEX idx_owner (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. EncryptionKeys Table
CREATE TABLE IF NOT EXISTS EncryptionKeys (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id INT UNSIGNED NOT NULL,
    user_id INT UNSIGNED NOT NULL,
    encrypted_file_key TEXT NOT NULL,
    key_type VARCHAR(100) NOT NULL DEFAULT 'AES-256-GCM',
    iv_or_nonce VARCHAR(100) NOT NULL,
    tag VARCHAR(100) NULL,
    encryption_time_ms DOUBLE DEFAULT 0.0,
    version INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES Files(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE,
    INDEX idx_file_user (file_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. FileClassification Table
CREATE TABLE IF NOT EXISTS FileClassification (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id INT UNSIGNED NOT NULL UNIQUE,
    classification_label ENUM('Public', 'Confidential', 'Secret') NOT NULL DEFAULT 'Confidential',
    dlp_risk_score DECIMAL(5, 2) NOT NULL DEFAULT 0.00,
    contains_pii BOOLEAN NOT NULL DEFAULT FALSE,
    contains_credentials BOOLEAN NOT NULL DEFAULT FALSE,
    contains_ip BOOLEAN NOT NULL DEFAULT FALSE,
    classified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES Files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. FileIntegrity Table
CREATE TABLE IF NOT EXISTS FileIntegrity (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id INT UNSIGNED NOT NULL UNIQUE,
    sha256_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES Files(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. FileSharing Table
CREATE TABLE IF NOT EXISTS FileSharing (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    file_id INT UNSIGNED NOT NULL,
    owner_id INT UNSIGNED NOT NULL,
    share_token VARCHAR(100) UNIQUE NOT NULL,
    qr_code TEXT NULL,
    expiry_time TIMESTAMP NOT NULL,
    status ENUM('active', 'revoked', 'expired') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES Files(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES Users(id) ON DELETE CASCADE,
    INDEX idx_sharing (owner_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. ActivityLogs Table
CREATE TABLE IF NOT EXISTS ActivityLogs (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    action VARCHAR(100) NOT NULL,
    module VARCHAR(100) NOT NULL DEFAULT 'General',
    file_name VARCHAR(255) NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NULL,
    details JSON NULL,
    status ENUM('success', 'failed', 'blocked') NOT NULL DEFAULT 'success',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE SET NULL,
    INDEX idx_user_activity (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. ClassificationHistory Table
CREATE TABLE IF NOT EXISTS ClassificationHistory (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    filename VARCHAR(255) NOT NULL,
    category ENUM('Public', 'Confidential', 'Secret') NOT NULL,
    confidence DOUBLE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
