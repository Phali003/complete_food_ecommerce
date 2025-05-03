-- Migration: Add tables for enhanced password reset functionality
-- Created: 2025-04-16

-- Table to store password history for preventing password reuse
CREATE TABLE IF NOT EXISTS password_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table to track password reset attempts for rate limiting
CREATE TABLE IF NOT EXISTS password_reset_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_username VARCHAR(50) NOT NULL,
    initiated_by INT,
    attempt_count INT DEFAULT 1,
    attempt_window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    FOREIGN KEY (initiated_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_target_username (target_username),
    INDEX idx_window_start (attempt_window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Table for security audit logging
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    event_type VARCHAR(50) NOT NULL,
    event_description TEXT,
    ip_address VARCHAR(45),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_event_type (event_type),
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add comments for better documentation
ALTER TABLE password_history COMMENT 'Stores password history to prevent reuse of recent passwords';
ALTER TABLE password_reset_attempts COMMENT 'Tracks password reset attempts for rate limiting';
ALTER TABLE audit_log COMMENT 'Security audit log for tracking security-related events';

