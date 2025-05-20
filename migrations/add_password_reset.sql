-- Migration: Add password reset functionality tables
-- Created: 2025-05-15

-- Drop existing table to recreate with correct structure
DROP TABLE IF EXISTS password_reset_attempts;

-- Create table for tracking password reset attempts with correct columns
CREATE TABLE IF NOT EXISTS password_reset_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    attempt_count INT DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    INDEX idx_email_attempt (email, last_attempt)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Log the migration
INSERT INTO audit_log (event_type, event_description) 
VALUES ('SCHEMA_MIGRATION', 'Created password reset attempts table');

