-- Migration: Remove password reset related tables and columns
-- Created: 2025-05-15

-- Drop tables that were used for password reset functionality
DROP TABLE IF EXISTS password_reset_attempts;

-- Remove reset token columns from users table
ALTER TABLE users 
    DROP COLUMN reset_token,
    DROP COLUMN reset_token_expiry;

-- Log the migration in audit_log
INSERT INTO audit_log (event_type, event_description) 
VALUES ('SCHEMA_MIGRATION', 'Removed password reset tables and columns');

