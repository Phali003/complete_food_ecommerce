-- Check if column exists
SET @dbname = 'food_ecommerce';
SET @tablename = 'users';
SET @columnname = 'is_super_admin';
SET @preparedStatement = (SELECT IF(
  (
    SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE
      TABLE_SCHEMA = @dbname
      AND TABLE_NAME = @tablename
      AND COLUMN_NAME = @columnname
  ) > 0,
  "SELECT 'Column already exists'",
  "ALTER TABLE users ADD COLUMN is_super_admin BOOLEAN DEFAULT FALSE"
));

PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- Set existing admin as super_admin
UPDATE users 
SET is_super_admin = TRUE 
WHERE username = 'admin' AND role = 'admin';

