# Database Migrations

This directory contains database schema and migration files for the Food E-commerce application.

## Schema Updates

The `schema.sql` file contains the latest database schema with all necessary tables for authentication and user management.

### How to Apply

1. Make sure MySQL is installed and running
2. Create the database if it doesn't exist:
   ```sql
   CREATE DATABASE IF NOT EXISTS food_ecommerce;
   ```
3. Apply the schema:
   ```bash
   mysql -u your_username -p food_ecommerce < schema.sql
   ```

### Tables Created

1. `users` - Stores user information with case-insensitive username/email
2. `password_history` - Tracks password changes for security
3. `audit_log` - Logs authentication events
4. `password_reset_attempts` - Tracks password reset attempts for rate limiting

### Important Notes

- The schema uses case-insensitive collation (utf8mb4_unicode_ci) for username and email fields
- Indexes are created for optimal query performance, including case-insensitive lookups
- Foreign key constraints are added for referential integrity
- Timestamps are automatically managed for created_at and updated_at fields

## Troubleshooting

If you're experiencing authentication issues:

1. Run the database check script:
   ```bash
   node scripts/checkDatabase.js
   ```

2. Make sure the users table has case-insensitive collation for username and email columns

3. Verify that the required indexes exist, especially the case-insensitive ones:
   ```sql
   SHOW INDEX FROM users;
   ```

4. If you're still having issues, you might need to manually fix existing data:
   ```sql
   -- Fix any duplicate emails or usernames (case-insensitive)
   SELECT LOWER(email), COUNT(*) FROM users GROUP BY LOWER(email) HAVING COUNT(*) > 1;
   SELECT LOWER(username), COUNT(*) FROM users GROUP BY LOWER(username) HAVING COUNT(*) > 1;
   ```

