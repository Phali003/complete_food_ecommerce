const { pool } = require('../config/database');

/**
 * Migration to add the password_reset_tokens table for password reset functionality
 */
async function runMigration() {
  let connection;
  
  try {
    console.log('Starting migration for password_reset_tokens table...');
    
    // Get a connection from the pool
    connection = await pool.getConnection();
    
    // Create the password_reset_tokens table
    await connection.execute(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT PRIMARY KEY AUTO_INCREMENT,
        email VARCHAR(255) NOT NULL,
        token VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        user_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_token (token),
        INDEX idx_email (email),
        INDEX idx_expires_at (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    
    console.log('✅ password_reset_tokens table created successfully');
    
    // Check if there are any pending password reset tokens in the users table that need to be migrated
    const [users] = await connection.execute(`
      SELECT id, email, reset_token, reset_token_expiry
      FROM users
      WHERE reset_token IS NOT NULL AND reset_token_expiry > NOW()
    `);
    
    if (users.length > 0) {
      console.log(`Found ${users.length} pending password reset tokens to migrate`);
      
      // Migrate the tokens from users to the new table
      for (const user of users) {
        await connection.execute(`
          INSERT INTO password_reset_tokens
            (email, token, expires_at, user_id)
          VALUES (?, ?, ?, ?)
        `, [user.email, user.reset_token, user.reset_token_expiry, user.id]);
      }
      
      console.log('✅ Migrated pending reset tokens to new table');
    } else {
      console.log('No pending reset tokens to migrate');
    }
    
    console.log('Migration completed successfully!');
    return true;
  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    if (connection) {
      connection.release();
      console.log('Database connection released');
    }
  }
}

// Run the migration if this script is executed directly
if (require.main === module) {
  runMigration()
    .then(() => {
      console.log('🎉 Migration completed successfully');
      process.exit(0);
    })
    .catch((error) => {
      console.error('❌ Migration failed:', error);
      process.exit(1);
    });
}

module.exports = runMigration;

