/**
 * Script to remove all user accounts (role='user') while preserving admin accounts.
 * This script is designed to run after the project is completed to clean up the database.
 */

const { 
  beginTransaction, 
  commitTransaction, 
  rollbackTransaction, 
  query 
} = require('../config/database');

// Main function to remove user accounts
const removeUserAccounts = async () => {
  console.log('Starting user account removal process...');
  
  let connection;
  let deletedUserIds = [];
  
  try {
    // Step 1: Start a transaction
    console.log('Beginning transaction...');
    connection = await beginTransaction();
    console.log('Transaction started successfully');

    // Step 2: Get all user IDs with role='user'
    console.log('Identifying users to be removed...');
    const userAccountsToRemove = await connection.execute(
      'SELECT id, username, email FROM users WHERE role = ?',
      ['user']
    );
    
    const userIds = userAccountsToRemove[0].map(user => user.id);
    deletedUserIds = [...userIds]; // Store for reporting
    
    console.log(`Found ${userIds.length} user accounts to remove`);
    if (userIds.length === 0) {
      console.log('No user accounts to remove. Aborting process.');
      await commitTransaction(connection);
      return { success: true, message: 'No user accounts to remove' };
    }
    
    // Log users to be deleted
    console.log('Users to be deleted:');
    userAccountsToRemove[0].forEach(user => {
      console.log(`- ID: ${user.id}, Username: ${user.username}, Email: ${user.email}`);
    });

    // Step 3a: Delete records from audit_log table
    console.log('Removing related audit_log entries...');
    const placeholders = userIds.map(() => '?').join(',');
    const auditLogQuery = `DELETE FROM audit_log WHERE user_id IN (${placeholders})`;
    const auditLogResult = await connection.execute(auditLogQuery, userIds);
    console.log(`Removed ${auditLogResult[0].affectedRows} audit_log entries`);

    // Step 3b: Delete records from password_history table
    console.log('Removing related password_history entries...');
    const passwordHistoryQuery = `DELETE FROM password_history WHERE user_id IN (${placeholders})`;
    const passwordHistoryResult = await connection.execute(passwordHistoryQuery, userIds);
    console.log(`Removed ${passwordHistoryResult[0].affectedRows} password_history entries`);

    // Step 3c: Delete records from blacklisted_tokens table
    console.log('Removing related blacklisted_tokens entries...');
    const blacklistedTokensQuery = `DELETE FROM blacklisted_tokens WHERE user_id IN (${placeholders})`;
    const blacklistedTokensResult = await connection.execute(blacklistedTokensQuery, userIds);
    console.log(`Removed ${blacklistedTokensResult[0].affectedRows} blacklisted_tokens entries`);

    // Step 3d: Delete records from cart_items table (if applicable)
    console.log('Removing related cart_items entries...');
    const cartItemsQuery = `DELETE FROM cart_items WHERE user_id IN (${placeholders})`;
    try {
      const cartItemsResult = await connection.execute(cartItemsQuery, userIds);
      console.log(`Removed ${cartItemsResult[0].affectedRows} cart_items entries`);
    } catch (error) {
      if (error.code === 'ER_NO_SUCH_TABLE') {
        console.log('cart_items table does not exist, skipping...');
      } else {
        throw error;
      }
    }

    // Step 3e: Delete records from orders table (if applicable)
    console.log('Removing related orders entries...');
    const ordersQuery = `DELETE FROM orders WHERE user_id IN (${placeholders})`;
    try {
      const ordersResult = await connection.execute(ordersQuery, userIds);
      console.log(`Removed ${ordersResult[0].affectedRows} orders entries`);
    } catch (error) {
      if (error.code === 'ER_NO_SUCH_TABLE') {
        console.log('orders table does not exist, skipping...');
      } else {
        throw error;
      }
    }

    // Step 4: Delete the user accounts themselves
    console.log('Removing user accounts...');
    const deleteUserQuery = `DELETE FROM users WHERE id IN (${placeholders})`;
    const deleteUserResult = await connection.execute(deleteUserQuery, userIds);
    console.log(`Removed ${deleteUserResult[0].affectedRows} user accounts`);

    // Step 5: Reset auto-increment
    console.log('Resetting auto-increment value...');
    // First, find the highest admin ID to set auto-increment after it
    const maxIdResult = await connection.execute('SELECT MAX(id) as max_id FROM users');
    const nextId = maxIdResult[0][0].max_id + 1;
    
    const resetAutoIncrementQuery = `ALTER TABLE users AUTO_INCREMENT = ${nextId}`;
    await connection.execute(resetAutoIncrementQuery);
    console.log(`Auto-increment value reset to ${nextId}`);

    // Step 6: Commit the transaction
    console.log('Committing transaction...');
    await commitTransaction(connection);
    console.log('Transaction committed successfully!');

    return {
      success: true,
      message: `Successfully removed ${deleteUserResult[0].affectedRows} user accounts`,
      details: {
        usersRemoved: deleteUserResult[0].affectedRows,
        auditLogsRemoved: auditLogResult[0].affectedRows,
        passwordHistoriesRemoved: passwordHistoryResult[0].affectedRows,
        blacklistedTokensRemoved: blacklistedTokensResult[0].affectedRows,
        newAutoIncrementValue: nextId
      }
    };
    
  } catch (error) {
    // Step 7: Roll back transaction on error
    console.error('Error during user account removal process:', error.message);
    
    if (connection) {
      console.log('Rolling back transaction...');
      try {
        await rollbackTransaction(connection);
        console.log('Transaction rolled back successfully');
      } catch (rollbackError) {
        console.error('Error rolling back transaction:', rollbackError.message);
      }
    }

    return {
      success: false,
      message: `Failed to remove user accounts: ${error.message}`,
      error: error
    };
  }
};

// Verify remaining accounts after deletion
const verifyRemaining = async () => {
  try {
    console.log('\nVerifying remaining accounts...');
    const remainingUsers = await query('SELECT id, username, role FROM users ORDER BY id');
    
    console.log('\nRemaining accounts:');
    for (const user of remainingUsers) {
      console.log(`- ID: ${user.id}, Username: ${user.username}, Role: ${user.role}`);
    }
    
    console.log(`\nTotal remaining accounts: ${remainingUsers.length}`);
    return remainingUsers;
  } catch (error) {
    console.error('Error verifying remaining accounts:', error.message);
    return [];
  }
};

module.exports = { removeUserAccounts, verifyRemaining };

// Execute the script if it's run directly
if (require.main === module) {
  (async () => {
    console.log('======================================================');
    console.log('=== USER ACCOUNT REMOVAL SCRIPT - PRODUCTION DATA ===');
    console.log('======================================================');
    
    try {
      const result = await removeUserAccounts();
      
      if (result.success) {
        console.log('\n✅ SUCCESS:', result.message);
        if (result.details) {
          console.log('\nDeletion Summary:');
          console.log(`- User accounts removed: ${result.details.usersRemoved}`);
          console.log(`- Audit log entries removed: ${result.details.auditLogsRemoved}`);
          console.log(`- Password history entries removed: ${result.details.passwordHistoriesRemoved}`);
          console.log(`- Blacklisted tokens removed: ${result.details.blacklistedTokensRemoved}`);
          console.log(`- Auto-increment value reset to: ${result.details.newAutoIncrementValue}`);
        }
        
        // Verify remaining accounts
        await verifyRemaining();
      } else {
        console.error('\n❌ ERROR:', result.message);
      }
    } catch (error) {
      console.error('\n❌ FATAL ERROR:', error.message);
    }
    
    console.log('\n======================================================');
    console.log('=== USER ACCOUNT REMOVAL SCRIPT COMPLETE ===');
    console.log('======================================================');
    
    process.exit(0);
  })();
}

