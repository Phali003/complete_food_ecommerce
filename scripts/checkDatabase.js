const { pool } = require('../config/database');

async function checkDatabaseStructure() {
    let connection;
    try {
        console.log('Connecting to database...');
        connection = await pool.getConnection();
        console.log('Connected successfully! Checking database structure...\n');

        // Check users table
        console.log('Checking users table...');
        const [userTable] = await connection.query(`
            SELECT TABLE_NAME, ENGINE, TABLE_COLLATION
            FROM information_schema.TABLES
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'users'
        `);

        if (userTable.length === 0) {
            console.error('❌ users table is missing!');
            console.log('Please run the schema.sql file to create the required tables.');
            return false;
        }

        // Check users table columns
        const [userColumns] = await connection.query(`
            SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA, COLLATION_NAME
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'users'
        `);

        const requiredColumns = [
            'id',
            'username',
            'email',
            'password_hash',
            'role'
        ];

        const missingColumns = requiredColumns.filter(
            col => !userColumns.some(dbCol => dbCol.COLUMN_NAME === col)
        );

        if (missingColumns.length > 0) {
            console.error('❌ Missing columns in users table:', missingColumns.join(', '));
            console.log('Please run the schema.sql file to add the missing columns.');
            return false;
        }

        // Check column collations for case-insensitivity
        const usernameCol = userColumns.find(col => col.COLUMN_NAME === 'username');
        const emailCol = userColumns.find(col => col.COLUMN_NAME === 'email');
        
        if (!usernameCol.COLLATION_NAME || !usernameCol.COLLATION_NAME.includes('_ci')) {
            console.error('❌ Username column does not have case-insensitive collation!');
            console.log('This can cause login issues with different letter cases.');
            return false;
        }

        if (!emailCol.COLLATION_NAME || !emailCol.COLLATION_NAME.includes('_ci')) {
            console.error('❌ Email column does not have case-insensitive collation!');
            console.log('This can cause login issues with different letter cases.');
            return false;
        }

        // Check indexes
        const [userIndexes] = await connection.query(`
            SHOW INDEX FROM users
        `);

        const requiredIndexes = [
            'username',
            'email',
        ];

        const missingIndexes = requiredIndexes.filter(
            idx => !userIndexes.some(dbIdx => dbIdx.Column_name === idx)
        );

        if (missingIndexes.length > 0) {
            console.error('❌ Missing indexes in users table:', missingIndexes.join(', '));
            console.log('Please run the schema.sql file to add the missing indexes.');
            return false;
        }

        // Check for case-insensitive indexes
        const hasUsernameLowerIndex = userIndexes.some(idx => 
            idx.Expression?.toLowerCase().includes('lower') && 
            idx.Column_name === 'username'
        );
        
        const hasEmailLowerIndex = userIndexes.some(idx => 
            idx.Expression?.toLowerCase().includes('lower') && 
            idx.Column_name === 'email'
        );

        if (!hasUsernameLowerIndex) {
            console.warn('⚠️ No index for case-insensitive username lookups found.');
            console.log('We recommend adding an index: CREATE INDEX idx_username_lower ON users(LOWER(username));');
        }

        if (!hasEmailLowerIndex) {
            console.warn('⚠️ No index for case-insensitive email lookups found.');
            console.log('We recommend adding an index: CREATE INDEX idx_email_lower ON users(LOWER(email));');
        }

        // Test a sample user login query
        try {
            console.log('\nTesting case-insensitive user lookup...');
            const testUsername = 'TestUser';
            
            // Try a case-insensitive username lookup
            const [userByUsername] = await connection.query(`
                SELECT id, username FROM users 
                WHERE LOWER(username) = LOWER(?)
                LIMIT 1
            `, [testUsername]);
            
            console.log(`Lookup test with username '${testUsername}': ${userByUsername.length > 0 ? 'User found' : 'No user found'}`);
            
            // Try a case-insensitive email lookup
            const testEmail = 'test@example.com';
            const [userByEmail] = await connection.query(`
                SELECT id, username, email FROM users 
                WHERE LOWER(email) = LOWER(?)
                LIMIT 1
            `, [testEmail]);
            
            console.log(`Lookup test with email '${testEmail}': ${userByEmail.length > 0 ? 'User found' : 'No user found'}`);
        } catch (error) {
            console.error('Test query failed:', error.message);
        }

        console.log('\n✅ Users table structure looks good!');
        
        // Show total number of users in the system
        const [userCount] = await connection.query('SELECT COUNT(*) as count FROM users');
        console.log(`Total users in the system: ${userCount[0].count}`);
        
        return true;
    } catch (error) {
        console.error('Error checking database structure:', error);
        return false;
    } finally {
        if (connection) {
            connection.release();
            console.log('\nDatabase connection released.');
        }
    }
}

// Run the check
checkDatabaseStructure()
    .then(isValid => {
        if (!isValid) {
            console.log('\nTo fix these issues:');
            console.log('1. Create the migrations directory if it doesn\'t exist: mkdir migrations');
            console.log('2. Save the schema.sql file with the correct table definitions');
            console.log('3. Run the schema.sql file: mysql -u <username> -p food_ecommerce < migrations/schema.sql');
            console.log('\nOr you can apply these changes manually through a MySQL client.');
        } else {
            console.log('\nYour database structure looks good! If you\'re still having login issues:');
            console.log('1. Check that bcrypt is working correctly for password hashing/verification');
            console.log('2. Verify that the JWT token is being generated and validated correctly');
            console.log('3. Check browser cookies and CORS settings for token storage');
        }
        process.exit(isValid ? 0 : 1);
    })
    .catch(error => {
        console.error('Failed to check database structure:', error);
        process.exit(1);
    });

