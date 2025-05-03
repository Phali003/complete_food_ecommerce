const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
require('dotenv').config();
// Import TEST_PASSWORD from test_db.js
const { TEST_PASSWORD } = require('./test_db.js');
async function testLogin() {
    try {
        console.log('Testing test user login process...');
        console.log('Connecting to database...');
        // Connect to database
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME
        });
        console.log('Database connection established');
        
        // Get test user data
        console.log('Fetching test user data...');
        console.log('Looking for test user with email: test_user@example.com');
        const [users] = await connection.execute(
            'SELECT * FROM users WHERE email = ?',
            ['test_user@example.com']
        );
        
        if (users.length === 0) {
            console.log('Test user not found! Make sure you run test_db.js first to create the test user.');
            return;
        }
        
        const user = users[0];
        console.log('Test user found:', {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            password_hash: user.password_hash ? user.password_hash.substring(0, 10) + '...' : 'undefined'
        });
        
        // Test password verification
        const password = TEST_PASSWORD; // Use the same password from test_db.js
        console.log('\nTesting password verification...');
        console.log('Password being tested:', password);
        console.log('Stored password hash (partial):', user.password_hash ? user.password_hash.substring(0, 10) + '...' : 'undefined');
        console.log('Password hash length:', user.password_hash ? user.password_hash.length : 0);
        const isValid = await bcrypt.compare(password, user.password_hash);
        console.log('Password verification result:', isValid);
        
        if (isValid) {
            console.log('✅ Login test successful! User credentials are valid.');
            console.log(`This confirms that a user could successfully log in with:`);
            console.log(`  - Username: ${user.username}`); 
            console.log(`  - Email: ${user.email}`);
            console.log(`  - Password: ${TEST_PASSWORD}`);
        } else {
            console.log('❌ Login test failed! Invalid credentials.');
            console.log('Possible issues:');
            console.log('1. Make sure test_db.js was run first to create the test user');
            console.log('2. Make sure both scripts use the same TEST_PASSWORD');
            console.log('3. Check if bcrypt is working correctly');
        }
        
        await connection.end();
        console.log('Database connection closed');
        
    } catch (error) {
        console.error('Test failed:', error);
        console.error('Error details:', error.message);
    }
}

testLogin();
