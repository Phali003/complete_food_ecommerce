const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function testUserCreation() {
    console.log('Starting test user creation...');
    
    const connection = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'mysql',
        database: 'food_ecommerce'
    });
    
    try {
        // First delete the user if it already exists to avoid duplicate key errors
        await connection.execute(
            'DELETE FROM users WHERE username = ? OR email = ?', 
            ['testuser8000', 'testuser8000@example.com']
        );
        console.log('Cleaned up any existing test user');
        
        // Use a strong password that meets all validation requirements
        const testPassword = 'TestPass123!';
        const hashedPassword = await bcrypt.hash(testPassword, 10);
        console.log('Password hashed successfully');
        
        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            ['testuser8000', 'testuser8000@example.com', hashedPassword, 'user']
        );
        console.log('Insert Result:', result);
        console.log('New user ID:', result.insertId);
        console.log('Created test user with:');
        console.log('  Username: testuser8000');
        console.log('  Email: testuser8000@example.com');
        console.log('  Password: TestPass123!');
        console.log('You can use these credentials to log in via the web interface');
        
    } catch (error) {
        console.error('Error:', error);
    } finally {
        await connection.end();
        console.log('Connection closed');
    }
}

testUserCreation();
