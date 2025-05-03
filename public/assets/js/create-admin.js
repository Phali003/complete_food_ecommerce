const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
require('dotenv').config();

async function createAdmin() {
    try {
        // Generate password hash
        const password = 'admin123';
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Connect to database
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME
        });
        
        // Delete existing admin if exists
        await connection.execute('DELETE FROM users WHERE email = ?', ['admin@example.com']);
        
        // Create new admin user
        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
            ['admin', 'admin@example.com', hashedPassword, 'admin']
        );
        
        console.log('Admin user created successfully:', {
            id: result.insertId,
            username: 'admin',
            email: 'admin@example.com',
            role: 'admin'
        });
        
        // Verify the password hash
        const [users] = await connection.execute('SELECT * FROM users WHERE email = ?', ['admin@example.com']);
        const isValid = await bcrypt.compare(password, users[0].password_hash);
        console.log('Password verification test:', isValid ? 'PASSED' : 'FAILED');
        
        await connection.end();
        
    } catch (error) {
        console.error('Failed to create admin:', error);
    }
}

createAdmin();

