#!/usr/bin/env node
require('dotenv').config();
const bcrypt = require('bcryptjs');
const { pool } = require('../config/database');

async function createInitialAdmin(username, email, password) {
    if (!process.env.INITIAL_ADMIN_SETUP_CODE) {
        console.error('Error: INITIAL_ADMIN_SETUP_CODE not set in environment');
        process.exit(1);
    }

    const connection = await pool.getConnection();
    try {
        // Check if any admin exists
        const [admins] = await connection.execute(
            'SELECT COUNT(*) as count FROM users WHERE role = ?',
            ['admin']
        );

        if (admins[0].count > 0) {
            console.error('Error: Admin account already exists');
            process.exit(1);
        }

        // Create super admin
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash, role, is_super_admin) VALUES (?, ?, ?, ?, ?)',
            [username, email, hashedPassword, 'admin', true]
        );

        console.log('Super admin created successfully!');
        console.log('Username:', username);
        console.log('Please securely store these credentials');

    } catch (error) {
        console.error('Error creating admin:', error);
        process.exit(1);
    } finally {
        connection.release();
        process.exit(0);
    }
}

// Get command line arguments
const args = process.argv.slice(2);
if (args.length !== 3) {
    console.log('Usage: node create-initial-admin.js <username> <email> <password>');
    process.exit(1);
}

createInitialAdmin(args[0], args[1], args[2]);

