const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { pool, directQuery } = require('../config/database');
const { protect } = require('../middleware/auth');

// Handle signup requests
// In signup route - modify duplicate check
router.post('/signup', async (req, res) => {
    try {
        const { username, email, password, confirm_password } = req.body;
        
        if (!username || !email || !password || !confirm_password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        let connection = null;
        try {
            connection = await pool.getConnection();

            // Check for existing user
            const [existingUsers] = await connection.execute(
                'SELECT username, email FROM users WHERE LOWER(username) = LOWER(?) OR LOWER(email) = LOWER(?)',
                [username, email]
            );

            if (existingUsers.length > 0) {
                const exists = existingUsers[0];
                if (exists.username.toLowerCase() === username.toLowerCase()) {
                    return res.status(400).json({
                        success: false,
                        message: "Username already taken"
                    });
                }
                if (exists.email.toLowerCase() === email.toLowerCase()) {
                    return res.status(400).json({
                        success: false,
                        message: "Email already registered"
                    });
                }
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const [result] = await connection.execute(
                'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [username, email, hashedPassword, 'user']
            );

            const token = jwt.sign(
                { 
                    userId: result.insertId,
                    username: username,
                    role: 'user'
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                path: '/',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            return res.status(201).json({
                success: true,
                message: "User registered successfully",
                user: {
                    id: result.insertId,
                    username: username,
                    email: email,
                    role: 'user'
                },
                token
            });
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Registration failed. Please try again.",
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Handle login requests
// In login route - modify the parameter handling
router.post('/login', async (req, res) => {
    let connection = null;
    try {
        const { email, username, password } = req.body;
        const identifier = email || username;
        
        if (!identifier || !password) {
            return res.status(400).json({
                success: false,
                message: identifier ? "Password is required" : "Email or username is required"
            });
        }

        connection = await pool.getConnection();
        
        // First check if user exists
        const [users] = await connection.execute(
            `SELECT id, username, email, password_hash, role 
             FROM users 
             WHERE LOWER(username) = LOWER(?) 
             OR LOWER(email) = LOWER(?)`,
            [identifier, identifier]
        );

        if (!users || users.length === 0) {
            return res.status(401).json({
                success: false,
                message: `${email ? 'Email' : 'Username'} not found`
            });
        }

        const user = users[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Incorrect password"
            });
        }

        const token = jwt.sign(
            { 
                userId: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            success: true,
            message: "Login successful",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            token
        });

    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({
            success: false,
            message: "Login failed. Please try again later."
        });
    } finally {
        if (connection) {
            try {
                await connection.release();
            } catch (releaseError) {
                console.error('Error releasing connection:', releaseError);
            }
        }
    }
});

// Test endpoint: Just returns success
router.get('/test-success', (req, res) => {
    console.log('TEST SUCCESS: Request received');
    console.log('Headers:', req.headers);
    
    try {
        res.status(200).json({
            success: true,
            message: "Test endpoint successful",
            timestamp: new Date().toISOString()
        });
        console.log('TEST SUCCESS: Response sent successfully');
    } catch (error) {
        console.error('TEST SUCCESS: Error sending response:', error);
        res.status(500).end('Error in test endpoint');
    }
});

// Test endpoint: Deliberately throws an error
router.get('/test-error', (req, res, next) => {
    console.log('TEST ERROR: Request received, about to throw error');
    
    try {
        // Throw a deliberate error
        throw new Error('This is a test error');
    } catch (error) {
        console.error('TEST ERROR: Error caught:', error.message);
        
        // Handle error directly
        try {
            res.status(500).json({
                success: false,
                message: "Test error endpoint",
                error: error.message
            });
            console.log('TEST ERROR: Error response sent successfully');
        } catch (responseError) {
            console.error('TEST ERROR: Failed to send error response:', responseError);
            res.status(500).end('Failed to send error response');
        }
    }
});

// Initial Admin Setup Endpoint - Only works when no admin exists
router.post('/setup-initial-admin', async (req, res) => {
    console.log('SETUP: Initial admin setup request received');
    
    try {
        const { username, email, password, setupCode } = req.body;
        
        // Validate required fields
        if (!username || !email || !password || !setupCode) {
            return res.status(400).json({
                success: false,
                message: "All fields including setup code are required"
            });
        }
        
        // Verify setup code matches environment variable
        if (setupCode !== process.env.INITIAL_ADMIN_SETUP_CODE) {
            return res.status(403).json({
                success: false,
                message: "Invalid setup code"
            });
        }
        
        // Check if any admin already exists
        const connection = await pool.getConnection();
        try {
            const [admins] = await connection.execute(
                'SELECT COUNT(*) as count FROM users WHERE role = ?',
                ['admin']
            );
            
            if (admins[0].count > 0) {
                return res.status(400).json({
                    success: false,
                    message: "Admin account already exists. This endpoint is only for initial setup."
                });
            }
            
            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            
            // Insert new admin with super_admin privileges
            const [result] = await connection.execute(
                'INSERT INTO users (username, email, password_hash, role, is_super_admin) VALUES (?, ?, ?, ?, ?)',
                [username, email, hashedPassword, 'admin', true]
            );
            
            console.log('SETUP: Initial admin created successfully with ID:', result.insertId);
            
            // Generate JWT token
            const token = jwt.sign(
                { userId: result.insertId },
                process.env.JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            return res.status(201).json({
                success: true,
                message: "Initial admin account created successfully",
                userId: result.insertId,
                token
            });
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('SETUP error:', error);
        return res.status(500).json({
            success: false,
            message: "Admin setup failed",
            error: error.message
        });
    }
});

// Test endpoint: Test database connection
router.get('/test-db', async (req, res) => {
    console.log('TEST DB: Testing database connection');
    
    try {
        // Test direct database connection
        const connection = await pool.testDirectConnection();
        console.log('TEST DB: Connection test result:', connection);
        
        res.status(200).json({
            success: true,
            message: "Database connection test",
            result: connection ? "successful" : "failed"
        });
    } catch (error) {
        console.error('TEST DB: Database test error:', error);
        res.status(500).json({
            success: false,
            message: "Database connection test failed",
            error: error.message
        });
    }
});

// Test endpoint: Create user directly
router.post('/test-create-user', async (req, res) => {
    console.log('TEST CREATE USER: Request received');
    
    try {
        const testUser = {
            username: `test_${Date.now()}`,
            email: `test_${Date.now()}@example.com`,
            password: "Test123!"
        };
        
        console.log('TEST CREATE USER: Creating test user:', testUser.username);
        
        // Hash password
        const hashedPassword = await bcrypt.hash(testUser.password, 10);
        
        // Insert directly with MySQL2
        const mysql = require('mysql2/promise');
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST || 'localhost',
            user: process.env.DB_USER || 'root',
            password: process.env.DB_PASSWORD || 'mysql',
            database: process.env.DB_NAME || 'food_ecommerce'
        });
        
        const [result] = await connection.execute(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [testUser.username, testUser.email, hashedPassword]
        );
        
        await connection.end();
        
        console.log('TEST CREATE USER: User created successfully', result);
        
        res.status(201).json({
            success: true,
            message: "Test user created successfully",
            userId: result.insertId,
            username: testUser.username
        });
    } catch (error) {
        console.error('TEST CREATE USER: Error creating test user:', error);
        res.status(500).json({
            success: false,
            message: "Failed to create test user",
            error: error.message
        });
    }
});

// Admin creation route - requires super admin authorization
router.post('/create-admin', protect, async (req, res) => {
    try {
        // Check if the requesting user is a super admin
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can create new administrators"
            });
        }

        const { username, email, password } = req.body;

        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required"
            });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const connection = await pool.getConnection();
        try {
            // Create new admin user
            const [result] = await connection.execute(
                'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
                [username, email, hashedPassword, 'admin']
            );

            return res.status(201).json({
                success: true,
                message: "Admin user created successfully",
                userId: result.insertId
            });
        } finally {
            if (connection) connection.release();
        }
    } catch (error) {
        console.error('Create admin error:', error);
        return res.status(500).json({
            success: false,
            message: "Failed to create admin user",
            error: error.message
        });
    }
});

// Add this temporary route for testing
router.get('/list-admins', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const [admins] = await connection.execute(
            'SELECT username, email FROM users WHERE role = ?',
            ['admin']
        );
        
        res.json({
            success: true,
            admins: admins.map(admin => ({
                username: admin.username,
                email: admin.email
            }))
        });
    } finally {
        connection.release();
    }
});
// Add this temporary route for database migration
router.post('/migrate-admin', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        // First check if column exists
        const [columns] = await connection.execute(`
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = 'users' 
            AND COLUMN_NAME = 'is_super_admin'
        `);

        if (columns.length === 0) {
            // Add the column if it doesn't exist
            await connection.execute(`
                ALTER TABLE users
                ADD COLUMN is_super_admin BOOLEAN DEFAULT FALSE
            `);

            // Set existing admin as super_admin
            await connection.execute(`
                UPDATE users 
                SET is_super_admin = TRUE 
                WHERE username = 'admin' AND role = 'admin'
            `);
        }

        res.json({
            success: true,
            message: "Migration completed successfully"
        });
    } catch (error) {
        console.error('Migration error:', error);
        res.status(500).json({
            success: false,
            message: "Migration failed",
            error: error.message
        });
    } finally {
        connection.release();
    }
});
// Update admin status (super_admin only)
router.patch('/update-admin-status', protect, async (req, res) => {
    try {
        // Verify super admin status
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can update admin status"
            });
        }

        const { adminId, isActive } = req.body;

        const connection = await pool.getConnection();
        try {
            // Update admin status
            await connection.execute(
                'UPDATE users SET is_active = ? WHERE id = ? AND role = ?',
                [isActive, adminId, 'admin']
            );

            res.json({
                success: true,
                message: `Admin account ${isActive ? 'activated' : 'deactivated'} successfully`
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Admin status update error:', error);
        res.status(500).json({
            success: false,
            message: "Failed to update admin status",
            error: error.message
        });
    }
});

// Get detailed admin list (super_admin only)
router.get('/admin-details', protect, async (req, res) => {
    try {
        // Verify super admin status
        if (!req.user.is_super_admin) {
            return res.status(403).json({
                success: false,
                message: "Only super admins can view detailed admin information"
            });
        }

        const connection = await pool.getConnection();
        try {
            const [admins] = await connection.execute(
                'SELECT id, username, email, created_at, is_super_admin FROM users WHERE role = ?',
                ['admin']
            );

            res.json({
                success: true,
                admins: admins
            });
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Admin details fetch error:', error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch admin details",
            error: error.message
        });
    }
});

// Helper function to validate password complexity
const validatePasswordComplexity = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);
    
    const errors = [];
    
    if (password.length < minLength) {
        errors.push(`Password must be at least ${minLength} characters long`);
    }
    
    if (!hasUpperCase) {
        errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!hasLowerCase) {
        errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!hasNumbers) {
        errors.push('Password must contain at least one number');
    }
    
    if (!hasSpecialChar) {
        errors.push('Password must contain at least one special character');
    }
    
    return {
        isValid: errors.length === 0,
        errors
    };
};

// Helper function to send password reset notification email
const sendPasswordResetNotification = async (email, username, resetBy) => {
    try {
        // Create a transporter
        const transporter = nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: process.env.EMAIL_SECURE === 'true',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        // Setup email data
        const mailOptions = {
            from: `"Food E-commerce Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Your Admin Password Has Been Reset',
            html: `
                <h1>Password Reset Notification</h1>
                <p>Hello ${username},</p>
                <p>Your admin account password was reset by ${resetBy} on ${new Date().toLocaleString()}.</p>
                <p>If you did not authorize this change, please contact the super admin immediately.</p>
                <p>Regards,<br>Food E-commerce Security Team</p>
            `
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log(`Password reset notification sent to ${email}`);
        return true;
    } catch (error) {
        console.error('Failed to send password reset notification email:', error);
        return false;
    }
};

// Enhanced password reset route with security improvements
router.post('/admin/reset-password', protect, async (req, res) => {
    const connection = await pool.getConnection();
    
    try {
        const { username, newPassword, confirmPassword, confirmReset } = req.body;
        const resetRequestIP = req.ip || req.connection.remoteAddress;
        
        // Verify super admin status
        if (!req.user.is_super_admin) {
            // Log unauthorized attempt
            await connection.execute(
                'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
                [req.user.id, 'UNAUTHORIZED_RESET_ATTEMPT', `User attempted to reset password for ${username}`, resetRequestIP]
            );
            
            return res.status(403).json({
                success: false,
                message: "Only super admins can reset passwords"
            });
        }

        // Check if confirmation parameter is provided and valid
        if (!confirmReset || confirmReset !== 'CONFIRM') {
            return res.status(400).json({
                success: false,
                message: "Password reset requires explicit confirmation. Please provide 'CONFIRM' in the confirmReset field."
            });
        }
        
        // Confirm passwords match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                success: false,
                message: "New password and confirmation password do not match"
            });
        }

        // Validate password complexity
        const passwordValidation = validatePasswordComplexity(newPassword);
        if (!passwordValidation.isValid) {
            return res.status(400).json({
                success: false,
                message: "Password does not meet complexity requirements",
                errors: passwordValidation.errors
            });
        }

        // Check rate limits for password resets
        const [rateLimitCheck] = await connection.execute(
            'SELECT * FROM password_reset_attempts WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
            [username]
        );

        if (rateLimitCheck.length > 0 && rateLimitCheck[0].attempt_count >= 3) {
            // Log rate limit exceeded
            await connection.execute(
                'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
                [req.user.id, 'RATE_LIMIT_EXCEEDED', `Rate limit exceeded for password reset attempts on ${username}`, resetRequestIP]
            );
            
            return res.status(429).json({
                success: false,
                message: "Rate limit exceeded. Please try again later."
            });
        }

        // Get the target user's details and current password for history check
        const [userDetails] = await connection.execute(
            'SELECT id, email, password_hash FROM users WHERE username = ? AND role = ?',
            [username, 'admin']
        );

        if (userDetails.length === 0) {
            // Update rate limit tracking for non-existent users to prevent user enumeration
            if (rateLimitCheck.length === 0) {
                await connection.execute(
                    'INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)',
                    [username, req.user.id, resetRequestIP]
                );
            } else {
                await connection.execute(
                    'UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
                    [username]
                );
            }
            
            return res.status(404).json({
                success: false,
                message: "Admin user not found"
            });
        }

        const targetUserId = userDetails[0].id;
        const targetUserEmail = userDetails[0].email;
        const currentPasswordHash = userDetails[0].password_hash;
        
        // Check if new password matches the current password
        const isSameAsCurrent = await bcrypt.compare(newPassword, currentPasswordHash);
        if (isSameAsCurrent) {
            return res.status(400).json({
                success: false,
                message: "New password cannot be the same as the current password"
            });
        }

        // Check password history to prevent reuse
        const [passwordHistory] = await connection.execute(
            'SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 3',
            [targetUserId]
        );

        // Check against previous passwords
        for (const history of passwordHistory) {
            const isPasswordReused = await bcrypt.compare(newPassword, history.password_hash);
            if (isPasswordReused) {
                return res.status(400).json({
                    success: false,
                    message: "Cannot reuse recent passwords"
                });
            }
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Begin transaction to ensure data consistency
        await connection.beginTransaction();

        try {
            // Update the user's password
            await connection.execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                [hashedPassword, targetUserId]
            );

            // Store the old password in password history
            await connection.execute(
                'INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)',
                [targetUserId, currentPasswordHash]
            );

            // Reset password attempt counter or create new entry
            if (rateLimitCheck.length === 0) {
                await connection.execute(
                    'INSERT INTO password_reset_attempts (target_username, initiated_by, attempt_count, attempt_window_start, ip_address) VALUES (?, ?, 1, NOW(), ?)',
                    [username, req.user.id, resetRequestIP]
                );
            } else {
                await connection.execute(
                    'UPDATE password_reset_attempts SET attempt_count = attempt_count + 1, last_attempt_timestamp = NOW() WHERE target_username = ? AND attempt_window_start > DATE_SUB(NOW(), INTERVAL 1 HOUR)',
                    [username]
                );
            }

            // Log successful password reset
            await connection.execute(
                'INSERT INTO audit_log (user_id, event_type, event_description, ip_address) VALUES (?, ?, ?, ?)',
                [req.user.id, 'PASSWORD_RESET_SUCCESS', `Password reset for ${username} (ID: ${targetUserId})`, resetRequestIP]
            );

            // Commit the transaction
            await connection.commit();

            // Send notification email (after successful transaction)
            const emailSent = await sendPasswordResetNotification(
                targetUserEmail, 
                username, 
                req.user.username
            );

            return res.json({
                success: true,
                message: "Password reset successfully",
                emailSent: emailSent
            });
        } catch (error) {
            // Rollback if any error occurs
            await connection.rollback();
            throw error;
        }
    } catch (error) {
        console.error('Password reset error:', error);
        return res.status(500).json({
            success: false,
            message: "Failed to reset password",
            error: error.message
        });
    } finally {
        if (connection) connection.release();
    }
});

module.exports = router;
