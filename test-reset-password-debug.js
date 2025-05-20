// test-reset-password-debug.js
require("dotenv").config();
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

async function testResetPassword() {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });

  try {
    const token = "2de7515561ef22a34b7f850611b07bb781d15bd1";
    const password = "NewPassword123!";

    console.log("Testing reset password...");
    console.log("Token:", token);

    // Find user with valid reset token
    console.log("\nFinding user with token...");
    const [rows] = await pool.execute(
      "SELECT id, email, username FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()",
      [token]
    );

    console.log("Database query result:", rows);

    if (!rows || rows.length === 0) {
      console.log("No user found with valid token");
      return;
    }

    const user = rows[0];
    console.log("\nUser found:", {
      id: user.id,
      email: user.email,
      username: user.username,
    });

    // Hash new password
    console.log("\nHashing password...");
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Update password and clear reset token
    console.log("\nUpdating password...");
    await pool.execute(
      "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
      [hashedPassword, user.id]
    );

    // Store in password history
    console.log("\nStoring in password history...");
    await pool.execute(
      "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
      [user.id, hashedPassword]
    );

    // Verify changes
    console.log("\nVerifying changes...");
    const [verifyResult] = await pool.execute(
      "SELECT reset_token, reset_token_expiry FROM users WHERE id = ?",
      [user.id]
    );
    console.log("Verification result:", verifyResult[0]);

    console.log("\nPassword reset completed successfully");
  } catch (error) {
    console.error("Error during password reset:", error);
  } finally {
    await pool.end();
  }
}

// Run the test
console.log("Starting reset password test...");
testResetPassword().catch(console.error);
