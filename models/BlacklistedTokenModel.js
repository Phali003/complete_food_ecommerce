const { pool } = require('../config/database');

/**
 * BlacklistedToken Model - Handles storage and verification of invalidated tokens
 */
class BlacklistedTokenModel {
  /**
   * Add a token to the blacklist
   * @param {String} token - JWT token to blacklist
   * @param {Number} userId - ID of the user associated with the token
   * @returns {Promise} Query result
   */
  static async blacklistToken(token, userId) {
    const [result] = await pool.execute(`
      INSERT INTO blacklisted_tokens (token, user_id, blacklisted_at)
      VALUES (?, ?, NOW())
    `, [token, userId]);
    return result;
  }

  /**
   * Check if a token is blacklisted
   * @param {String} token - JWT token to check
   * @returns {Boolean} True if token is blacklisted
   */
  static async isBlacklisted(token) {
    const [result] = await pool.execute(`
      SELECT COUNT(*) as count 
      FROM blacklisted_tokens 
      WHERE token = ? AND blacklisted_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `, [token]);
    return result[0].count > 0;
  }

  /**
   * Clean up old blacklisted tokens (maintenance function)
   * @returns {Promise} Query result
   */
  static async cleanupOldTokens() {
    const [result] = await pool.execute(`
      DELETE FROM blacklisted_tokens
      WHERE blacklisted_at <= DATE_SUB(NOW(), INTERVAL 24 HOUR)
    `);
    return result;
  }
}

module.exports = BlacklistedTokenModel;

