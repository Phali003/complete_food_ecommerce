const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

// Strong test password that meets complexity requirements
const TEST_PASSWORD = "TestPass123!";

async function testUserFlow() {
  let connection;
  try {
    // 1. Initialize connection using .env credentials
    connection = await mysql.createConnection({
      host: "localhost",
      user: "root",
      password: "mysql",
      database: "food_ecommerce"
    });

    // 2. Simulate user registration
    // Hash the password properly using bcrypt
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(TEST_PASSWORD, salt);
    console.log('Password hashed successfully');
    
    const [users] = await connection.execute(
      `INSERT INTO users (username, email, password_hash) 
       VALUES ('test_user', 'test_user@example.com', ?)`,
      [hashedPassword]
    );
    console.log('✅ User registration successful - ID:', users.insertId);

    // 3. Simulate product selection
    const [products] = await connection.execute(
      `SELECT id, price FROM products WHERE name = 'Classic Cheeseburger'`
    );
    const productId = products[0].id;
    const productPrice = products[0].price;
    console.log('🛒 Selected product ID:', productId, 'Price:', productPrice);

    // 4. Simulate add to cart
    const [cartResult] = await connection.execute(
      `INSERT INTO cart_items (user_id, product_id, quantity)
       VALUES (?, ?, 1)`,
      [users.insertId, productId]
    );
    console.log('📦 Cart updated - Rows affected:', cartResult.affectedRows);

    // 5. Simulate order placement
    await connection.beginTransaction();
    try {
      // Create order
      const [orderResult] = await connection.execute(
        `INSERT INTO orders (user_id, total_amount)
         VALUES (?, ?)`,
        [users.insertId, productPrice]
      );

      // Add order items
      await connection.execute(
        `INSERT INTO order_items (order_id, product_id, quantity, unit_price)
         VALUES (?, ?, 1, ?)`,
        [orderResult.insertId, productId, productPrice]
      );

      await connection.commit();
      console.log('💰 Order successfully placed - ID:', orderResult.insertId);
    } catch (orderError) {
      await connection.rollback();
      throw orderError;
    }

    // 6. Verify database state
    const [finalOrder] = await connection.execute(
      `SELECT o.id, COUNT(oi.id) AS items 
       FROM orders o
       JOIN order_items oi ON o.id = oi.order_id
       WHERE o.user_id = ?
       GROUP BY o.id`,
      [users.insertId]
    );
    
    console.log('🔍 Verification:');
    console.log('- Orders created:', finalOrder.length);
    console.log('- Items per order:', finalOrder[0].items);

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    // Cleanup test data
    if(connection) {
      await connection.execute(`DELETE FROM users WHERE username = 'test_user'`);
      await connection.end();
    }
  }
}

// Run the full test sequence
testUserFlow();

// Export the test password for use in test-login.js
module.exports = { TEST_PASSWORD };
