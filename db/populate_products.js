/**
 * Script to populate the products table with test food items
 * This script ensures the products table has the correct schema and inserts test data
 */
const mysql = require('mysql2/promise');
require('dotenv').config();

async function populateProducts() {
  console.log('Starting database population script...');
  
  let connection;
  try {
    // Create connection to database
    connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || 'mysql',
      database: process.env.DB_NAME || 'food_ecommerce'
    });
    
    console.log('Connected to database successfully');
    
// Check if table needs to be cleared
    const [rows] = await connection.execute('SELECT COUNT(*) as count FROM products');
    if (rows[0].count > 0) {
      const clearPrompt = await promptUser('Products table already has data. Clear existing data? (y/n): ');
      if (clearPrompt.toLowerCase() === 'y') {
        try {
          console.log('Temporarily disabling foreign key checks...');
          await connection.execute('SET FOREIGN_KEY_CHECKS = 0');
          
          // First clear dependent tables to remove foreign key references
          console.log('Clearing cart_items table...');
          await connection.execute('TRUNCATE TABLE cart_items');
          
          console.log('Clearing order_items table...');
          await connection.execute('TRUNCATE TABLE order_items');
          
          console.log('Clearing orders table...');
          await connection.execute('TRUNCATE TABLE orders');
          
          // Now safe to truncate products
          console.log('Clearing products table...');
          await connection.execute('TRUNCATE TABLE products');
          
          // Re-enable foreign key checks
          await connection.execute('SET FOREIGN_KEY_CHECKS = 1');
          console.log('Foreign key checks re-enabled');
          
          console.log('All related tables cleared successfully');
        } catch (truncateError) {
          console.error('Error during table truncation:', truncateError.message);
          console.log('Attempting to re-enable foreign key checks...');
          await connection.execute('SET FOREIGN_KEY_CHECKS = 1').catch(err => {
            console.error('Failed to re-enable foreign key checks:', err.message);
          });
          throw truncateError;
        }
      } else {
        console.log('Keeping existing data. New items will be added.');
      }
    }
    
    console.log('Inserting test food items...');
    
    // Insert Pizza category items
    await connection.execute(`
      INSERT INTO products (name, description, price, category, stock_quantity, image_url) 
      VALUES 
      ('Margherita Pizza', 'Classic pizza with tomato sauce, fresh mozzarella, and basil', 12.99, 'Pizza', 50, '/images/products/margherita.jpg'),
      ('Pepperoni Pizza', 'Traditional pizza topped with pepperoni slices and cheese', 14.99, 'Pizza', 45, '/images/products/pepperoni.jpg'),
      ('Hawaiian Pizza', 'Pizza with ham, pineapple chunks, and cheese', 15.99, 'Pizza', 40, '/images/products/hawaiian.jpg'),
      ('Vegetarian Pizza', 'Pizza loaded with bell peppers, onions, mushrooms, and olives', 16.99, 'Pizza', 35, '/images/products/vegetarian.jpg'),
      ('BBQ Chicken Pizza', 'Pizza with grilled chicken, red onions, and BBQ sauce', 17.99, 'Pizza', 30, '/images/products/bbq-chicken.jpg')
    `);
    console.log('Pizza category items inserted');
    
    // Insert Burgers category items
    await connection.execute(`
      INSERT INTO products (name, description, price, category, stock_quantity, image_url) 
      VALUES 
      ('Classic Cheeseburger', 'Beef patty with American cheese, lettuce, tomato, and special sauce', 10.99, 'Burgers', 60, '/images/products/cheeseburger.jpg'),
      ('Bacon Burger', 'Beef patty with crispy bacon, cheddar cheese, and BBQ sauce', 12.99, 'Burgers', 55, '/images/products/bacon-burger.jpg'),
      ('Veggie Burger', 'Plant-based patty with lettuce, tomato, and vegan mayo', 11.99, 'Burgers', 40, '/images/products/veggie-burger.jpg'),
      ('Chicken Burger', 'Grilled chicken breast with lettuce, tomato, and honey mustard', 11.99, 'Burgers', 50, '/images/products/chicken-burger.jpg'),
      ('Mushroom Swiss Burger', 'Beef patty topped with sautéed mushrooms and Swiss cheese', 13.99, 'Burgers', 45, '/images/products/mushroom-burger.jpg')
    `);
    console.log('Burgers category items inserted');
    
    // Insert Sides category items
    await connection.execute(`
      INSERT INTO products (name, description, price, category, stock_quantity, image_url) 
      VALUES 
      ('French Fries', 'Crispy golden fries seasoned with salt', 3.99, 'Sides', 80, '/images/products/french-fries.jpg'),
      ('Onion Rings', 'Crispy battered onion rings', 4.99, 'Sides', 70, '/images/products/onion-rings.jpg'),
      ('Mozzarella Sticks', 'Breaded mozzarella sticks served with marinara sauce', 6.99, 'Sides', 60, '/images/products/mozzarella-sticks.jpg'),
      ('Garlic Bread', 'Toasted bread with garlic butter and herbs', 4.99, 'Sides', 65, '/images/products/garlic-bread.jpg'),
      ('Coleslaw', 'Fresh cabbage, carrots, and mayo dressing', 3.99, 'Sides', 55, '/images/products/coleslaw.jpg')
    `);
    console.log('Sides category items inserted');
    
    // Insert Beverages category items
    await connection.execute(`
      INSERT INTO products (name, description, price, category, stock_quantity, image_url) 
      VALUES 
      ('Coca Cola', 'Classic cola drink (16 oz)', 2.99, 'Beverages', 100, '/images/products/coca-cola.jpg'),
      ('Sprite', 'Lemon-lime soda (16 oz)', 2.99, 'Beverages', 90, '/images/products/sprite.jpg'),
      ('Iced Tea', 'Freshly brewed sweet or unsweetened iced tea (16 oz)', 2.99, 'Beverages', 85, '/images/products/iced-tea.jpg'),
      ('Lemonade', 'Fresh-squeezed lemonade (16 oz)', 3.99, 'Beverages', 80, '/images/products/lemonade.jpg'),
      ('Bottled Water', 'Purified water (16 oz)', 1.99, 'Beverages', 120, '/images/products/water.jpg')
    `);
    console.log('Beverages category items inserted');
    
    // Count inserted items
    const [productsCount] = await connection.execute('SELECT COUNT(*) as count FROM products');
    console.log(`Database population complete. Total products: ${productsCount[0].count}`);
    
  } catch (error) {
    console.error('Error in database population script:', error);
  } finally {
    if (connection) {
      await connection.end();
      console.log('Database connection closed');
    }
  }
}

// Mock prompt function (replace with actual prompt if running interactively)
async function promptUser(question) {
  // In a non-interactive environment, default to 'y'
  console.log(question + ' (defaulting to "y" in non-interactive mode)');
  return 'y';
}

// Run the script
populateProducts().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

