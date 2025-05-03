-- Drop existing database if it exists and create a new one
DROP DATABASE IF EXISTS food_ecommerce;
CREATE DATABASE food_ecommerce;
USE food_ecommerce;

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    is_super_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email)
);

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2) NOT NULL,
    category VARCHAR(50) NOT NULL,
    stock_quantity INT NOT NULL DEFAULT 0,
    image_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_name (name)
);

-- Orders table
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    total_amount DECIMAL(10, 2) NOT NULL,
    status ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
    shipping_address TEXT,
    phone_number VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_id (user_id),
    INDEX idx_status (status)
);

-- Order items table
CREATE TABLE order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    unit_price DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE RESTRICT,
    INDEX idx_order_id (order_id),
    INDEX idx_product_id (product_id)
);

-- Cart items table
CREATE TABLE cart_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_product (user_id, product_id),
    INDEX idx_user_id (user_id)
);
-- Add sample admin user (password: admin123)
INSERT INTO users (username, email, password_hash, role, is_super_admin) 
VALUES ('admin', 'admin@example.com', '$2b$10$1JG6hVjGvM2OHQqKsVpKZ.PDtZfzzR.JFWn7YjIawxND4FMX/Cv9O', 'admin', TRUE);

-- Add sample categories
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Burger and Fries', 'Classic burger with crispy fries', 12.99, 'Fast Food', 50, '/Assets/myImages/burgersAndFries.jpg'),
('Fried Chicken Wings', 'Crispy fried chicken wings', 10.99, 'Fast Food', 40, '/Assets/myImages/friedChickenWings.jpg'),
('Pizza', 'Delicious classic pizza with various toppings', 14.99, 'Fast Food', 30, '/Assets/myImages/pizza1.jpg'),
('Champagne', 'Premium sparkling wine', 29.99, 'Beverages', 20, '/Assets/myImages/champagne1.jpg'),
('Cake', 'Sweet dessert cake for celebrations', 24.99, 'Desserts', 15, '/Assets/myImages/cake1.jpg'),
('Vegetable Stir-fry', 'Healthy vegetable stir-fry with rice', 13.99, 'Healthy', 25, '/Assets/myImages/foodiesfeed.com_colorful-vegetable-stir-fry-with-rice.jpg');

