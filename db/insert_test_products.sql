-- Insert test food items for Pizza category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Margherita Pizza', 'Classic pizza with tomato sauce, fresh mozzarella, and basil', 12.99, 'Pizza', 50, '/images/products/margherita.jpg'),
('Pepperoni Pizza', 'Traditional pizza topped with pepperoni slices and cheese', 14.99, 'Pizza', 45, '/images/products/pepperoni.jpg'),
('Hawaiian Pizza', 'Pizza with ham, pineapple chunks, and cheese', 15.99, 'Pizza', 40, '/images/products/hawaiian.jpg'),
('Vegetarian Pizza', 'Pizza loaded with bell peppers, onions, mushrooms, and olives', 16.99, 'Pizza', 35, '/images/products/vegetarian.jpg'),
('BBQ Chicken Pizza', 'Pizza with grilled chicken, red onions, and BBQ sauce', 17.99, 'Pizza', 30, '/images/products/bbq-chicken.jpg');

-- Insert test food items for Burgers category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Classic Cheeseburger', 'Beef patty with American cheese, lettuce, tomato, and special sauce', 10.99, 'Burgers', 60, '/images/products/cheeseburger.jpg'),
('Bacon Burger', 'Beef patty with crispy bacon, cheddar cheese, and BBQ sauce', 12.99, 'Burgers', 55, '/images/products/bacon-burger.jpg'),
('Veggie Burger', 'Plant-based patty with lettuce, tomato, and vegan mayo', 11.99, 'Burgers', 40, '/images/products/veggie-burger.jpg'),
('Chicken Burger', 'Grilled chicken breast with lettuce, tomato, and honey mustard', 11.99, 'Burgers', 50, '/images/products/chicken-burger.jpg'),
('Mushroom Swiss Burger', 'Beef patty topped with sautéed mushrooms and Swiss cheese', 13.99, 'Burgers', 45, '/images/products/mushroom-burger.jpg');

-- Insert test food items for Sides category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('French Fries', 'Crispy golden fries seasoned with salt', 3.99, 'Sides', 80, '/images/products/french-fries.jpg'),
('Onion Rings', 'Crispy battered onion rings', 4.99, 'Sides', 70, '/images/products/onion-rings.jpg'),
('Mozzarella Sticks', 'Breaded mozzarella sticks served with marinara sauce', 6.99, 'Sides', 60, '/images/products/mozzarella-sticks.jpg'),
('Garlic Bread', 'Toasted bread with garlic butter and herbs', 4.99, 'Sides', 65, '/images/products/garlic-bread.jpg'),
('Coleslaw', 'Fresh cabbage, carrots, and mayo dressing', 3.99, 'Sides', 55, '/images/products/coleslaw.jpg');

-- Insert test food items for Salads category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Caesar Salad', 'Romaine lettuce, croutons, parmesan cheese with Caesar dressing', 8.99, 'Salads', 40, '/images/products/caesar-salad.jpg'),
('Greek Salad', 'Cucumbers, tomatoes, onions, feta cheese, and olives with olive oil', 9.99, 'Salads', 35, '/images/products/greek-salad.jpg'),
('Chicken Salad', 'Mixed greens, grilled chicken, avocado, and honey mustard dressing', 11.99, 'Salads', 30, '/images/products/chicken-salad.jpg'),
('Caprese Salad', 'Fresh mozzarella, tomatoes, and basil with balsamic glaze', 10.99, 'Salads', 25, '/images/products/caprese-salad.jpg'),
('Cobb Salad', 'Lettuce, chicken, bacon, avocado, eggs, and blue cheese dressing', 12.99, 'Salads', 20, '/images/products/cobb-salad.jpg');

-- Insert test food items for Desserts category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Chocolate Cake', 'Rich chocolate layer cake with fudge frosting', 6.99, 'Desserts', 25, '/images/products/chocolate-cake.jpg'),
('Cheesecake', 'Creamy New York style cheesecake', 7.99, 'Desserts', 20, '/images/products/cheesecake.jpg'),
('Apple Pie', 'Traditional apple pie with cinnamon and flaky crust', 6.99, 'Desserts', 15, '/images/products/apple-pie.jpg'),
('Ice Cream', 'Three scoops of vanilla, chocolate, and strawberry ice cream', 5.99, 'Desserts', 30, '/images/products/ice-cream.jpg'),
('Tiramisu', 'Classic Italian dessert with coffee-soaked ladyfingers and mascarpone', 8.99, 'Desserts', 15, '/images/products/tiramisu.jpg');

-- Insert test food items for Beverages category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Coca Cola', 'Classic cola drink (16 oz)', 2.99, 'Beverages', 100, '/images/products/coca-cola.jpg'),
('Sprite', 'Lemon-lime soda (16 oz)', 2.99, 'Beverages', 90, '/images/products/sprite.jpg'),
('Iced Tea', 'Freshly brewed sweet or unsweetened iced tea (16 oz)', 2.99, 'Beverages', 85, '/images/products/iced-tea.jpg'),
('Lemonade', 'Fresh-squeezed lemonade (16 oz)', 3.99, 'Beverages', 80, '/images/products/lemonade.jpg'),
('Bottled Water', 'Purified water (16 oz)', 1.99, 'Beverages', 120, '/images/products/water.jpg');

-- Insert test food items for Combo Meals category
INSERT INTO products (name, description, price, category, stock_quantity, image_url) VALUES
('Burger Combo', 'Cheeseburger with fries and a drink', 15.99, 'Combo Meals', 50, '/images/products/burger-combo.jpg'),
('Pizza Meal', 'Two slices of pizza with a side salad and a drink', 16.99, 'Combo Meals', 45, '/images/products/pizza-meal.jpg'),
('Family Feast', 'Large pizza, 4 sides, and 4 drinks', 39.99, 'Combo Meals', 30, '/images/products/family-feast.jpg'),
('Kids Meal', 'Small burger, small fries, small drink, and a dessert', 9.99, 'Combo Meals', 40, '/images/products/kids-meal.jpg'),
('Salad Combo', 'Any salad with garlic bread and a drink', 14.99, 'Combo Meals', 35, '/images/products/salad-combo.jpg');

