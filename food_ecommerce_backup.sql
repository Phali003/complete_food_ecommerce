-- MySQL dump 10.13  Distrib 9.3.0, for Win64 (x86_64)
--
-- Host: localhost    Database: food_ecommerce
-- ------------------------------------------------------
-- Server version	8.0.41

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `audit_log`
--

DROP TABLE IF EXISTS `audit_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `audit_log` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int DEFAULT NULL,
  `event_type` varchar(50) NOT NULL,
  `event_description` text,
  `ip_address` varchar(45) DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_event_type` (`event_type`),
  KEY `idx_timestamp` (`timestamp`),
  CONSTRAINT `audit_log_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Security audit log for tracking security-related events';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `audit_log`
--

LOCK TABLES `audit_log` WRITE;
/*!40000 ALTER TABLE `audit_log` DISABLE KEYS */;
INSERT INTO `audit_log` VALUES (1,NULL,'login_failed','Failed login attempt: invalid password','::1','2025-04-26 09:58:34'),(2,NULL,'login_failed','Failed login attempt: invalid password','::1','2025-04-26 09:58:48'),(3,NULL,'login_success','Successful login','::1','2025-04-26 09:59:20'),(4,NULL,'login_failed','Failed login attempt: invalid password','::1','2025-04-26 10:01:43'),(5,NULL,'login_success','Successful login','::1','2025-04-26 10:02:08'),(6,NULL,'login_success','Successful login','::1','2025-04-26 10:02:31'),(7,NULL,'login_success','Successful login','::1','2025-04-26 10:04:02'),(8,NULL,'login_success','Successful login','::1','2025-04-26 10:04:20'),(9,NULL,'login_success','Successful login','::1','2025-04-26 10:04:37'),(10,NULL,'SCHEMA_MIGRATION','Removed password reset tables and columns',NULL,'2025-05-15 05:40:45'),(11,NULL,'SCHEMA_MIGRATION','Added password reset tables and columns',NULL,'2025-05-15 05:45:08'),(12,NULL,'SCHEMA_MIGRATION','Created password reset attempts table',NULL,'2025-05-15 05:54:31');
/*!40000 ALTER TABLE `audit_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `blacklisted_tokens`
--

DROP TABLE IF EXISTS `blacklisted_tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `blacklisted_tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `user_id` int NOT NULL,
  `blacklisted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `idx_token` (`token`(255)),
  KEY `idx_blacklisted_at` (`blacklisted_at`),
  CONSTRAINT `blacklisted_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `blacklisted_tokens`
--

LOCK TABLES `blacklisted_tokens` WRITE;
/*!40000 ALTER TABLE `blacklisted_tokens` DISABLE KEYS */;
/*!40000 ALTER TABLE `blacklisted_tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `cart_items`
--

DROP TABLE IF EXISTS `cart_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `cart_items` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `product_id` int NOT NULL,
  `quantity` int NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_user_product` (`user_id`,`product_id`),
  KEY `product_id` (`product_id`),
  KEY `idx_user_id` (`user_id`),
  CONSTRAINT `cart_items_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `cart_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `cart_items`
--

LOCK TABLES `cart_items` WRITE;
/*!40000 ALTER TABLE `cart_items` DISABLE KEYS */;
/*!40000 ALTER TABLE `cart_items` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `order_items`
--

DROP TABLE IF EXISTS `order_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `order_items` (
  `id` int NOT NULL AUTO_INCREMENT,
  `order_id` int NOT NULL,
  `product_id` int NOT NULL,
  `quantity` int NOT NULL,
  `unit_price` decimal(10,2) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_order_id` (`order_id`),
  KEY `idx_product_id` (`product_id`),
  CONSTRAINT `order_items_ibfk_1` FOREIGN KEY (`order_id`) REFERENCES `orders` (`id`) ON DELETE CASCADE,
  CONSTRAINT `order_items_ibfk_2` FOREIGN KEY (`product_id`) REFERENCES `products` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `order_items`
--

LOCK TABLES `order_items` WRITE;
/*!40000 ALTER TABLE `order_items` DISABLE KEYS */;
/*!40000 ALTER TABLE `order_items` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `orders`
--

DROP TABLE IF EXISTS `orders`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `orders` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `total_amount` decimal(10,2) NOT NULL,
  `status` enum('pending','processing','shipped','delivered','cancelled') DEFAULT 'pending',
  `shipping_address` text,
  `phone_number` varchar(20) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  KEY `idx_status` (`status`),
  CONSTRAINT `orders_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `orders`
--

LOCK TABLES `orders` WRITE;
/*!40000 ALTER TABLE `orders` DISABLE KEYS */;
/*!40000 ALTER TABLE `orders` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `password_history`
--

DROP TABLE IF EXISTS `password_history`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_history` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`),
  CONSTRAINT `password_history_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='Stores password history to prevent reuse of recent passwords';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `password_history`
--

LOCK TABLES `password_history` WRITE;
/*!40000 ALTER TABLE `password_history` DISABLE KEYS */;
/*!40000 ALTER TABLE `password_history` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `password_reset_attempts`
--

DROP TABLE IF EXISTS `password_reset_attempts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `password_reset_attempts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `attempt_count` int DEFAULT '1',
  `first_attempt` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `last_attempt` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `ip_address` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_email_attempt` (`email`,`last_attempt`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `password_reset_attempts`
--

LOCK TABLES `password_reset_attempts` WRITE;
/*!40000 ALTER TABLE `password_reset_attempts` DISABLE KEYS */;
INSERT INTO `password_reset_attempts` VALUES (1,'priscphalis@gmail.com',1,'2025-05-15 05:59:28','2025-05-15 05:59:28','::1'),(2,'USMN33746819@portal.textingfactory.com',1,'2025-05-15 09:19:54','2025-05-15 09:19:54','::1'),(3,'newstudent@test.com',1,'2025-05-15 09:45:10','2025-05-15 09:45:10','::1'),(4,'peter@gmail.com',1,'2025-05-15 09:45:21','2025-05-15 09:45:21','::1'),(5,'priscphalis@gmail.com',1,'2025-05-15 09:45:39','2025-05-15 09:45:39','::1'),(6,'newstudent@test.com',1,'2025-05-15 09:56:23','2025-05-15 09:56:23','::1'),(7,'priscphalis@test.com',1,'2025-05-15 09:56:40','2025-05-15 09:56:40','::1'),(8,'newstudent@test.com',1,'2025-05-15 10:04:57','2025-05-15 10:04:57','::1'),(9,'GBCHN3899251@portal.chat-from-home.com',1,'2025-05-15 10:07:48','2025-05-15 10:07:48','::1'),(10,'pejter@gmail.com',1,'2025-05-15 10:27:38','2025-05-15 10:27:38','::1');
/*!40000 ALTER TABLE `password_reset_attempts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `products`
--

DROP TABLE IF EXISTS `products`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `products` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `description` text,
  `price` decimal(10,2) NOT NULL,
  `category` varchar(50) NOT NULL,
  `stock_quantity` int NOT NULL DEFAULT '0',
  `image_url` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_category` (`category`),
  KEY `idx_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `products`
--

LOCK TABLES `products` WRITE;
/*!40000 ALTER TABLE `products` DISABLE KEYS */;
INSERT INTO `products` VALUES (1,'Margherita Pizza','Classic pizza with tomato sauce, fresh mozzarella, and basil',12.99,'Pizza',50,'/images/products/margherita.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(2,'Pepperoni Pizza','Traditional pizza topped with pepperoni slices and cheese',14.99,'Pizza',45,'/images/products/pepperoni.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(3,'Hawaiian Pizza','Pizza with ham, pineapple chunks, and cheese',15.99,'Pizza',40,'/images/products/hawaiian.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(4,'Vegetarian Pizza','Pizza loaded with bell peppers, onions, mushrooms, and olives',16.99,'Pizza',35,'/images/products/vegetarian.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(5,'BBQ Chicken Pizza','Pizza with grilled chicken, red onions, and BBQ sauce',17.99,'Pizza',30,'/images/products/bbq-chicken.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(6,'Classic Cheeseburger','Beef patty with American cheese, lettuce, tomato, and special sauce',10.99,'Burgers',60,'/images/products/cheeseburger.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(7,'Bacon Burger','Beef patty with crispy bacon, cheddar cheese, and BBQ sauce',12.99,'Burgers',55,'/images/products/bacon-burger.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(8,'Veggie Burger','Plant-based patty with lettuce, tomato, and vegan mayo',11.99,'Burgers',40,'/images/products/veggie-burger.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(9,'Chicken Burger','Grilled chicken breast with lettuce, tomato, and honey mustard',11.99,'Burgers',50,'/images/products/chicken-burger.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(10,'Mushroom Swiss Burger','Beef patty topped with saut├®ed mushrooms and Swiss cheese',13.99,'Burgers',45,'/images/products/mushroom-burger.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(11,'French Fries','Crispy golden fries seasoned with salt',3.99,'Sides',80,'/images/products/french-fries.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(12,'Onion Rings','Crispy battered onion rings',4.99,'Sides',70,'/images/products/onion-rings.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(13,'Mozzarella Sticks','Breaded mozzarella sticks served with marinara sauce',6.99,'Sides',60,'/images/products/mozzarella-sticks.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(14,'Garlic Bread','Toasted bread with garlic butter and herbs',4.99,'Sides',65,'/images/products/garlic-bread.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(15,'Coleslaw','Fresh cabbage, carrots, and mayo dressing',3.99,'Sides',55,'/images/products/coleslaw.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(16,'Coca Cola','Classic cola drink (16 oz)',2.99,'Beverages',100,'/images/products/coca-cola.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(17,'Sprite','Lemon-lime soda (16 oz)',2.99,'Beverages',90,'/images/products/sprite.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(18,'Iced Tea','Freshly brewed sweet or unsweetened iced tea (16 oz)',2.99,'Beverages',85,'/images/products/iced-tea.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(19,'Lemonade','Fresh-squeezed lemonade (16 oz)',3.99,'Beverages',80,'/images/products/lemonade.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02'),(20,'Bottled Water','Purified water (16 oz)',1.99,'Beverages',120,'/images/products/water.jpg','2025-04-26 08:16:02','2025-04-26 08:16:02');
/*!40000 ALTER TABLE `products` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` enum('user','admin') DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `is_super_admin` tinyint(1) DEFAULT '0',
  `reset_token` varchar(255) DEFAULT NULL,
  `reset_token_expiry` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`),
  KEY `idx_email` (`email`),
  KEY `idx_username_ci` (`username`),
  KEY `idx_email_ci` (`email`),
  KEY `idx_reset_token` (`reset_token`)
) ENGINE=InnoDB AUTO_INCREMENT=50 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-05-18 12:00:21
