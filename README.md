# Fresh Eats Market Online

![Fresh Eats Market Logo](./public/assets/myImages/fork.png)

## 🛒 Overview

Fresh Eats Market Online is a dynamic e-commerce platform dedicated to bringing the freshest and highest quality groceries directly to your doorstep. This full-featured online grocery store combines a user-friendly interface with robust backend services to provide an exceptional shopping experience.

## ✨ Features

- **User Authentication & Authorization**

  - Secure signup/login system
  - Role-based access control (customer, admin)
  - Password reset functionality
  - JWT-based authentication

- **Product Management**

  - Comprehensive product catalog with categories
  - High-quality product images and detailed descriptions
  - Inventory management system
  - Product search and filtering options

- **Shopping Experience**

  - Intuitive shopping cart functionality
  - Wishlist for saving favorite items
  - Personalized recommendations
  - Real-time product availability

- **Order Processing**

  - Secure checkout process
  - Multiple payment method integration
  - Order history and tracking
  - Order confirmation emails

- **Admin Dashboard**

  - Comprehensive sales analytics
  - Inventory management
  - Customer management
  - Order processing tools

- **Security Features**
  - CSRF protection
  - Rate limiting
  - Input validation and sanitization
  - Secure password storage with bcrypt

## 🛠️ Technology Stack

- **Frontend**

  - HTML5, CSS3, JavaScript
  - EJS templating engine
  - Responsive design

- **Backend**

  - Node.js
  - Express.js
  - MySQL database
  - RESTful API architecture

- **Authentication & Security**

  - JSON Web Tokens (JWT)
  - bcrypt for password hashing
  - Helmet for security headers
  - express-rate-limit for rate limiting

- **Additional Tools**
  - Nodemailer for email functionality
  - Joi for data validation
  - dotenv for environment variables
  - MySQL2 for database connectivity

## 📂 Project Structure

```
Fresh-Eats-Market/
├── api/                  # API routes and controllers
├── config/               # Configuration files
├── controllers/          # Request handlers
├── db/                   # Database migrations and seeds
├── docs/                 # Documentation files
├── middleware/           # Express middleware
├── models/               # Database models
├── public/               # Static assets (CSS, JS, images)
├── routes/               # Express routes
├── scripts/              # Utility scripts
├── utils/                # Helper functions
├── views/                # EJS templates
├── .env                  # Environment variables
├── package.json          # Project dependencies
├── server.js             # Application entry point
└── README.md             # Project documentation
```

## 🚀 Installation & Setup

### Prerequisites

- Node.js (v14.x or higher)
- MySQL (v8.x or higher)

### Installation Steps

1. **Clone the repository**

   ```bash
   git clone https://github.com/Phali003/complete_food_ecommerce.git
   cd complete_food_ecommerce
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Configure environment variables**

   - Rename `.env.example` to `.env`
   - Update database credentials and other settings

4. **Set up the database**

   ```bash
   npm run setup-db
   ```

5. **Start the application**

   ```bash
   # Development mode
   npm run dev

   # Production mode
   npm start
   ```

6. **Access the application**
   - Open your browser and navigate to `http://localhost:3000`

## 📝 Usage

### Customer Features

1. Browse products by categories
2. Add items to cart
3. Create and manage your account
4. Place and track orders
5. Save favorite products to wishlist

### Admin Features

1. Manage products (add, edit, remove)
2. Process customer orders
3. View sales reports and analytics
4. Manage user accounts

## 🔧 Scripts & Commands

- `npm start`: Start the application in production mode
- `npm run dev`: Start the application with nodemon (development mode)
- `npm run check-db`: Verify database connection
- `npm run setup-db`: Initialize database with tables and seed data
- `npm run fix-css`: Fix CSS issues in the project
- `npm run minify-css`: Minify CSS files for production
- `npm run verify-css`: Verify the integrity of CSS files
- `npm run cleanup`: Clean up unused CSS files
- `npm run verify-project`: Run comprehensive project verification

## 🔒 Security

Fresh Eats Market implements several security measures:

- **Data Protection**

  - Secure password hashing with bcrypt
  - HTTPS for all communications
  - Input validation to prevent injection attacks

- **Authentication & Authorization**

  - JWT-based authentication with token expiration
  - Role-based access control
  - CSRF protection for forms

- **API Security**
  - Rate limiting to prevent abuse
  - Secure HTTP headers with Helmet
  - Proper error handling to prevent information leakage

## 👥 Contributing

We welcome contributions to improve Fresh Eats Market! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the ISC License - see the LICENSE file for details.

---

&copy; 2025 Fresh Eats Market Online. All rights reserved.
