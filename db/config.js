const mongoose = require('mongoose');
require('dotenv').config();

// MongoDB connection URI - use environment variable or default to localhost
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/foodEcommerce';

// MongoDB connection options
const options = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  // Removed legacy options, these are default in newer MongoDB/Mongoose versions:
  // useCreateIndex: true,
  // useFindAndModify: false
};

// Connect to MongoDB
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGODB_URI, options);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
    return conn;
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error.message}`);
    // Return the error so it can be handled by the caller
    throw error;
  }
};

// Close MongoDB connection
const closeDB = async () => {
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  } catch (error) {
    console.error(`Error closing MongoDB connection: ${error.message}`);
    throw error;
  }
};

// Database connection state helper
const isConnected = () => {
  return mongoose.connection.readyState === 1; // 1 = connected
};

module.exports = {
  connectDB,
  closeDB,
  isConnected
};

