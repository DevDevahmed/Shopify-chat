// MongoDB Atlas Configuration for Production
const mongoose = require('mongoose');

const connectMongoDB = async () => {
  try {
    // MongoDB Atlas connection string (from environment variables)
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/vendor_chat_system';
    
    await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10, // Maintain up to 10 socket connections
      serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
      bufferMaxEntries: 0, // Disable mongoose buffering
      bufferCommands: false, // Disable mongoose buffering
    });
    
    console.log('✅ MongoDB Atlas connected successfully');
    console.log(`📍 Database: ${mongoose.connection.name}`);
    
    // Handle connection events for production monitoring
    mongoose.connection.on('error', (err) => {
      console.error('❌ MongoDB connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️ MongoDB disconnected');
    });
    
    mongoose.connection.on('reconnected', () => {
      console.log('🔄 MongoDB reconnected');
    });
    
    // Graceful shutdown
    process.on('SIGINT', async () => {
      await mongoose.connection.close();
      console.log('MongoDB connection closed through app termination');
      process.exit(0);
    });
    
  } catch (error) {
    console.error('❌ MongoDB Atlas connection failed:', error);
    process.exit(1);
  }
};

// MySQL Configuration (Alternative - not needed for Atlas)
const mysql = require('mysql2/promise');

const createMySQLConnection = async () => {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'vendor_chat_system',
      charset: 'utf8mb4'
    });
    console.log('✅ MySQL connected successfully');
    return connection;
  } catch (error) {
    console.error('❌ MySQL connection failed:', error);
    process.exit(1);
  }
};

module.exports = {
  connectMongoDB,
  createMySQLConnection
};
