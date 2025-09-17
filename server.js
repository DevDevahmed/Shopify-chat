require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const crypto = require('crypto');
const axios = require('axios');

// Import Models
const Vendor = require('./models/Vendor');

const app = express();

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB Atlas successfully');
    console.log('🔗 Database: vendor_chat_system');
  })
  .catch((error) => {
    console.error('❌ MongoDB connection failed:', error.message);
    process.exit(1);
  });

// CORS configuration - Allow all Vercel apps and development
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Allow localhost for development
    if (origin.includes('localhost')) return callback(null, true);
    
    // Allow all Vercel apps
    if (origin.includes('.vercel.app')) return callback(null, true);
    
    // Allow all Netlify apps
    if (origin.includes('.netlify.app')) return callback(null, true);
    
    // Allow specific domains
    const allowedOrigins = [
      'https://front-shopmariem.vercel.app',
      'https://shopify-chat-mariem.vercel.app',
      'https://shop-vqgi.vercel.app',
      'https://shop-e2dx.vercel.app', // Your new frontend URL
    ];
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // Default allow for development
    callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With',
    'Accept',
    'Origin',
    'Access-Control-Request-Method',
    'Access-Control-Request-Headers'
  ],
  exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar'],
  preflightContinue: false,
  optionsSuccessStatus: 200
}));

app.use(express.json());

// Handle preflight requests for all routes
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept, Origin');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.sendStatus(200);
});

// CometChat REST API configuration
const COMETCHAT_API_BASE = `https://api-${process.env.COMETCHAT_REGION}.cometchat.io/v3.0`;

// Helper function to make CometChat API calls
async function cometChatAPI(endpoint, method = 'GET', data = null) {
  try {
    const config = {
      method,
      url: `${COMETCHAT_API_BASE}${endpoint}`,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'appId': process.env.COMETCHAT_APP_ID,
        'apiKey': process.env.COMETCHAT_AUTH_KEY
      }
    };
    if (data) {
      config.data = data;
    }
    console.log(`CometChat API Call: ${method} ${config.url}`);
    const response = await axios(config);
    console.log(`CometChat API Success: ${response.status}`);
    return response.data;
  } catch (error) {
    console.error('CometChat API Error Details:');
    console.error('- URL:', `${COMETCHAT_API_BASE}${endpoint}`);
    console.error('- Method:', method);
    console.error('- Status:', error.response?.status);
    console.error('- Response:', error.response?.data);
    console.error('- Message:', error.message);
    throw error;
  }
}

// CometChat registration function
async function registerVendorInCometChat(vendorData) {
  try {
    console.log(`🔄 Registering vendor in CometChat: ${vendorData.uid}`);
    
    const response = await axios.post(`https://api-${process.env.COMETCHAT_REGION}.cometchat.io/v3/users`, {
      uid: vendorData.uid,
      name: vendorData.name,
      email: vendorData.email,
      metadata: {
        department: vendorData.department,
        companyName: vendorData.companyName,
        phone: vendorData.phone || '',
        bio: vendorData.bio || '',
        role: 'vendor'
      }
    }, {
      headers: {
        'Content-Type': 'application/json',
        'apikey': process.env.COMETCHAT_AUTH_KEY
      }
    });

    console.log(`✅ CometChat registration successful for: ${vendorData.uid}`);
    return { 
      success: true, 
      data: response.data,
      message: 'Vendor registered in CometChat successfully'
    };
    
  } catch (error) {
    console.error(`❌ CometChat registration failed for ${vendorData.uid}:`, error.response?.data || error.message);
    
    // Check if user already exists (409 conflict)
    if (error.response?.status === 409) {
      console.log(`ℹ️ Vendor ${vendorData.uid} already exists in CometChat`);
      return { 
        success: true, 
        data: { uid: vendorData.uid },
        message: 'Vendor already exists in CometChat'
      };
    }
    
    return { 
      success: false, 
      error: error.response?.data?.error?.message || error.message 
    };
  }
}

// Admin Schema (Simple in-memory for now)
const Admin = mongoose.model('Admin', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'admin' },
  createdAt: { type: Date, default: Date.now }
}));

// Create default admin if not exists
async function createDefaultAdmin() {
  try {
    const adminEmail = 'admin@shopify-vendor.com';
    const adminPassword = 'admin123';
    
    const adminExists = await Admin.findOne({ email: adminEmail });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const newAdmin = await Admin.create({
        email: adminEmail,
        password: hashedPassword,
        role: 'super_admin'
      });
      console.log('✅ Default admin created successfully:', adminEmail);
      console.log('🔑 Admin ID:', newAdmin._id);
    } else {
      console.log('ℹ️ Default admin already exists:', adminEmail);
    }
  } catch (error) {
    console.error('❌ Error creating default admin:', error);
    console.error('Error details:', error.message);
  }
}

// Initialize default admin
createDefaultAdmin();

// ==================== VENDOR REGISTRATION ENDPOINTS ====================

// Vendor Registration
app.post('/api/vendors/register', async (req, res) => {
  try {
    const { businessName, contactName, email, phone, businessType, description, website, address } = req.body;
    
    // Check if email already exists
    const existingVendor = await Vendor.findOne({ email });
    if (existingVendor) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered. Please use a different email or contact support.'
      });
    }
    
    // Generate vendor UID
    const vendorId = `vendor_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const registrationId = crypto.randomUUID();
    
    // Create new vendor with pending status
    const vendor = new Vendor({
      vendorId,
      email,
      firstName: contactName.split(' ')[0] || contactName,
      lastName: contactName.split(' ').slice(1).join(' ') || '',
      phone,
      companyName: businessName,
      department: businessType,
      businessType: 'company',
      password: await bcrypt.hash('vendor123', 10), // Default password
      internalVendorId: registrationId,
      bio: description,
      status: 'pending',
      businessAddress: {
        street: address,
        city: '',
        state: '',
        country: '',
        zipCode: ''
      },
      vendorProfile: {
        storeUrl: website || ''
      }
    });
    
    await vendor.save();
    
    console.log(`✅ New vendor registration: ${businessName} (${email})`);
    
    res.json({
      success: true,
      message: 'Registration submitted successfully. Please wait for admin approval.',
      registrationId: vendor.internalVendorId
    });
    
  } catch (error) {
    console.error('❌ Vendor registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  }
});

// Check Registration Status
app.get('/api/vendors/status/:registrationId', async (req, res) => {
  try {
    const { registrationId } = req.params;
    
    const vendor = await Vendor.findOne({ internalVendorId: registrationId });
    if (!vendor) {
      return res.status(404).json({
        success: false,
        message: 'Registration not found.'
      });
    }
    
    res.json({
      success: true,
      status: vendor.status,
      vendorId: vendor.vendorId,
      rejectionReason: vendor.rejectionReason
    });
    
  } catch (error) {
    console.error('❌ Status check error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to check status.'
    });
  }
});

// Vendor Login (Updated to work with MongoDB)
app.post('/api/vendors/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find approved vendor
    const vendor = await Vendor.findOne({ 
      email, 
      status: 'approved' 
    });
    
    if (!vendor) {
      return res.status(401).json({ 
        error: "Vendor not found or not approved" 
      });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, vendor.password);
    if (!isMatch) {
      return res.status(401).json({ 
        error: "Invalid password" 
      });
    }

    // Ensure vendor exists in CometChat
    if (!vendor.cometChatRegistered) {
      try {
        await registerVendorInCometChat({
          uid: vendor.vendorId,
          name: vendor.fullName,
          email: vendor.email,
          department: vendor.department,
          companyName: vendor.companyName,
          phone: vendor.phone,
          bio: vendor.bio
        });
        
        vendor.cometChatUid = vendor.vendorId;
        vendor.cometChatRegistered = true;
        await vendor.save();
      } catch (cometChatError) {
        console.error('CometChat registration failed:', cometChatError);
      }
    }

    try {
      // Create auth token for vendor using CometChat REST API
      const tokenResponse = await cometChatAPI(`/users/${vendor.vendorId}/auth_tokens`, 'POST');
      const token = tokenResponse.data.authToken;
      
      // Update last login
      vendor.lastLoginAt = new Date();
      await vendor.save();
      
      res.json({ 
        token, 
        uid: vendor.vendorId, 
        name: vendor.fullName 
      });
    } catch (error) {
      console.error('Failed to create auth token:', error.response?.data || error.message);
      res.status(500).json({ error: 'Failed to create authentication token' });
    }
    
  } catch (error) {
    console.error('❌ Vendor login error:', error);
    res.status(500).json({
      error: 'Login failed. Please try again.'
    });
  }
});

// Get vendor UID by email
app.get('/api/vendor/uid/:email', async (req, res) => {
  try {
    const vendor = await Vendor.findOne({ email: req.params.email, status: 'approved' });
    if (!vendor) {
      return res.status(404).json({ error: "Vendor not found" });
    }
    res.json({ uid: vendor.vendorId });
  } catch (error) {
    console.error('Error finding vendor:', error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  try {
    console.log('🔐 Admin login attempt:', req.body);
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required.'
      });
    }
    
    // Ensure default admin exists
    await createDefaultAdmin();
    
    const admin = await Admin.findOne({ email });
    console.log('👤 Admin found:', admin ? 'Yes' : 'No');
    
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials.'
      });
    }
    
    const isValidPassword = await bcrypt.compare(password, admin.password);
    console.log('🔑 Password valid:', isValidPassword);
    
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid admin credentials.'
      });
    }
    
    // Generate admin token
    const token = crypto.randomBytes(32).toString('hex');
    
    console.log('✅ Admin login successful for:', email);
    
    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        email: admin.email,
        role: admin.role
      }
    });
    
  } catch (error) {
    console.error('❌ Admin login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get All Vendors (Admin)
app.get('/api/admin/vendors', async (req, res) => {
  try {
    // Simple auth check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized access.'
      });
    }
    
    const pending = await Vendor.find({ status: 'pending' }).sort({ createdAt: -1 });
    const approved = await Vendor.find({ status: 'approved' }).sort({ approvedAt: -1 });
    const rejected = await Vendor.find({ status: 'rejected' }).sort({ createdAt: -1 });
    
    res.json({
      success: true,
      pending: pending.map(v => ({
        id: v._id,
        businessName: v.companyName,
        contactName: v.fullName,
        email: v.email,
        phone: v.phone,
        businessType: v.department,
        description: v.bio,
        website: v.vendorProfile?.storeUrl,
        address: v.businessAddress?.street,
        status: v.status,
        createdAt: v.createdAt,
        rejectionReason: v.rejectionReason
      })),
      approved: approved.map(v => ({
        id: v._id,
        businessName: v.companyName,
        contactName: v.fullName,
        email: v.email,
        phone: v.phone,
        businessType: v.department,
        description: v.bio,
        website: v.vendorProfile?.storeUrl,
        address: v.businessAddress?.street,
        status: v.status,
        createdAt: v.createdAt,
        approvedAt: v.approvedAt
      })),
      rejected: rejected.map(v => ({
        id: v._id,
        businessName: v.companyName,
        contactName: v.fullName,
        email: v.email,
        phone: v.phone,
        businessType: v.department,
        description: v.bio,
        website: v.vendorProfile?.storeUrl,
        address: v.businessAddress?.street,
        status: v.status,
        createdAt: v.createdAt,
        rejectionReason: v.rejectionReason
      }))
    });
    
  } catch (error) {
    console.error('❌ Get vendors error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch vendors.'
    });
  }
});

// Approve Vendor (Admin)
app.post('/api/admin/vendors/:vendorId/approve', async (req, res) => {
  try {
    const { vendorId } = req.params;
    
    const vendor = await Vendor.findById(vendorId);
    if (!vendor) {
      return res.status(404).json({
        success: false,
        message: 'Vendor not found.'
      });
    }
    
    // Update vendor status
    vendor.status = 'approved';
    vendor.approvedAt = new Date();
    vendor.approvedBy = 'admin';
    vendor.statusUpdatedAt = new Date();
    
    await vendor.save();
    
    // Register vendor in CometChat
    try {
      await registerVendorInCometChat({
        uid: vendor.vendorId,
        name: vendor.fullName,
        email: vendor.email,
        department: vendor.department,
        companyName: vendor.companyName,
        phone: vendor.phone,
        bio: vendor.bio
      });
      
      vendor.cometChatUid = vendor.vendorId;
      vendor.cometChatRegistered = true;
      await vendor.save();
      
      console.log(`✅ Vendor approved and registered in CometChat: ${vendor.companyName}`);
    } catch (cometChatError) {
      console.error('❌ CometChat registration failed:', cometChatError);
      // Continue with approval even if CometChat fails
    }
    
    res.json({
      success: true,
      message: 'Vendor approved successfully.',
      vendor: {
        id: vendor._id,
        businessName: vendor.companyName,
        vendorId: vendor.vendorId
      }
    });
    
  } catch (error) {
    console.error('❌ Vendor approval error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve vendor.'
    });
  }
});

// Reject Vendor (Admin)
app.post('/api/admin/vendors/:vendorId/reject', async (req, res) => {
  try {
    const { vendorId } = req.params;
    const { reason } = req.body;
    
    const vendor = await Vendor.findById(vendorId);
    if (!vendor) {
      return res.status(404).json({
        success: false,
        message: 'Vendor not found.'
      });
    }
    
    vendor.status = 'rejected';
    vendor.rejectionReason = reason || 'Application did not meet requirements.';
    vendor.rejectedAt = new Date();
    vendor.rejectedBy = 'admin';
    vendor.statusUpdatedAt = new Date();
    
    await vendor.save();
    
    console.log(`❌ Vendor rejected: ${vendor.companyName} - ${reason}`);
    
    res.json({
      success: true,
      message: 'Vendor rejected.',
      vendor: {
        id: vendor._id,
        businessName: vendor.companyName
      }
    });
    
  } catch (error) {
    console.error('❌ Vendor rejection error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject vendor.'
    });
  }
});

// Get vendors for Shopify widget (approved vendors only)
app.get('/api/vendors', async (req, res) => {
  try {
    const vendors = await Vendor.find({ 
      status: 'approved',
      isActive: true 
    }).select('vendorId companyName department fullName');
    
    const formattedVendors = vendors.map(v => ({
      uid: v.vendorId,
      name: v.fullName,
      department: v.department,
      companyName: v.companyName
    }));
    
    res.json(formattedVendors);
  } catch (error) {
    console.error('Error fetching vendors:', error);
    res.status(500).json({ error: 'Failed to fetch vendors' });
  }
});

// Get vendor customers (for dashboard)
app.get('/api/vendors/:vendorUid/customers', async (req, res) => {
  try {
    const { vendorUid } = req.params;
    
    // Verify vendor exists
    const vendor = await Vendor.findOne({ vendorId: vendorUid, status: 'approved' });
    if (!vendor) {
      return res.status(404).json({ error: 'Vendor not found' });
    }
    
    // Fetch conversations from CometChat
    try {
      const conversationsResponse = await cometChatAPI(`/users/${vendorUid}/conversations`);
      const customers = conversationsResponse.data || [];
      
      res.json(customers);
    } catch (cometChatError) {
      console.error('CometChat API error:', cometChatError);
      res.json([]); // Return empty array if CometChat fails
    }
    
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
    
    // Test admin creation
    await createDefaultAdmin();
    
    // Count collections
    const vendorCount = await Vendor.countDocuments();
    const adminCount = await Admin.countDocuments();
    
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: dbStatus,
      collections: {
        vendors: vendorCount,
        admins: adminCount
      },
      environment: {
        nodeEnv: process.env.NODE_ENV || 'development',
        mongoUri: process.env.MONGODB_URI ? 'Configured' : 'Missing',
        cometChatAppId: process.env.COMETCHAT_APP_ID ? 'Configured' : 'Missing'
      }
    });
  } catch (error) {
    res.status(500).json({
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 MongoDB: ${process.env.MONGODB_URI ? 'Connected' : 'Not configured'}`);
  console.log(`💬 CometChat: ${process.env.COMETCHAT_APP_ID ? 'Configured' : 'Not configured'}`);
});
