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

// EMERGENCY CORS FIX - Allow everything
app.use((req, res, next) => {
  // Set CORS headers for ALL requests
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', '*');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Max-Age', '86400');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  next();
});

app.use(express.json());

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
    
    const response = await axios.post(`https://api-${process.env.COMETCHAT_REGION}.cometchat.io/v3.0/users`, {
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
        'appId': process.env.COMETCHAT_APP_ID,
        'apiKey': process.env.COMETCHAT_AUTH_KEY
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
    console.log('🔄 Vendor registration attempt:', req.body);
    
    const { businessName, contactName, email, phone, businessType, description, website, address } = req.body;
    
    // Validate required fields
    if (!businessName || !contactName || !email || !phone || !businessType) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }
    
    console.log('✅ Fields validated');
    
    // Check if email already exists
    console.log('🔍 Checking existing vendor...');
    const existingVendor = await Vendor.findOne({ email });
    if (existingVendor) {
      console.log('❌ Email already exists:', email);
      return res.status(400).json({
        success: false,
        message: 'Email already registered. Please use a different email or contact support.'
      });
    }
    
    console.log('✅ Email is unique');
    
    // Generate vendor UID
    const vendorId = `vendor_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const registrationId = `reg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    console.log('✅ Generated IDs:', { vendorId, registrationId });
    
    // Hash password
    console.log('🔐 Hashing password...');
    const hashedPassword = await bcrypt.hash('vendor123', 10);
    console.log('✅ Password hashed');
    
    // Create new vendor with pending status
    console.log('📝 Creating vendor object...');
    const vendor = new Vendor({
      vendorId,
      email,
      firstName: contactName.split(' ')[0] || contactName,
      lastName: contactName.split(' ').slice(1).join(' ') || '',
      phone,
      companyName: businessName,
      department: businessType,
      businessType: 'company',
      password: hashedPassword,
      internalVendorId: registrationId,
      bio: description || '',
      status: 'pending',
      businessAddress: {
        street: address || '',
        city: '',
        state: '',
        country: '',
        zipCode: ''
      },
      vendorProfile: {
        storeUrl: website || ''
      }
    });
    
    console.log('💾 Saving vendor to database...');
    await vendor.save();
    
    console.log(`✅ New vendor registration successful: ${businessName} (${email})`);
    
    res.json({
      success: true,
      message: 'Registration submitted successfully. Please wait for admin approval.',
      registrationId: vendor.internalVendorId
    });
    
  } catch (error) {
    console.error('❌ Vendor registration error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
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
    console.log('🔐 Vendor login attempt:', { email: req.body.email });
    
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: "Email and password are required" 
      });
    }
    
    // Find approved vendor
    console.log('🔍 Looking for approved vendor with email:', email);
    const vendor = await Vendor.findOne({ 
      email, 
      status: 'approved' 
    });
    
    console.log('👤 Vendor found:', vendor ? 'Yes' : 'No');
    if (vendor) {
      console.log('📊 Vendor details:', {
        id: vendor._id,
        email: vendor.email,
        status: vendor.status,
        vendorId: vendor.vendorId,
        hasPassword: !!vendor.password,
        firstName: vendor.firstName,
        lastName: vendor.lastName
      });
    }
    
    if (!vendor) {
      // Check if vendor exists but not approved
      const anyVendor = await Vendor.findOne({ email });
      if (anyVendor) {
        console.log('❌ Vendor exists but status is:', anyVendor.status);
        return res.status(401).json({ 
          error: `Vendor account is ${anyVendor.status}. Please wait for admin approval.` 
        });
      }
      return res.status(401).json({ 
        error: "Vendor not found. Please register first." 
      });
    }
    
    // Verify password
    console.log('🔑 Verifying password...');
    console.log('Password provided:', password);
    console.log('Stored password hash exists:', !!vendor.password);
    
    const isMatch = await bcrypt.compare(password, vendor.password);
    console.log('🔑 Password match:', isMatch);
    
    if (!isMatch) {
      return res.status(401).json({ 
        error: "Invalid password" 
      });
    }

    console.log('✅ Password verified, proceeding with CometChat...');

    // Ensure vendor exists in CometChat
    if (!vendor.cometChatRegistered) {
      console.log('📝 Registering vendor in CometChat...');
      try {
        const fullName = `${vendor.firstName} ${vendor.lastName}`.trim();
        await registerVendorInCometChat({
          uid: vendor.vendorId,
          name: fullName,
          email: vendor.email,
          department: vendor.department,
          companyName: vendor.companyName,
          phone: vendor.phone,
          bio: vendor.bio
        });
        
        vendor.cometChatUid = vendor.vendorId;
        vendor.cometChatRegistered = true;
        await vendor.save();
        console.log('✅ CometChat registration successful');
      } catch (cometChatError) {
        console.error('❌ CometChat registration failed:', cometChatError);
      }
    }

    try {
      console.log('🎫 Creating CometChat auth token for vendor:', vendor.vendorId);
      
      // First, check if user exists in CometChat
      try {
        console.log('🔍 Checking if vendor exists in CometChat...');
        const userCheck = await cometChatAPI(`/users/${vendor.vendorId}`);
        console.log('✅ Vendor exists in CometChat:', userCheck.data.uid);
      } catch (checkError) {
        console.log('❌ Vendor not found in CometChat, creating...');
        // Force re-register in CometChat
        const fullName = `${vendor.firstName} ${vendor.lastName}`.trim();
        await registerVendorInCometChat({
          uid: vendor.vendorId,
          name: fullName,
          email: vendor.email,
          department: vendor.department,
          companyName: vendor.companyName,
          phone: vendor.phone,
          bio: vendor.bio
        });
        console.log('✅ Vendor re-registered in CometChat');
      }
      
      // Now create auth token
      console.log('🎫 Creating auth token...');
      const tokenResponse = await cometChatAPI(`/users/${vendor.vendorId}/auth_tokens`, 'POST');
      const token = tokenResponse.data.authToken;
      
      console.log('✅ Auth token created successfully');
      
      // Update last login
      vendor.lastLoginAt = new Date();
      await vendor.save();
      
      const fullName = `${vendor.firstName} ${vendor.lastName}`.trim();
      
      console.log('🎉 Login successful for:', email);
      
      res.json({ 
        token, 
        uid: vendor.vendorId, 
        name: fullName 
      });
    } catch (error) {
      console.error('❌ Failed to create auth token:', error);
      console.error('❌ Error details:', error.response?.data || error.message);
      console.error('❌ Error stack:', error.stack);
      res.status(500).json({ 
        error: 'Failed to create authentication token',
        details: error.response?.data?.error?.message || error.message
      });
    }
    
  } catch (error) {
    console.error('❌ Vendor login error:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      error: 'Login failed. Please try again.',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
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
      cometChatRegistered: true 
    }).select('vendorId companyName department email phone bio status');
    
    const formattedVendors = vendors.map(vendor => ({
      uid: vendor.vendorId,
      name: vendor.companyName,
      department: vendor.department,
      email: vendor.email,
      phone: vendor.phone,
      bio: vendor.bio,
      status: 'online' // You can implement real status checking later
    }));
    
    res.json({ vendors: formattedVendors });
  } catch (error) {
    console.error('Error fetching vendors:', error);
    res.status(500).json({ error: 'Failed to fetch vendors' });
  }
});

// Get available vendors (alias for Shopify widget compatibility)
app.get('/api/vendors/available', async (req, res) => {
  try {
    const vendors = await Vendor.find({ 
      status: 'approved',
      cometChatRegistered: true 
    }).select('vendorId companyName department email phone bio status');
    
    const formattedVendors = vendors.map(vendor => ({
      uid: vendor.vendorId,
      name: vendor.companyName,
      department: vendor.department,
      email: vendor.email,
      phone: vendor.phone,
      bio: vendor.bio,
      status: 'online' // You can implement real status checking later
    }));
    
    console.log(`📋 Available vendors fetched: ${formattedVendors.length} vendors`);
    res.json({ vendors: formattedVendors });
  } catch (error) {
    console.error('Error fetching available vendors:', error);
    res.status(500).json({ error: 'Failed to fetch available vendors' });
  }
});

// Assign customer to vendor (for Shopify widget)
app.post('/api/assign-customer-to-vendor', async (req, res) => {
  try {
    const { customerId, vendorId } = req.body;
    
    console.log('💾 Assigning customer to vendor:', { customerId, vendorId });
    
    // This is mainly for logging - CometChat handles the actual mapping
    // But we can store it for analytics or backup purposes
    
    res.json({
      success: true,
      message: 'Customer-vendor mapping stored',
      customerId,
      vendorId
    });
    
  } catch (error) {
    console.error('❌ Error assigning customer to vendor:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to assign customer to vendor'
    });
  }
});

// Send message endpoint (for Shopify widget)
app.post('/api/send-message', async (req, res) => {
  try {
    const { customerId, vendorId, message, timestamp } = req.body;
    
    console.log('📤 Message sent notification:', {
      customerId,
      vendorId,
      message: message.substring(0, 50) + '...',
      timestamp
    });
    
    // Mark customer as active (this helps vendor dashboard show active customers)
    // The actual message is handled by CometChat, this is just for logging/tracking
    
    res.json({
      success: true,
      message: 'Message logged successfully',
      customerId,
      vendorId,
      timestamp
    });
    
  } catch (error) {
    console.error('❌ Error logging message:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to log message'
    });
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

// Simple test endpoint
app.get('/test-cors', (req, res) => {
  res.json({ 
    message: 'CORS is working!', 
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'no-origin'
  });
});

// Test CometChat registration
app.get('/test-cometchat/:vendorId', async (req, res) => {
  try {
    const { vendorId } = req.params;
    
    console.log('🧪 Testing CometChat for vendor:', vendorId);
    
    // Find vendor in database
    const vendor = await Vendor.findOne({ vendorId });
    if (!vendor) {
      return res.status(404).json({ error: 'Vendor not found in database' });
    }
    
    console.log('📋 Vendor found:', {
      vendorId: vendor.vendorId,
      email: vendor.email,
      firstName: vendor.firstName,
      lastName: vendor.lastName
    });
    
    // Test CometChat registration
    const fullName = `${vendor.firstName} ${vendor.lastName}`.trim();
    console.log('🔄 Attempting CometChat registration...');
    
    const result = await registerVendorInCometChat({
      uid: vendor.vendorId,
      name: fullName,
      email: vendor.email,
      department: vendor.department,
      companyName: vendor.companyName,
      phone: vendor.phone,
      bio: vendor.bio
    });
    
    console.log('✅ CometChat registration result:', result);
    
    res.json({
      success: true,
      vendor: {
        vendorId: vendor.vendorId,
        name: fullName,
        email: vendor.email
      },
      cometChatResult: result
    });
    
  } catch (error) {
    console.error('❌ CometChat test failed:', error);
    res.status(500).json({
      error: error.message,
      details: error.response?.data || error.stack
    });
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
