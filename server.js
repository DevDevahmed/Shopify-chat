require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const { connectMongoDB } = require('./config/database');
const Vendor = require('./models/Vendor');
const vendorManagementService = require('./services/vendorManagementService');
// Internal vendor management system - no external APIs required
console.log('✅ Using internal vendor management system (no external API costs)');
const axios = require('axios');

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
const csv = require('csv-parser');
const { Readable } = require('stream');
const crypto = require('crypto');

// Helper function to generate secure random password
function generateSecurePassword(length = 12) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.raw({ type: 'text/csv' }));

// CometChat REST API configuration
const COMETCHAT_API_BASE = `https://api-${process.env.COMETCHAT_REGION}.cometchat.io/v3.0`;

// Helper function to make CometChat API calls
async function cometChatAPI(endpoint, method = 'GET', data = null) {
  try {
// Connect to MongoDB Atlas
connectMongoDB();

    // Validate environment variables
    if (!process.env.COMETCHAT_APP_ID || !process.env.COMETCHAT_AUTH_KEY || !process.env.COMETCHAT_REGION) {
      console.error('❌ Missing required CometChat environment variables');
      console.log('Required: COMETCHAT_APP_ID, COMETCHAT_AUTH_KEY, COMETCHAT_REGION');
      process.exit(1);
    }

    // Validate ShipTurtle environment variables
    if (!process.env.SHIPTURTLE_API_KEY || !process.env.SHIPTURTLE_STORE_ID) {
      console.warn('⚠️ ShipTurtle API credentials not configured');
      console.log('Optional: SHIPTURTLE_API_KEY, SHIPTURTLE_STORE_ID, SHIPTURTLE_API_URL');
    }
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

const VENDORS_FILE = path.join(__dirname, 'data', 'vendors.json');

async function getVendors() {
  try {
    const data = await fs.readFile(VENDORS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

async function saveVendors(vendors) {
  await fs.writeFile(VENDORS_FILE, JSON.stringify(vendors, null, 2));
}

async function ensureVendorExists(vendor) {
  try {
    // Check if user exists in CometChat
    await cometChatAPI(`/users/${vendor.uid}`);
  } catch (e) {
    // User doesn't exist, create them
    try {
      const userData = {
        uid: vendor.uid,
        name: vendor.name,
        metadata: { role: "vendor", email: vendor.email }
      };
      await cometChatAPI('/users', 'POST', userData);
      console.log(`✅ Created vendor in CometChat: ${vendor.name}`);
    } catch (createError) {
      console.error(`❌ Failed to create vendor ${vendor.name}:`, createError.response?.data || createError.message);
    }
  }
}

async function ensureCustomerExists(customerId) {
  try {
    await cometChatAPI(`/users/${customerId}`);
  } catch (e) {
    try {
      const userData = {
        uid: customerId,
        name: `Customer ${customerId}`,
        metadata: { role: "customer" }
      };
      await cometChatAPI('/users', 'POST', userData);
      console.log(`✅ Created customer in CometChat: ${customerId}`);
    } catch (createError) {
      console.error(`❌ Failed to create customer ${customerId}:`, createError.response?.data || createError.message);
    }
  }
}

app.post('/api/sync-vendors', async (req, res) => {
  try {
    const vendors = [];
    const stream = Readable.from(req.body.toString());
    await new Promise((resolve, reject) => {
      stream
        .pipe(csv())
        .on('data', (row) => {
          vendors.push({
            email: row.Email?.trim(),
            name: row.Name?.trim(),
            id: row.ID?.trim()
          });
        })
        .on('end', resolve)
        .on('error', reject);
    });

    if (vendors.length === 0) {
      return res.status(400).json({ error: "No vendors found in CSV" });
    }

    let existingVendors = await getVendors();
    const newVendorsWithPasswords = [];

    for (const vendor of vendors) {
      if (!vendor.email || !vendor.name || !vendor.id) continue;
      const existing = existingVendors.find(v => v.email === vendor.email);
      const uid = vendor.id;

      if (!existing) {
        // Generate unique secure password for each new vendor
        const plainPassword = generateSecurePassword();
        const hashedPassword = await bcrypt.hash(plainPassword, 10);
        const newVendor = {
          email: vendor.email,
          name: vendor.name,
          password: hashedPassword,
          uid
        };
        existingVendors.push(newVendor);
        newVendorsWithPasswords.push({
          ...newVendor,
          plainPassword // Store temporarily for response
        });
        console.log(`🆕 Added vendor: ${vendor.name} (${vendor.email}) with password: ${plainPassword}`);
      } else {
        if (existing.name !== vendor.name) {
          existing.name = vendor.name;
          console.log(`🔄 Updated vendor: ${vendor.name}`);
        }
      }

      await ensureVendorExists({ uid, name: vendor.name, email: vendor.email });
    }

    await saveVendors(existingVendors);

    res.json({
      success: true,
      added: newVendorsWithPasswords.length,
      total: existingVendors.length,
      newVendors: newVendorsWithPasswords.map(v => ({
        email: v.email,
        name: v.name,
        password: v.plainPassword
      }))
    });
  } catch (error) {
    console.error("CSV Sync Error:", error);
    res.status(500).json({ error: "Failed to sync vendors from CSV" });
  }
});

app.post('/api/vendor/login', async (req, res) => {
  const { email, password } = req.body;
  const vendors = await getVendors();
  const vendor = vendors.find(v => v.email === email);

  if (!vendor) {
    return res.status(401).json({ error: "Vendor not found" });
  }

  const isMatch = await bcrypt.compare(password, vendor.password);
  if (!isMatch) {
    return res.status(401).json({ error: "Invalid password" });
  }

  await ensureVendorExists(vendor);

  try {
    // Create auth token for vendor using CometChat REST API
    const tokenResponse = await cometChatAPI(`/users/${vendor.uid}/auth_tokens`, 'POST');
    const token = tokenResponse.data.authToken;
    res.json({ token, uid: vendor.uid, name: vendor.name });
  } catch (error) {
    console.error('Failed to create auth token:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to create authentication token' });
  }
});

app.get('/api/vendor/uid/:email', async (req, res) => {
  const vendors = await getVendors();
  const vendor = vendors.find(v => v.email === req.params.email);
  if (!vendor) return res.status(404).json({ error: "Vendor not found" });
  res.json({ uid: vendor.uid });
});

// CometChat Message Webhook - Triggered when customer sends a message
app.post('/api/cometchat-webhook', async (req, res) => {
  try {
    const { data } = req.body;
    // Check if this is a message event from a customer
    if (data && data.message && data.message.sender) {
      const senderId = data.message.sender.uid;
      const receiverId = data.message.receiver?.uid;
      console.log(`💬 Message webhook: ${senderId} → ${receiverId}`);

      // Check if sender is a customer (not a vendor)
      try {
        const senderData = await cometChatAPI(`/users/${senderId}`);
        const isCustomer = senderData.data?.metadata?.role === 'customer';
        if (isCustomer) {
          // Get customer-vendor mapping to find assigned vendor
          const mapping = await getCustomerVendorMapping();
          const assignedVendor = mapping[senderId];
          if (assignedVendor) {
            // Mark customer as active (has sent a message)
            await markCustomerAsActive(senderId, assignedVendor);
            console.log(`✅ Customer ${senderId} marked as active for vendor ${assignedVendor}`);
          } else {
            console.warn(`⚠️ Customer ${senderId} sent message but no vendor assigned`);
          }
        }
      } catch (error) {
        console.error('Error processing message webhook:', error.message);
      }
    }
    res.json({ success: true, message: 'Webhook processed' });
  } catch (error) {
    console.error('CometChat webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.post('/api/sync-customer', async (req, res) => {
  const { id, email, first_name, last_name } = req.body;
  if (!id) return res.status(400).json({ error: "Customer ID required" });

  try {
    let customerExists = false;
    const customerName = `${first_name || 'Customer'} ${last_name || ''}`.trim();
    
    // Check if customer already exists
    try {
      const existingCustomer = await cometChatAPI(`/users/${id}`);
      customerExists = true;
      
      // Update existing customer with latest Shopify info
      const updateData = {
        name: customerName,
        metadata: { 
          email: email || "guest@example.com", 
          role: "customer",
          shopifyName: customerName,
          firstName: first_name,
          lastName: last_name
        }
      };
      await cometChatAPI(`/users/${id}`, 'PUT', updateData);
      console.log(`🔄 Updated customer: ${customerName} (${email})`);
    } catch (e) {
      // User doesn't exist, create them
      const userData = {
        uid: id,
        name: customerName,
        metadata: { 
          email: email || "guest@example.com", 
          role: "customer",
          shopifyName: customerName,
          firstName: first_name,
          lastName: last_name
        }
      };
      await cometChatAPI('/users', 'POST', userData);
      console.log(`✅ Created customer: ${customerName} (${email})`);
    }

    // Auto-assign customer to a vendor if not already assigned
    const mapping = await getCustomerVendorMapping();
    if (!mapping[id]) {
      const vendors = await getVendors();
      if (vendors.length > 0) {
        // Simple round-robin assignment - assign to vendor with least customers
        const vendorCustomerCounts = {};
        vendors.forEach(v => vendorCustomerCounts[v.uid] = 0);
        Object.values(mapping).forEach(vendorId => {
          if (vendorCustomerCounts[vendorId] !== undefined) {
            vendorCustomerCounts[vendorId]++;
          }
        });
        const leastBusyVendor = Object.keys(vendorCustomerCounts).reduce((a, b) => 
          vendorCustomerCounts[a] <= vendorCustomerCounts[b] ? a : b
        );
        mapping[id] = leastBusyVendor;
        await saveCustomerVendorMapping(mapping);
        console.log(`🔗 Auto-assigned customer ${id} to vendor ${leastBusyVendor}`);
      }
    }

    res.json({ 
      success: true, 
      message: customerExists ? "Customer updated successfully" : "Customer created successfully",
      assigned: mapping[id] || null,
      customerName: customerName
    });
  } catch (error) {
    console.error("Error syncing customer:", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to sync customer" });
  }
});

// File paths for data storage
const CUSTOMER_VENDOR_MAPPING_FILE = path.join(__dirname, 'data', 'customer-vendor-mapping.json');
const ACTIVE_CUSTOMERS_FILE = path.join(__dirname, 'data', 'active-customers.json');
const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');

// Helper functions for customer-vendor mapping
async function getCustomerVendorMapping() {
  try {
    await fs.mkdir(path.dirname(CUSTOMER_VENDOR_MAPPING_FILE), { recursive: true });
    const data = await fs.readFile(CUSTOMER_VENDOR_MAPPING_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    // File doesn't exist, create it with empty mapping
    const emptyMapping = {};
    await saveCustomerVendorMapping(emptyMapping);
    return emptyMapping;
  }
}

async function saveCustomerVendorMapping(mapping) {
  try {
    await fs.mkdir(path.dirname(CUSTOMER_VENDOR_MAPPING_FILE), { recursive: true });
    await fs.writeFile(CUSTOMER_VENDOR_MAPPING_FILE, JSON.stringify(mapping, null, 2));
  } catch (error) {
    console.error('Failed to save customer-vendor mapping:', error);
  }
}

// Helper functions for active customers (who have sent messages)
async function getActiveCustomers() {
  try {
    await fs.mkdir(path.dirname(ACTIVE_CUSTOMERS_FILE), { recursive: true });
    const data = await fs.readFile(ACTIVE_CUSTOMERS_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    // File doesn't exist, create it with empty data
    const emptyCustomers = {};
    await saveActiveCustomers(emptyCustomers);
    return emptyCustomers;
  }
}

async function saveActiveCustomers(customers) {
  try {
    await fs.mkdir(path.dirname(ACTIVE_CUSTOMERS_FILE), { recursive: true });
    await fs.writeFile(ACTIVE_CUSTOMERS_FILE, JSON.stringify(customers, null, 2));
  } catch (error) {
    console.error('Failed to save active customers:', error);
  }
}

// Helper functions for messages
async function getMessages() {
  try {
    await fs.mkdir(path.dirname(MESSAGES_FILE), { recursive: true });
    const data = await fs.readFile(MESSAGES_FILE, 'utf8');
    return JSON.parse(data);
  } catch {
    return []; // Return an empty array if the file doesn't exist
  }
}

async function saveMessages(messages) {
  try {
    await fs.mkdir(path.dirname(MESSAGES_FILE), { recursive: true });
    await fs.writeFile(MESSAGES_FILE, JSON.stringify(messages, null, 2));
  } catch (error) {
    console.error('Failed to save messages:', error);
  }
}

// Mark customer as active (has sent a message)
async function markCustomerAsActive(customerId, vendorId) {
  const activeCustomers = await getActiveCustomers();
  const now = new Date().toISOString();
  if (!activeCustomers[customerId]) {
    activeCustomers[customerId] = {
      vendorId,
      firstMessageAt: now,
      lastMessageAt: now
    };
    console.log(`🟢 Customer ${customerId} is now active (first message sent)`);
  } else {
    activeCustomers[customerId].lastMessageAt = now;
  }
  await saveActiveCustomers(activeCustomers);
  return activeCustomers[customerId];
}

// Get customers assigned to a specific vendor - fetch directly from CometChat conversations
app.get('/api/vendors/:vendorUid/customers', async (req, res) => {
  try {
    const { vendorUid } = req.params;
    console.log(`🔍 Fetching customers for vendor: ${vendorUid}`);
    
    // Method 1: Get conversations for this vendor from CometChat
    try {
      const conversationsResponse = await cometChatAPI(`/users/${vendorUid}/conversations?conversationType=user&limit=100`);
      
      if (conversationsResponse.data && conversationsResponse.data.length > 0) {
        const customers = conversationsResponse.data
          .filter(conversation => {
            // Filter out conversations where the vendor is talking to themselves
            return conversation.conversationWith && conversation.conversationWith.uid !== vendorUid;
          })
          .map(conversation => {
            const customer = conversation.conversationWith;
            // Add conversation metadata
            customer.lastActive = conversation.updatedAt;
            customer.lastMessage = conversation.lastMessage;
            customer.conversationId = conversation.conversationId;
            return customer;
          });
        
        console.log(`📋 Found ${customers.length} customers with conversations for vendor ${vendorUid}`);
        return res.json({ 
          customers,
          total: customers.length,
          source: 'cometchat_conversations'
        });
      }
    } catch (conversationError) {
      console.warn('Failed to fetch conversations from CometChat, trying fallback method:', conversationError.message);
    }
    
    // Method 2: Fallback - get from local active customers (legacy method)
    const activeCustomers = await getActiveCustomers();
    const activeCustomerIds = Object.keys(activeCustomers).filter(customerId => 
      activeCustomers[customerId].vendorId === vendorUid
    );
    
    console.log(`📋 Fallback: Vendor ${vendorUid} has ${activeCustomerIds.length} active customers from local storage`);
    
    const customers = [];
    for (const customerId of activeCustomerIds) {
      try {
        const customer = await cometChatAPI(`/users/${customerId}`);
        const customerData = customer.data;
        customerData.activityInfo = activeCustomers[customerId];
        customers.push(customerData);
      } catch (error) {
        console.warn(`Customer ${customerId} not found in CometChat:`, error.message);
      }
    }
    
    res.json({ 
      customers,
      total: customers.length,
      source: 'local_storage_fallback',
      message: customers.length === 0 ? 'No customers have sent messages yet' : `${customers.length} active customers`
    });
    
  } catch (error) {
    console.error('Error fetching vendor customers:', error);
    res.status(500).json({ error: 'Failed to fetch customers' });
  }
});

// Assign customer to vendor
app.post('/api/assign-customer-to-vendor', async (req, res) => {
  try {
    const { customerId, vendorId } = req.body;
    if (!customerId || !vendorId) {
      return res.status(400).json({ error: 'Customer ID and Vendor ID are required' });
    }
    const mapping = await getCustomerVendorMapping();
    mapping[customerId] = vendorId;
    await saveCustomerVendorMapping(mapping);
    res.json({ success: true, message: `Customer ${customerId} assigned to vendor ${vendorId}` });
  } catch (error) {
    console.error('Error assigning customer to vendor:', error);
    res.status(500).json({ error: 'Failed to assign customer to vendor' });
  }
});

// Get active vendor for customer widget (for auto-assignment)
app.get('/api/vendor/active', async (req, res) => {
  try {
    const vendors = await getVendors();
    // Return the first available vendor as default, or implement round-robin logic
    const activeVendor = vendors.length > 0 ? vendors[0] : null;
    res.json({ uid: activeVendor?.uid || 'default_vendor' });
  } catch (error) {
    res.json({ uid: 'default_vendor' });
  }

// Get available vendors for customer selection
app.get('/api/vendors/available', async (req, res) => {
  try {
    const result = await vendorManagementService.getAvailableVendors();
    if (result.success) {
      res.json({
        vendors: result.vendors,
        total: result.total
      });
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to fetch available vendors:', error);
    res.status(500).json({
      error: 'Failed to fetch available vendors'
    });
  }
});

// Get all vendors (admin only endpoint)
app.get('/api/admin/vendors', async (req, res) => {
  try {
    // Simple admin check (you can enhance this with proper JWT later)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer admin_')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    const result = await vendorManagementService.getAllVendors(req.query);
    if (result.success) {
      res.json({
        success: true,
        vendors: result.vendors,
        total: result.total
      });
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to fetch vendors:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch vendors'
    });
  }
});

// Approve vendor (admin only)
app.post('/api/admin/vendors/:vendorId/approve', async (req, res) => {
  try {
    // Admin authentication check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer admin_')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    const { vendorId } = req.params;
    const result = await vendorManagementService.approveVendor(vendorId, 'admin');
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to approve vendor:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Reject vendor (admin only)
app.post('/api/admin/vendors/:vendorId/reject', async (req, res) => {
  try {
    // Admin authentication check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer admin_')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    const { vendorId } = req.params;
    const { reason } = req.body;
    const result = await vendorManagementService.rejectVendor(vendorId, reason, 'admin');
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to reject vendor:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Toggle vendor status (activate/suspend)
app.post('/api/vendors/:vendorId/toggle-status', async (req, res) => {
  try {
    const { vendorId } = req.params;
    const { isActive } = req.body;
    const result = await vendorManagementService.toggleVendorStatus(vendorId, isActive);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(404).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to toggle vendor status:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Get vendor statistics (admin only)
app.get('/api/admin/stats', async (req, res) => {
  try {
    // Admin authentication check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer admin_')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    const result = await vendorManagementService.getVendorStats();
    
    if (result.success) {
      res.json(result.stats);
    } else {
      res.status(500).json(result);
    }
  } catch (error) {
    console.error('❌ Failed to get vendor stats:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Admin authentication (separate from vendors)
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }
    
    // Hardcoded admin credentials (you can move this to environment variables later)
    const ADMIN_EMAIL = 'mariem@gmail.com';
    const ADMIN_PASSWORD = 'mariem123';
    
    if (email === ADMIN_EMAIL && password === ADMIN_PASSWORD) {
      // Generate admin session token (simple approach)
      const adminToken = `admin_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      
      res.json({
        success: true,
        message: 'Admin login successful',
        admin: {
          email: ADMIN_EMAIL,
          name: 'Admin',
          role: 'admin',
          token: adminToken
        }
      });
    } else {
      res.status(401).json({
        success: false,
        error: 'Invalid admin credentials'
      });
    }
    
  } catch (error) {
    console.error('❌ Admin authentication failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Vendor authentication (separate from admin)
app.post('/api/vendors/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required'
      });
    }
    
    const result = await vendorManagementService.authenticateVendor(email, password);
    
    if (result.success) {
      res.json(result);
    } else {
      res.status(401).json(result);
    }
  } catch (error) {
    console.error('❌ Vendor authentication failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

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

// Retry CometChat registration for a vendor (admin only)
app.post('/api/admin/vendors/:vendorId/retry-cometchat', async (req, res) => {
  try {
    // Admin authentication check
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer admin_')) {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }
    
    // Get vendor details
    const { vendorId } = req.params;
    const vendorResult = await vendorManagementService.getVendor(vendorId);
    
    if (!vendorResult.success) {
      return res.status(404).json({
        success: false,
        error: 'Vendor not found'
      });
    }
    
    const vendor = vendorResult.vendor;
    console.log(`🔄 Retrying CometChat registration for vendor: ${vendorId}`);
    
    try {
      const cometChatResult = await registerVendorInCometChat({
        uid: vendor.vendorId,
        name: `${vendor.firstName} ${vendor.lastName}`,
        email: vendor.email,
        department: vendor.department,
        companyName: vendor.companyName,
        phone: vendor.phone,
        bio: vendor.bio
      });
      
      if (cometChatResult.success) {
        vendor.cometChatUid = vendor.vendorId;
        vendor.cometChatRegistered = true;
        await vendor.save();
        
        console.log(`✅ CometChat registration successful for vendor: ${vendorId}`);
        
        res.json({
          success: true,
          message: 'CometChat registration successful',
          vendor: {
            vendorId: vendor.vendorId,
            name: `${vendor.firstName} ${vendor.lastName}`,
            cometChatRegistered: true
          }
        });
      } else {
        console.log(`❌ CometChat registration failed for vendor: ${vendorId}`, cometChatResult.error);
        res.status(500).json({
          success: false,
          error: cometChatResult.error
        });
      }
    } catch (error) {
      console.error(`❌ CometChat registration error for vendor ${vendorId}:`, error.message);
      res.status(500).json({
        success: false,
        error: error.message
      });
    }
    
  } catch (error) {
    console.error('❌ Retry CometChat registration failed:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 MongoDB: ${process.env.MONGODB_URI ? 'Connected' : 'Not configured'}`);
});
});