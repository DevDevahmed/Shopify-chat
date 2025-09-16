require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcryptjs');
const axios = require('axios');
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
    // Validate required environment variables
    if (!process.env.COMETCHAT_APP_ID || !process.env.COMETCHAT_AUTH_KEY || !process.env.COMETCHAT_REGION) {
      throw new Error('Missing CometChat environment variables. Please check COMETCHAT_APP_ID, COMETCHAT_AUTH_KEY, and COMETCHAT_REGION');
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
  const { id, email, first_name } = req.body;
  if (!id) return res.status(400).json({ error: "Customer ID required" });

  try {
    let customerExists = false;
    
    // Check if customer already exists
    try {
      await cometChatAPI(`/users/${id}`);
      customerExists = true;
    } catch (e) {
      // User doesn't exist, create them
      const userData = {
        uid: id,
        name: first_name || "Guest",
        metadata: { email: email || "guest@example.com", role: "customer" }
      };
      await cometChatAPI('/users', 'POST', userData);
      console.log(`✅ Created customer: ${first_name} (${email})`);
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
      message: customerExists ? "Customer already exists" : "Customer created successfully",
      assigned: mapping[id] || null
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

// Get customers assigned to a specific vendor (ONLY ACTIVE CUSTOMERS WHO SENT MESSAGES)
app.get('/api/vendor/:vendorUid/customers', async (req, res) => {
  try {
    const { vendorUid } = req.params;
    const activeCustomers = await getActiveCustomers();
    
    // Find only ACTIVE customers assigned to this vendor (who have sent messages)
    const activeCustomerIds = Object.keys(activeCustomers).filter(customerId => 
      activeCustomers[customerId].vendorId === vendorUid
    );
    
    console.log(`Vendor ${vendorUid} has ${activeCustomerIds.length} active customers (who sent messages)`);
    
    // Fetch customer details from CometChat
    const customers = [];
    for (const customerId of activeCustomerIds) {
      try {
        const customer = await cometChatAPI(`/users/${customerId}`);
        const customerData = customer.data;
        
        // Add activity info
        customerData.activityInfo = activeCustomers[customerId];
        customers.push(customerData);
      } catch (error) {
        console.warn(`Active customer ${customerId} not found in CometChat:`, error.message);
      }
    }
    
    res.json({ 
      customers,
      totalActive: customers.length,
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
});

// Get available vendors for customer selection
app.get('/api/vendors/available', async (req, res) => {
  try {
    const vendors = await getVendors();
    
    // Format vendors for customer selection UI
    const availableVendors = vendors.map(vendor => ({
      uid: vendor.uid,
      name: vendor.name,
      email: vendor.email,
      status: 'online', // TODO: Implement real status checking
      department: vendor.vendorName // Use vendorName as the department
    }));
    
    res.json({ 
      vendors: availableVendors,
      total: availableVendors.length 
    });
  } catch (error) {
    console.error('Error fetching available vendors:', error);
    res.status(500).json({ error: 'Failed to fetch available vendors' });
  }
});

// Customer selects a specific vendor
app.post('/api/customer/select-vendor', async (req, res) => {
  try {
    const { customerId, vendorId } = req.body;
    
    if (!customerId || !vendorId) {
      return res.status(400).json({ error: 'Customer ID and Vendor ID are required' });
    }
    
    // Verify vendor exists (vendorId is actually the department name)
    const vendors = await getVendors();
    const selectedVendor = vendors.find(v => v.vendorName === vendorId);
    
    if (!selectedVendor) {
      console.log(`❌ Vendor not found for department: ${vendorId}`);
      console.log('Available vendors:', vendors.map(v => ({ uid: v.uid, vendorName: v.vendorName })));
      return res.status(404).json({ error: 'Selected vendor not found' });
    }
    
    // Update customer-vendor mapping (store vendor uid, not department name)
    const mapping = await getCustomerVendorMapping();
    mapping[customerId] = selectedVendor.uid;
    await saveCustomerVendorMapping(mapping);
    
    console.log(`🎯 Customer ${customerId} selected vendor ${vendorId} (${selectedVendor.name})`);
    
    res.json({ 
      success: true, 
      message: `Connected to ${selectedVendor.name}`,
      vendor: {
        uid: selectedVendor.uid,
        name: selectedVendor.name,
        department: selectedVendor.name
      }
    });
  } catch (error) {
    console.error('Error selecting vendor:', error);
    res.status(500).json({ error: 'Failed to select vendor' });
  }
});

// Customer sends a message to a vendor
app.post('/api/send-message', async (req, res) => {
  try {
    const { customerId, vendorId, message, timestamp } = req.body;

    if (!customerId || !vendorId || !message || !timestamp) {
      return res.status(400).json({ error: 'Missing required fields for sending a message' });
    }

    // Log the message on the server
    console.log(`[${timestamp}] Message from ${customerId} to ${vendorId}: ${message}`);

    // Save the message to our messages.json file
    const messages = await getMessages();
    messages.push({ customerId, vendorId, message, timestamp });
    await saveMessages(messages);

    // Mark customer as active so they appear in vendor dashboard
    await markCustomerAsActive(customerId, vendorId);
    console.log(`✅ Customer ${customerId} marked as active for vendor ${vendorId}`);

    // Create customer in CometChat if they don't exist (for vendor dashboard messaging)
    try {
      await ensureCustomerExists(customerId);
    } catch (error) {
      console.error('Failed to create customer in CometChat:', error);
    }

    res.json({ success: true, message: 'Message received' });

  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get all vendors (for super user dashboard)
app.get('/api/vendors', async (req, res) => {
  try {
    const vendors = await getVendors();
    res.json({ vendors });
  } catch (error) {
    console.error('Error fetching vendors:', error);
    res.status(500).json({ error: 'Failed to fetch vendors' });
  }
});

// Get all customers (for super user dashboard)
app.get('/api/customers', async (req, res) => {
  try {
    // Use CometChat REST API to fetch users
    const response = await cometChatAPI('/users?limit=100');
    const allUsers = response.data || [];
    
    // Filter for customers only
    const customers = allUsers.filter(user => 
      user.metadata && user.metadata.role === 'customer'
    );
    
    console.log(`Found ${customers.length} customers out of ${allUsers.length} total users`);
    res.json({ customers });
  } catch (error) {
    console.error('Error fetching customers:', error.response?.data || error.message);
    
    // If CometChat API fails, return empty array for now
    // This allows the system to work even if no customers exist yet
    res.json({ customers: [], message: 'No customers found or CometChat API unavailable' });
  }
});

// Get all customer-vendor assignments (for super user dashboard)
app.get('/api/customer-vendor-assignments', async (req, res) => {
  try {
    const assignments = await getCustomerVendorMapping();
    res.json({ assignments });
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// Get active customers for a vendor (customers who have sent messages) - fetch from CometChat
app.get('/api/vendors/:vendorId/customers', async (req, res) => {
  try {
    const { vendorId } = req.params;
    
    // Get conversations for this vendor from CometChat
    const conversationsResponse = await cometChatAPI(`/users/${vendorId}/conversations?conversationType=user&limit=100`);
    
    if (conversationsResponse.data && conversationsResponse.data.data) {
      const customers = conversationsResponse.data.data
        .filter(conversation => conversation.conversationWith && conversation.conversationWith.uid !== vendorId)
        .map(conversation => ({
          id: conversation.conversationWith.uid,
          name: conversation.conversationWith.name || `Customer ${conversation.conversationWith.uid}`,
          lastActive: conversation.updatedAt,
          avatar: conversation.conversationWith.avatar || null,
          lastMessage: conversation.lastMessage ? conversation.lastMessage.text : null
        }));
      
      console.log(`Found ${customers.length} customers with conversations for vendor ${vendorId}`);
      res.json({ customers });
    } else {
      res.json({ customers: [] });
    }
  } catch (error) {
    console.error('Error getting vendor customers from CometChat:', error);
    res.status(500).json({ error: 'Failed to get vendor customers from CometChat' });
  }
});

// Manual endpoint to activate customer (for testing - simulates customer sending first message)
app.post('/api/activate-customer', async (req, res) => {
  try {
    const { customerId } = req.body;
    
    if (!customerId) {
      return res.status(400).json({ error: 'Customer ID is required' });
    }
    
    // Get customer-vendor mapping
    const mapping = await getCustomerVendorMapping();
    const assignedVendor = mapping[customerId];
    
    if (!assignedVendor) {
      return res.status(404).json({ error: 'Customer not found or not assigned to any vendor' });
    }
    
    // Mark customer as active
    const activityInfo = await markCustomerAsActive(customerId, assignedVendor);
    
    res.json({
      success: true,
      message: `Customer ${customerId} activated for vendor ${assignedVendor}`,
      customerId,
      vendorId: assignedVendor,
      activityInfo
    });
  } catch (error) {
    console.error('Error activating customer:', error);
    res.status(500).json({ error: 'Failed to activate customer' });
  }
});

// Set vendor as active (called when vendor logs into dashboard)
app.post('/api/vendor/set-active', async (req, res) => {
  try {
    const { uid } = req.body;
    
    if (!uid) {
      return res.status(400).json({ error: 'Vendor UID is required' });
    }
    
    // Mark vendor as active (you can extend this to store in database)
    console.log(`✅ Vendor ${uid} is now active`);
    
    res.json({ 
      success: true, 
      message: `Vendor ${uid} marked as active`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error setting vendor active:', error);
    res.status(500).json({ error: 'Failed to set vendor as active' });
  }
});

// Sync all vendors to CometChat
app.post('/api/sync-all-vendors', async (req, res) => {
  try {
    const vendors = await getVendors();
    const results = [];
    
    for (const vendor of vendors) {
      try {
        await ensureVendorExists(vendor);
        results.push({ uid: vendor.uid, name: vendor.name, status: 'success' });
      } catch (error) {
        results.push({ uid: vendor.uid, name: vendor.name, status: 'failed', error: error.message });
      }
    }
    
    res.json({ 
      message: 'Vendor sync completed',
      results,
      total: vendors.length,
      successful: results.filter(r => r.status === 'success').length
    });
  } catch (error) {
    console.error('Error syncing vendors:', error);
    res.status(500).json({ error: 'Failed to sync vendors' });
  }
});

// Debug endpoint to test CometChat connection
app.get('/api/debug/cometchat', async (req, res) => {
  try {
    console.log('🔍 Testing CometChat connection...');
    console.log('Environment variables:');
    console.log('- COMETCHAT_APP_ID:', process.env.COMETCHAT_APP_ID ? '✅ Set' : '❌ Missing');
    console.log('- COMETCHAT_AUTH_KEY:', process.env.COMETCHAT_AUTH_KEY ? '✅ Set' : '❌ Missing');
    console.log('- COMETCHAT_REGION:', process.env.COMETCHAT_REGION ? '✅ Set' : '❌ Missing');
    console.log('- API Base URL:', COMETCHAT_API_BASE);
    
    // Test basic API connectivity
    const response = await cometChatAPI('/users?limit=1');
    
    res.json({
      success: true,
      message: 'CometChat connection successful',
      apiBase: COMETCHAT_API_BASE,
      totalUsers: response.data?.length || 0,
      environment: {
        appId: process.env.COMETCHAT_APP_ID ? 'Set' : 'Missing',
        authKey: process.env.COMETCHAT_AUTH_KEY ? 'Set' : 'Missing',
        region: process.env.COMETCHAT_REGION ? 'Set' : 'Missing'
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      details: error.response?.data,
      apiBase: COMETCHAT_API_BASE,
      environment: {
        appId: process.env.COMETCHAT_APP_ID ? 'Set' : 'Missing',
        authKey: process.env.COMETCHAT_AUTH_KEY ? 'Set' : 'Missing',
        region: process.env.COMETCHAT_REGION ? 'Set' : 'Missing'
      }
    });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`🚀 Backend running on port ${process.env.PORT}`);
});