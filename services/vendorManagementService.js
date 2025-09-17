// Self-Contained Vendor Management Service (No External APIs)
const Vendor = require('../models/Vendor');
const bcrypt = require('bcryptjs');

class VendorManagementService {
  constructor() {
    console.log('🏪 Vendor Management Service initialized (No external APIs required)');
  }

  // Register vendor in our own system
  async registerVendor(vendorData) {
    try {
      // Generate unique vendor ID
      const timestamp = Date.now();
      const randomString = Math.random().toString(36).substring(2, 8);
      const vendorId = `vendor_${timestamp}_${randomString}`;

      // Create vendor in database
      const newVendor = new Vendor({
        vendorId,
        email: vendorData.email.toLowerCase(),
        firstName: vendorData.firstName,
        lastName: vendorData.lastName,
        companyName: vendorData.companyName,
        department: vendorData.department,
        phone: vendorData.phone || '',
        timezone: vendorData.timezone || 'UTC',
        workingHours: vendorData.workingHours || '9:00 AM - 5:00 PM',
        bio: vendorData.bio || '',
        password: vendorData.hashedPassword,
        businessAddress: vendorData.businessAddress,
        businessDocuments: vendorData.businessDocuments,
        status: 'pending', // Requires admin approval
        
        // Our own vendor management (no external API)
        internalVendorId: vendorId,
        internalRegistered: true,
        internalRegistrationDate: new Date(),
        
        // Commission and settings
        vendorProfile: {
          commission: vendorData.commission || 10,
          paymentMethod: vendorData.paymentMethod || 'bank_transfer',
          shippingSettings: {
            freeShippingThreshold: vendorData.freeShippingThreshold || 500,
            shippingCharges: vendorData.shippingCharges || 50
          }
        }
      });

      await newVendor.save();

      return {
        success: true,
        vendorId: vendorId,
        message: 'Vendor registered successfully in internal system',
        vendor: newVendor
      };

    } catch (error) {
      console.error('❌ Internal vendor registration failed:', error.message);
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get vendor by ID
  async getVendor(vendorId) {
    try {
      const vendor = await Vendor.findOne({ vendorId });
      if (!vendor) {
        return {
          success: false,
          error: 'Vendor not found'
        };
      }

      return {
        success: true,
        vendor: vendor
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get all vendors with filtering
  async getAllVendors(filters = {}) {
    try {
      let query = {};
      
      if (filters.status) {
        query.status = filters.status;
      }
      
      if (filters.department) {
        query.department = filters.department;
      }
      
      if (filters.isActive !== undefined) {
        query.isActive = filters.isActive;
      }

      const vendors = await Vendor.find(query).sort({ createdAt: -1 });
      
      return {
        success: true,
        vendors: vendors,
        total: vendors.length
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get available vendors for customer chat
  async getAvailableVendors() {
    try {
      const vendors = await Vendor.find({
        status: 'approved',
        isActive: true,
        cometChatRegistered: true
      }).select('vendorId firstName lastName companyName department bio workingHours timezone status');

      const availableVendors = vendors.map(vendor => ({
        uid: vendor.cometChatUid || vendor.vendorId,
        name: `${vendor.firstName} ${vendor.lastName}`,
        email: vendor.email,
        status: vendor.status || 'online',
        department: vendor.department,
        companyName: vendor.companyName,
        bio: vendor.bio,
        workingHours: vendor.workingHours,
        timezone: vendor.timezone
      }));

      return {
        success: true,
        vendors: availableVendors,
        total: availableVendors.length
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Approve vendor
  async approveVendor(vendorId, approvedBy = 'admin') {
    try {
      const vendor = await Vendor.findOne({ vendorId });
      if (!vendor) {
        return {
          success: false,
          error: 'Vendor not found'
        };
      }

      vendor.status = 'approved';
      vendor.approvedAt = new Date();
      vendor.approvedBy = approvedBy;
      
      await vendor.save();

      return {
        success: true,
        message: 'Vendor approved successfully',
        vendor: vendor
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Reject vendor
  async rejectVendor(vendorId, reason = '', rejectedBy = 'admin') {
    try {
      const vendor = await Vendor.findOne({ vendorId });
      if (!vendor) {
        return {
          success: false,
          error: 'Vendor not found'
        };
      }

      vendor.status = 'rejected';
      vendor.rejectedAt = new Date();
      vendor.rejectedBy = rejectedBy;
      vendor.rejectionReason = reason;
      
      await vendor.save();

      return {
        success: true,
        message: 'Vendor rejected',
        vendor: vendor
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Update vendor profile
  async updateVendor(vendorId, updateData) {
    try {
      const vendor = await Vendor.findOne({ vendorId });
      if (!vendor) {
        return {
          success: false,
          error: 'Vendor not found'
        };
      }

      // Update allowed fields
      const allowedFields = [
        'firstName', 'lastName', 'phone', 'bio', 'timezone', 
        'workingHours', 'businessAddress', 'vendorProfile'
      ];

      allowedFields.forEach(field => {
        if (updateData[field] !== undefined) {
          vendor[field] = updateData[field];
        }
      });

      await vendor.save();

      return {
        success: true,
        message: 'Vendor updated successfully',
        vendor: vendor
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Suspend/Activate vendor
  async toggleVendorStatus(vendorId, isActive) {
    try {
      const vendor = await Vendor.findOne({ vendorId });
      if (!vendor) {
        return {
          success: false,
          error: 'Vendor not found'
        };
      }

      vendor.isActive = isActive;
      vendor.statusUpdatedAt = new Date();
      
      await vendor.save();

      return {
        success: true,
        message: `Vendor ${isActive ? 'activated' : 'suspended'} successfully`,
        vendor: vendor
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Get vendor statistics
  async getVendorStats() {
    try {
      const totalVendors = await Vendor.countDocuments();
      const pendingVendors = await Vendor.countDocuments({ status: 'pending' });
      const approvedVendors = await Vendor.countDocuments({ status: 'approved' });
      const rejectedVendors = await Vendor.countDocuments({ status: 'rejected' });
      const activeVendors = await Vendor.countDocuments({ isActive: true });
      const cometChatRegistered = await Vendor.countDocuments({ cometChatRegistered: true });

      // Get vendors by department
      const vendorsByDepartment = await Vendor.aggregate([
        { $group: { _id: '$department', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);

      return {
        success: true,
        stats: {
          total: totalVendors,
          pending: pendingVendors,
          approved: approvedVendors,
          rejected: rejectedVendors,
          active: activeVendors,
          cometChatRegistered: cometChatRegistered,
          byDepartment: vendorsByDepartment
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Vendor login authentication
  async authenticateVendor(email, password) {
    try {
      const vendor = await Vendor.findOne({ 
        email: email.toLowerCase(),
        status: 'approved',
        isActive: true
      });

      if (!vendor) {
        return {
          success: false,
          error: 'Invalid credentials or vendor not approved'
        };
      }

      const isPasswordValid = await bcrypt.compare(password, vendor.password);
      if (!isPasswordValid) {
        return {
          success: false,
          error: 'Invalid credentials'
        };
      }

      // Update last login
      vendor.lastLoginAt = new Date();
      await vendor.save();

      return {
        success: true,
        message: 'Authentication successful',
        vendor: {
          vendorId: vendor.vendorId,
          email: vendor.email,
          name: `${vendor.firstName} ${vendor.lastName}`,
          department: vendor.department,
          companyName: vendor.companyName,
          cometChatUid: vendor.cometChatUid
        }
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  // Search vendors
  async searchVendors(searchTerm, filters = {}) {
    try {
      let query = {
        $or: [
          { firstName: { $regex: searchTerm, $options: 'i' } },
          { lastName: { $regex: searchTerm, $options: 'i' } },
          { email: { $regex: searchTerm, $options: 'i' } },
          { companyName: { $regex: searchTerm, $options: 'i' } },
          { department: { $regex: searchTerm, $options: 'i' } }
        ]
      };

      // Apply additional filters
      if (filters.status) {
        query.status = filters.status;
      }
      
      if (filters.department) {
        query.department = filters.department;
      }

      const vendors = await Vendor.find(query).sort({ createdAt: -1 });

      return {
        success: true,
        vendors: vendors,
        total: vendors.length
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}

module.exports = new VendorManagementService();
