// ShipTurtle API Integration Service
const axios = require('axios');

class ShipTurtleService {
  constructor() {
    this.baseURL = process.env.SHIPTURTLE_API_URL || 'https://api.shipturtle.com';
    this.apiKey = process.env.SHIPTURTLE_API_KEY;
    this.storeId = process.env.SHIPTURTLE_STORE_ID;
    
    if (!this.apiKey || !this.storeId) {
      console.warn('⚠️ ShipTurtle API credentials not configured');
    }
  }

  // Register vendor in ShipTurtle Multi-Vendor platform
  async registerVendor(vendorData) {
    try {
      const payload = {
        vendor: {
          email: vendorData.email,
          first_name: vendorData.firstName,
          last_name: vendorData.lastName,
          company_name: vendorData.companyName,
          phone: vendorData.phone,
          department: vendorData.department,
          business_type: vendorData.businessType || 'company',
          
          // Business Address
          business_address: {
            street: vendorData.businessAddress?.street,
            city: vendorData.businessAddress?.city,
            state: vendorData.businessAddress?.state,
            country: vendorData.businessAddress?.country || 'IN',
            zip_code: vendorData.businessAddress?.zipCode
          },
          
          // Business Documents
          business_documents: {
            gst_number: vendorData.businessDocuments?.gstNumber,
            pan_number: vendorData.businessDocuments?.panNumber,
            business_license: vendorData.businessDocuments?.businessLicense
          },
          
          // Bank Details
          bank_details: {
            account_number: vendorData.businessDocuments?.bankAccountDetails?.accountNumber,
            ifsc_code: vendorData.businessDocuments?.bankAccountDetails?.ifscCode,
            bank_name: vendorData.businessDocuments?.bankAccountDetails?.bankName,
            account_holder_name: vendorData.businessDocuments?.bankAccountDetails?.accountHolderName
          },
          
          // Store Settings
          store_settings: {
            commission_rate: vendorData.shipTurtleProfile?.commission || 10,
            free_shipping_threshold: vendorData.shipTurtleProfile?.shippingSettings?.freeShippingThreshold || 500,
            shipping_charges: vendorData.shipTurtleProfile?.shippingSettings?.shippingCharges || 50
          },
          
          // Status
          status: 'pending_approval',
          auto_approve: false // Set to true if you want auto-approval
        }
      };

      const response = await axios.post(`${this.baseURL}/v1/stores/${this.storeId}/vendors`, payload, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });

      if (response.data && response.data.vendor) {
        return {
          success: true,
          shipTurtleVendorId: response.data.vendor.id,
          vendorData: response.data.vendor,
          message: 'Vendor registered successfully in ShipTurtle'
        };
      }

      throw new Error('Invalid response from ShipTurtle API');

    } catch (error) {
      console.error('❌ ShipTurtle vendor registration failed:', error.response?.data || error.message);
      
      return {
        success: false,
        error: error.response?.data?.message || error.message,
        statusCode: error.response?.status
      };
    }
  }

  // Get vendor details from ShipTurtle
  async getVendor(shipTurtleVendorId) {
    try {
      const response = await axios.get(`${this.baseURL}/v1/stores/${this.storeId}/vendors/${shipTurtleVendorId}`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Accept': 'application/json'
        }
      });

      return {
        success: true,
        vendor: response.data.vendor
      };
    } catch (error) {
      console.error('❌ Failed to fetch vendor from ShipTurtle:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Update vendor in ShipTurtle
  async updateVendor(shipTurtleVendorId, updateData) {
    try {
      const response = await axios.put(`${this.baseURL}/v1/stores/${this.storeId}/vendors/${shipTurtleVendorId}`, {
        vendor: updateData
      }, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }
      });

      return {
        success: true,
        vendor: response.data.vendor
      };
    } catch (error) {
      console.error('❌ Failed to update vendor in ShipTurtle:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Approve vendor in ShipTurtle
  async approveVendor(shipTurtleVendorId) {
    try {
      const response = await axios.post(`${this.baseURL}/v1/stores/${this.storeId}/vendors/${shipTurtleVendorId}/approve`, {}, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Accept': 'application/json'
        }
      });

      return {
        success: true,
        message: 'Vendor approved successfully'
      };
    } catch (error) {
      console.error('❌ Failed to approve vendor in ShipTurtle:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Get all vendors from ShipTurtle
  async getAllVendors() {
    try {
      const response = await axios.get(`${this.baseURL}/v1/stores/${this.storeId}/vendors`, {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Accept': 'application/json'
        }
      });

      return {
        success: true,
        vendors: response.data.vendors || []
      };
    } catch (error) {
      console.error('❌ Failed to fetch vendors from ShipTurtle:', error.response?.data || error.message);
      return {
        success: false,
        error: error.response?.data?.message || error.message
      };
    }
  }

  // Sync vendor status from ShipTurtle
  async syncVendorStatus(shipTurtleVendorId) {
    const result = await this.getVendor(shipTurtleVendorId);
    if (result.success) {
      return {
        success: true,
        status: result.vendor.status,
        isApproved: result.vendor.status === 'approved',
        lastSyncAt: new Date()
      };
    }
    return result;
  }
}

module.exports = new ShipTurtleService();
