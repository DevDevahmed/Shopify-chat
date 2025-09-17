// MongoDB Vendor Model
const mongoose = require('mongoose');

const vendorSchema = new mongoose.Schema({
  // Unique identifiers
  vendorId: {
    type: String,
    unique: true,
    required: true
  },
  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true
  },
  
  // Personal Information
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  
  // Business Information
  companyName: {
    type: String,
    required: true,
    trim: true
  },
  department: {
    type: String,
    required: true,
    trim: true
  },
  businessType: {
    type: String,
    enum: ['individual', 'company', 'partnership'],
    default: 'company'
  },
  
  // Authentication
  password: {
    type: String,
    required: true
  },
  
  // Internal Vendor Management (No External APIs)
  internalVendorId: {
    type: String,
    required: true
  },
  internalRegistered: {
    type: Boolean,
    default: true
  },
  internalRegistrationDate: {
    type: Date,
    default: Date.now
  },
  
  // CometChat Integration (for chat)
  cometChatUid: {
    type: String,
    default: null
  },
  cometChatRegistered: {
    type: Boolean,
    default: false
  },
  
  // Vendor Details
  bio: {
    type: String,
    maxlength: 500
  },
  timezone: {
    type: String,
    default: 'UTC'
  },
  workingHours: {
    type: String,
    default: '9:00 AM - 5:00 PM'
  },
  
  // Status
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'suspended'],
    default: 'pending'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  
  // Verification
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  emailVerificationToken: {
    type: String,
    default: null
  },
  
  // Business Documents (for ShipTurtle KYC)
  businessDocuments: {
    gstNumber: String,
    panNumber: String,
    businessLicense: String,
    bankAccountDetails: {
      accountNumber: String,
      ifscCode: String,
      bankName: String,
      accountHolderName: String
    }
  },
  
  // Address Information
  businessAddress: {
    street: String,
    city: String,
    state: String,
    country: String,
    zipCode: String
  },
  
  // Vendor Profile & Business Settings
  vendorProfile: {
    storeUrl: String,
    commission: {
      type: Number,
      default: 10
    },
    paymentMethod: {
      type: String,
      enum: ['bank_transfer', 'paypal', 'stripe', 'other'],
      default: 'bank_transfer'
    },
    shippingSettings: {
      freeShippingThreshold: {
        type: Number,
        default: 500
      },
      shippingCharges: {
        type: Number,
        default: 50
      }
    }
  },
  
  // Admin Management
  approvedAt: {
    type: Date,
    default: null
  },
  approvedBy: {
    type: String,
    default: null
  },
  rejectedAt: {
    type: Date,
    default: null
  },
  rejectedBy: {
    type: String,
    default: null
  },
  rejectionReason: {
    type: String,
    default: null
  },
  lastLoginAt: {
    type: Date,
    default: null
  },
  statusUpdatedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Indexes for better performance (removed duplicates to fix warnings)
vendorSchema.index({ status: 1 });
vendorSchema.index({ department: 1 });

// Virtual for full name
vendorSchema.virtual('fullName').get(function() {
  return `${this.firstName} ${this.lastName}`;
});

// Methods
vendorSchema.methods.toJSON = function() {
  const vendor = this.toObject();
  delete vendor.password;
  delete vendor.emailVerificationToken;
  return vendor;
};

module.exports = mongoose.model('Vendor', vendorSchema);
