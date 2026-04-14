import mongoose from 'mongoose';
import { identConnection } from '../config/mongodb.js';

const RefreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  fcm: {
    type: String
  },
  deviceId: {
    type: String,
    required: true,
  },
  userId: {
    type: String,
    required: true,
    ref: 'User'
  },
  expired_at: {
    type: Date
  },
  // Soft-rotation fields: when a token is rotated, usedAt is set instead of
  // deleting the document.  replacedBy points to the new token so that client
  // retries (after 504 / ERR_FAILED) can still resolve to the replacement.
  usedAt: {
    type: Date,
    default: null,
  },
  replacedBy: {
    type: String,
    default: null,
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  updated_at: {
    type: Date,
    default: Date.now
  }
});

// Auto-clean used tokens after 5 minutes.
// Only applies to documents where usedAt is a Date (i.e. already rotated).
RefreshTokenSchema.index(
  { usedAt: 1 },
  { expireAfterSeconds: 300, partialFilterExpression: { usedAt: { $type: 'date' } } },
);

RefreshTokenSchema.pre('save', function(next) {
  this.updated_at = new Date();
  return next();
});

const RefreshToken = identConnection.model('RefreshToken', RefreshTokenSchema);

export default RefreshToken;
