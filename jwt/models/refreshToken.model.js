import mongoose from 'mongoose';
import Config from '../config/mongodb.js';

const _db = await mongoose.createConnection(
  Config.ident,
  Config.option
);

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
  created_at: {
    type: Date,
    default: new Date()
  },
  updated_at: {
    type: Date,
    default: new Date()
  }
})

RefreshTokenSchema.pre('save', function(next){
  return next();
})

const RefreshToken = _db.model('RefreshToken', RefreshTokenSchema);

export default RefreshToken