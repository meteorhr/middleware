import mongoose from 'mongoose';
import Config from '../config/mongodb.js';

const _db = await mongoose.createConnection(
  Config.ident,
  Config.option
);

const companySchema = new mongoose.Schema({
  name: {type: String, unique: [true, "ident.unique.company"], required: true},
  currency: {type: String},
  address: {
    country: {type: String},
    state: {type: String},
    city: {type: String},
    index: {type: String},
    street: {type: String},
    house: {type: String},
    housing: {type: String},
    apartment: {type: String},
    pos: {
      lat: {type: Number},
      lng: {type: Number}
    }
  },
})

companySchema.pre('save', (next) => {
  return next()
});



const Company = _db.model('Company', companySchema);

export default Company