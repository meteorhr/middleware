import mongoose from 'mongoose';
import Config from '../config/mongodb.js'; 

const _db = await mongoose.createConnection(
  Config.fin,
  Config.option
);

const _schema = new mongoose.Schema({
  createdAt: {type: Date },
  updatedAt: {type: Date }, 
  code: {type: String },
  name: {type: String},
  symbol: {type: String},
  orderIndex: {type: Number}
});

_schema.pre('save', (next) => {
  return next();
});
  
const FinCurrencies = _db.model('Currency', _schema);
export default FinCurrencies 