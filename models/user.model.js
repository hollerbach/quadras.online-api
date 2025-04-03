const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  verified: { type: Boolean, default: false },
  verifyToken: String,
  verifyTokenExpires: Date,
  resetToken: String,
  resetTokenExpires: Date,
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorSecret: { type: String }
});

module.exports = mongoose.model('User', userSchema);
