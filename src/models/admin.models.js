const mongoose = require('mongoose')

const { Schema } = require('mongoose')

const AdminSchema = new Schema({
  firstName: {
    type: String,
    required: true
  },
  lastName: {
    type: String
  },
  Email: {
    type: String,
    required: true,
    duplicate: false
  },
  password: {
    type: String,
    required: true
  },
  Contact: {
    type: Number,
    duplicate: false
  },
  verified: {
    type: Boolean,
    default: false
  },
  otp: {
    type: String
  }
})

const Admin = mongoose.model('Admin', AdminSchema)

module.exports = Admin
