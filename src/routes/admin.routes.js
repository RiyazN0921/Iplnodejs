const express = require('express')
const AdminController = require('../controllers/admin.controller')
const jwt = require('jsonwebtoken')

const AdminRouter = express.Router()

require('dotenv').config()
const Jwt_secrete_key = process.env.JWT_SECRETE_KEY

const verifyToken = async (req, res, next) => {
  const token = req.get('Authorization')
  if (token) {
    const payload = await jwt.verify(token.split(' ')[1], Jwt_secrete_key)
    if (payload) {
      next()
    } else {
      res.json({
        message: 'User is not allowed'
      })
    }
  } else {
    res.json({
      message: 'token is not valid'
    })
  }
}

AdminRouter.post('/admin/signup', AdminController.signup)

// AdminRouter.post('/admin/login', AdminController.login)

AdminRouter.post('/admin/login', AdminController.login)

AdminRouter.get('/admin/signup', verifyToken, AdminController.getAllAdmins)
AdminRouter.get('/request/otp', verifyToken, AdminController.requestAndSentOTP)
AdminRouter.post('/verify/otp', verifyToken, AdminController.verifyOTP)

module.exports = AdminRouter
