const Admin = require('../models/admin.models')
const jwt = require('jsonwebtoken')
require('dotenv').config()
const Jwt_secrete_key = process.env.JWT_SECRETE_KEY
const {
  generateSalt,
  hashPassword,
  decodePassword
} = require('../services/password.services')

const signup = async (req, res) => {
  try {
    const users = {
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      Email: req.body.Email,
      contact: req.body.contact
    }

    const salt = generateSalt()
    users.password = hashPassword(req.body.password, salt)
    const user = await Admin.create(users)
    res.json({
      message: user
    })
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}

const getAllAdmins = async (req, res) => {
  try {
    const users = await Admin.find()
    res.json({
      message: users
    })
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}

const login = async (req, res) => {
  const checkuser = await Admin.findOne({ Email: req.body.Email })
  if (checkuser) {
    const checkPassword = decodePassword(req.body.password, checkuser.password)

    if (checkPassword) {
      const email = checkuser.Email
      const token = jwt.sign({ email }, Jwt_secrete_key, { expiresIn: '5d' })
      return res.json({
        Message: 'You are now logged in',
        Token: token
      })
    } else {
      return res.json({ Message: 'Your password is incorrect' })
    }
  } else {
    return res.json({ Message: 'user/emailId not found' })
  }
}

const requestAndSentOTP = async (req, res) => {
  const checkUser = await Admin.findOne({ email: req.email })

  /// generating otp and saving to admin otp attribute or key field
  const generateOtp = Math.floor(10000 + Math.random() * 900000)
  checkUser.otp = generateOtp
  await checkUser.save()

  /// use twillio to send otp to admins

  const accountSid = 'AC37ffa1a10905d55d67becb5145bcf72b'
  const authToken = '09ad831af5f7f33ae65e092c048b1549'
  const client = require('twilio')(accountSid, authToken)
  const response = await client.messages.create({
    body: `Your OTP ${generateOtp} `,
    from: '+15076827906',
    to: '+916362618604'
  })

  res.json({ Message: 'OTP SENT TO YOUR PHONE' })
}

const verifyOTP = async (req, res) => {
  const checkUser = await Admin.findOne({ email: req.email })

  if (checkUser) {
    /// check if user given otp and otp saved in database same or not
    if (checkUser.otp == req.body.otp) {
      /// if both otp matches verifed = true
      checkUser.verified = true
      await checkUser.save()

      return res.json({ Message: 'You are verified now' })
    } else {
      /// if both otp not matches verifed = false
      return res.json({ Message: 'Your OTP is Wrong' })
    }
  } else {
    return res.json({ Messgage: 'User not found' })
  }
}

module.exports = {
  signup,
  getAllAdmins,
  login,
  requestAndSentOTP,
  verifyOTP
}
