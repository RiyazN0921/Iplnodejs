const mongoose = require('mongoose')
require('dotenv').config()

const db_url =
  'mongodb+srv://riyazn886:ymdFLG8TrOlOYtD0@riyaz.aatdsty.mongodb.net/?retryWrites=true&w=majority'
const db_connection = async () => {
  console.log('inside db connection function')
  await mongoose.connect(db_url)
  console.log('database connection established ......')
}

module.exports = db_connection
