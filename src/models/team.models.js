const mongoose = require('mongoose')

const { Schema } = require('mongoose')

const TeamSchema = new Schema({
  teamName: {
    type: String
  },
  city: {
    type: String
  },
  color: {
    type: String
  },
  size: {
    type: Number
  },
  owner: {
    type: String
  },
  players: [
    {
      type: mongoose.SchemaTypes.ObjectId,
      ref: 'Player',
      duplicate: false
    }
  ],
  Captain: {
    type: String
  },
  viceCaptain: {
    type: String
  }
})

const Team = mongoose.model('Team', TeamSchema)

module.exports = Team
