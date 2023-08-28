const { response } = require('express')
const Player = require('../models/player.model')
const Team = require('../models/team.models')

const playerTest = async (req, res) => {
  res.json({ Message: 'This is a test message from player' })
}

const createPlayer = async (req, res) => {
  const player = req.body

  const response = await Player.create(player)

  res.json({ Message: response })
}

const getAllPlayer = async (req, res) => {
  const response = await Player.find()

  res.json({ Message: response })
}

const getPlayerDetail = async (req, res) => {
  try {
    const response = await Player.findById(req.params.playerId)

    if (response) {
      res.json({
        Message: response
      })
    } else {
      res.json({
        Message: 'Player Id is not correct'
      })
    }
  } catch (error) {
    res.json({
      Message: 'Internal Server Error'
    })
  }
}

const updatePlayerInfo = async (req, res) => {
  try {
    const player = await Player.findById(req.params.playerId)
    if (player) {
      player.age = req.body.age || player.age
      player.money = req.body.money || player.money
      player.totalMatches = req.body.totalMatches || player.totalMatches

      await player.save()
      res.json({
        message: player
      })
    } else {
      res.json({
        message: 'player Id is not correct'
      })
    }
  } catch (error) {
    res.json({
      message: 'player Id is not correct'
    })
  }
}

const deletePlayer = async (req, res) => {
  try {
    const player = await Player.findById(req.params.playerId)
    if (player) {
      const players = await player.deleteOne({ _id: req.params.playerId })
      res.json({
        message: players
      })
    } else {
      res.json({
        message: 'PlayerId is not correct'
      })
    }
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}

const addPlayer = async (req, res) => {
  try {
    const team = await Team.findById(req.params.teamId)
    if (Team) {
      const player = await Player.findById(req.params.playerId)
      if (player) {
        team.players.push(player._id)
        await team.save()
        res.json({
          message: 'Player Added sucuessfully'
        })
      } else {
        res.json({
          message: 'teamId is correct but player not found'
        })
      }
    } else {
      res.json({
        message: 'teamId not found'
      })
    }
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}

module.exports = {
  playerTest,
  createPlayer,
  getAllPlayer,
  getPlayerDetail,
  updatePlayerInfo,
  deletePlayer,
  addPlayer
}
