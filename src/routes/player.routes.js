const express = require('express')
const PlayerController = require('../controllers/player.controller')

const PlayerRouter = express.Router()

PlayerRouter.post('/player', PlayerController.createPlayer)

PlayerRouter.get('/player/:playerId', PlayerController.getPlayerDetail)

PlayerRouter.get('/player', PlayerController.getAllPlayer)

PlayerRouter.patch('/player/:playerId', PlayerController.updatePlayerInfo)

PlayerRouter.delete('/player/:playerId', PlayerController.deletePlayer)

PlayerRouter.patch('/team/:teamId/player/:playerId', PlayerController.addPlayer)

module.exports = PlayerRouter
