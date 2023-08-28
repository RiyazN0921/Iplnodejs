const express = require('express')
const TeamController = require('../controllers/team.controller')

const TeamRouter = express.Router()

TeamRouter.post('/team', TeamController.createTeam)

TeamRouter.get('/team', TeamController.getAllTeams)

TeamRouter.get('/team/:teamId', TeamController.getATeam)

TeamRouter.patch('/team/:teamId', TeamController.updateATeam)

TeamRouter.delete('/team/:teamId', TeamController.deleteATeam)

TeamRouter.get('/detail/:teamId', TeamController.getATeamWithId)

module.exports = TeamRouter
