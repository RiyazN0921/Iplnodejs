const Team = require('../models/team.models')

const teamTest = async (req, res) => {
  res.json({ Message: 'This is a test message from team' })
}

const createTeam = async (req, res) => {
  const team = req.body

  const response = await Team.create(team)

  res.json({
    message: response
  })
}

const getAllTeams = async (req, res) => {
  const response = await Team.find().populate('players')

  res.json({
    message: response
  })
}

const getATeam = async (req, res) => {
  const teamId = req.params.teamId

  const response = await Team.findById(teamId)

  res.json({
    message: response
  })
}
//2- Build an API for updating a team info.
const updateATeam = async (req, res) => {
  try {
    const teams = await Team.findById(req.params.teamId)
    if (teams) {
      teams.color = req.body.color || teams.color
      teams.size = req.body.size || teams.size

      await teams.save()
      res.json({
        message: teams
      })
    } else {
      res.json({
        message: 'teamId is not correct'
      })
    }
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}
//1- Build an API for deleting a team.
const deleteATeam = async (req, res) => {
  try {
    const teams = await Team.findById(req.params.teamId)
    if (teams) {
      const team = await teams.deleteOne({ _id: req.params.teamId })
      res.json({
        message: teams
      })
    } else {
      res.json({
        message: 'TeamId is not correct'
      })
    }
  } catch (error) {
    res.json({
      message: 'internal server error'
    })
  }
}
//3 - Build an API for to a get team with all details along with list of players.

const getATeamWithId = async (req, res) => {
  try {
    const teams = await Team.findById(req.params.teamId).populate('players')
    if (teams) {
      res.json({
        message: teams
      })
    } else {
      res.json({
        message: ' Id is not valid'
      })
    }
  } catch (error) {
    res.json({
      message: ' Internal server error'
    })
  }
}
/**
 * req.body
 * req.params
 * req.query
 */

module.exports = {
  teamTest,
  createTeam,
  getAllTeams,
  getATeam,
  updateATeam,
  deleteATeam,
  getATeamWithId
}
