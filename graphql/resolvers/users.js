
const jwt = require('jsonwebtoken')
const { SECRET } = require('../../config')
const User = require('../../models/User')
const bcrypt = require('bcryptjs')
const { UserInputError } = require('apollo-server')
const { validateRegister, validateLogin } = require('../../utils/validators')

const generateToken = (user) => (
  jwt.sign({
    id: user.id,
    email: user.email,
    username: user.username
  }, SECRET, { expiresIn: '1h' })
)

module.exports = {
  Mutation: {
    async login(_, { username, password }) {
      const { errors, valid } = validateLogin(username, password)

      if (!valid) {
        throw new UserInputError('Errors', { errors })
      }

      const user = await User.findOne({ username })

      if (!user) {
        errors.general = 'User not found'
        throw new UserInputError('Wrong credentials', { errors })
      }

      const match = bcrypt.compareSync(password, user.password)
      if (!match) {
        errors.general = 'User not found'
        throw new UserInputError('Wrong credentials', { errors })
      }

      const token = generateToken(user)

      return {
        ...user._doc,
        id: user._id,
        token
      }
    },
    register: async (_, { registerInput:
      { username, email, password, confirmPassword }
    }) => {
      // TODO: validate user data
      const { valid, errors } = validateRegister(username, email, password, confirmPassword)
      if (!valid) {
        throw new UserInputError('Errors', { errors })
      }
      // TODO: Make sure user doesn't already exist
      const user = await User.findOne({ username })
      if (user) {
        throw new UserInputError('Username is taken', {
          erros: {
            username: 'This username is taken'
          }
        })
      }
      // TODO: hash password and create an auth token
      const salt = bcrypt.genSaltSync(10)
      password = bcrypt.hashSync(password, salt)

      const newUser = new User({
        email,
        username,
        password,
        createdAt: new Date().toISOString()
      })

      const res = await newUser.save()

      const token = generateToken(res)

      return {
        ...res._doc,
        id: res._id,
        token
      }
    }
  }
}