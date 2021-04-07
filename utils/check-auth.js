
const jwt = require('jsonwebtoken')
const { SECRET } = require('../config')
const { AuthenticationError } = require('apollo-server')

module.exports = (context) => {
  // context = {...headers}
  const authHeader = context.req.headers.authorization
  if (authHeader) {
    // bearer ...token
    const token = authHeader.split(`Bearer `)[1]
    if (token) {
      try {
        const user = jwt.verify(token, SECRET)
        return user
      } catch (error) {
        throw new AuthenticationError('Invalid/Expires token')
      }
    }
    throw new Error("Authentication token must be 'Bearer [token]")
  }
  throw new Error('Authorization header must be provided')
}