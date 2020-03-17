const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const Users = require("../users/users-model")

function restrict() {
	const authError = {
		message: "Invalid credentials",
	}
	
	return async (req, res, next) => {
		try {
			// the JWT is being sent automatically from the cookie jar,
			// so this uses the cookie-parser middleware to get the value.
			const { token } = req.cookies
			if (!token) {
				return res.status(401).json(authError)
			}

			jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
				if (err) {
					// something isn't right with the token. maybe it's
					// expired, or altered in some way. not authorized.
					return res.status(401).json(authError)
				}

				// once we attach to req, the decoded token values can be
				// accessed in any other middleware
				req.token = decoded
				console.log(decoded)

				next()
			})
		} catch(err) {
			next(err)
		}
	}
}

module.exports = restrict