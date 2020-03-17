const express = require("express")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const Users = require("../users/users-model")
const restrict = require("../middleware/restrict")

const router = express.Router()

router.post("/register", async (req, res, next) => {
	try {
		const { username } = req.body
		const user = await Users.findBy({ username }).first()

		if (user) {
			return res.status(409).json({
				message: "Username is already taken",
			})
		}

		res.status(201).json(await Users.add(req.body))
	} catch(err) {
		next(err)
	}
})

router.post("/login", async (req, res, next) => {
	const authError = {
		message: "Invalid Credentials",
	}

	try {
		const { username, password } = req.body

		const user = await Users.findBy({ username }).first()
		if (!user) {
			return res.status(401).json(authError)
		}

		const passwordValid = await bcrypt.compare(password, user.password)
		if (!passwordValid) {
			return res.status(401).json(authError)
		}

		// This data gets encoded into our JWT for use in later requests
		const payload = {
			userId: user.id,
			userRole: "admin", // this would normally come from a database
		}
		
		// generate a new JWT and cryptographically sign
		const token = jwt.sign(payload, process.env.JWT_SECRET)

		// sends a Set-Cookie header with the value of the token
		res.cookie("token", token)
		
		res.json({
			message: `Welcome ${user.username}!`,
		})
	} catch(err) {
		next(err)
	}
})

module.exports = router