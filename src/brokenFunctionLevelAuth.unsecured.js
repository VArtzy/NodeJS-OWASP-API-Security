import express from 'express'
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser'
import bcrypt from 'bcrypt'
import rateLimit from 'express-rate-limit'
import { randomUUID } from 'crypto'

const app = express()
app.use(bodyParser.json())

const users = {}
const invites = []

const SECRET_KEY = randomUUID() // Generate a unique secret key on each server start
const SALT_ROUNDS = 10

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login request per window
    message: 'Too many login attempts, please try again later'
})

const passwordCheck = (password) => {
    if (password.length < 8) return 'Password must be at least 8 characters'
    if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase character'
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase character'
    if (!/[!@$%^&*.?]/.test(password)) return 'Password must contain at least one special character'
    return null
}

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'Token is required' })

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' })
        req.username = decoded.username
        next()
    })
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' })
    }
    if (users[username]) {
        return res.status(400).json({ error: 'User already exists' })
    }
    const passwordError = passwordCheck(password)
    if (passwordError) {
        return res.status(400).json({ error: passwordError })
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)
    users[username] = { password: hashedPassword }
    res.status(201).json({ message: 'User created' })
})

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' })
    }

    const user = users[username]
    if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' })
    }

    const match = await bcrypt.compare(password, user.password)
    if (match) {
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' })
        res.json({ token })
    } else {
        res.status(401).json({ error: 'Invalid username or password' })
    }
})

// Vulnerable invite endpoint (no function level authorization)
app.post('/api/invites/new', verifyToken, (req, res) => {
    const { username } = req.body
    const newInvite = { username, date: new Date() }
    invites.push(newInvite)
    res.status(201).json(newInvite)
})

// Vulnerable get all users endpoint (no function level authorization)
app.get('/api/users/all', verifyToken, (_, res) => {
    res.json(users)
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
