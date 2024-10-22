import express from 'express'
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser'
import bcrypt from 'bcrypt'
import rateLimit from 'express-rate-limit'
import { randomUUID } from 'crypto'
import { buildSchema } from 'graphql'
import sharp from 'sharp'
import { graphqlHTTP } from 'express-graphql'
import { URL } from 'url'
import axios from 'axios'
import helmet from 'helmet'
import cors from 'cors'
// import { readFileSync } from 'fs'
import swaggerUi from 'swagger-ui-express'
import sqlite3 from 'sqlite3'
import https from 'https'
import swaggerDocument from './swagger.json' with { type: 'json' }
import { body, validationResult } from 'express-validator'

const app = express()
app.use(bodyParser.json())
app.use(helmet()) // Adds various security headers
app.use(cors({
    origin: 'https://example.com',
    methods: ['GET', 'POST']
})) // cors is enabled only for example.com meaning that only requests from example.com are allowed
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

const revenueData = {
    'nike': { revenue: 10000, owner: 'john' },
    'apple': { revenue: 20000, owner: 'tim' },
    'toyota': { revenue: 30000, owner: 'farrel' }
}
const users = {
    "admin": { password: 'test', role: 'admin' }
}
const bookings = {
    1: { id: 1, approved: false, comment: '', price: 100 },
}
const invites = []
let product = {
    id: 1,
    name: 'Limited Edition Gaming Console',
    price: 399.99,
    stock: 100
}
const purchaseHistory = new Map()
const apiVersions = {
    'v1': '1.0.0',
    'v2': '2.0.0-beta'
}
const db = new sqlite3.Database(':memory:')
db.run('CREATE TABLE businesses (id INTEGER PRIMARY KEY, name TEXT, address TEXT, enriched_data TEXT)')
const httpsAgent = new https.Agent({ timeout: 5000 })

const SECRET_KEY = randomUUID() // Generate a unique secret key on each server start
const SALT_ROUNDS = 10
const DEFAULT_ROLE = 'user'
const ALLOWED_DOMAINS = ['example.com', 'placehold.co']
const ALLOWED_SCHEMES = ['https']
const ALLOWED_REDIRECTS = ['api1.example.com', 'api2.example.com']

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login request per window
    message: 'Too many login attempts, please try again later'
})

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
})

const monetizeLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 3, // Limit each IP to 1 request per hour
    message: 'You have exceeded the hourly limit for this action'
})

const graphqlBatchLimit = (limit) => (req, res, next) => {
    if (Array.isArray(req.body)) {
        if (req.body.length > limit) {
            return res.status(400).json({ errors: [{ message: `Batch operations are limited to ${limit} per request.` }] })
        }
    }
    next()
}

const isAdmin = (req, res, next) => {
    if (req.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admin role required.' })
    }
    next()
}

const purchaseLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000, // 1 day
    max: 3, // Limit each IP to 3 purchase per day
    message: 'You have exceeded the daily purchase limit'
})

const isUrlAllowed = (url) => {
    try {
        const parsedUrl = new URL(url)
        return ALLOWED_SCHEMES.includes(parsedUrl.protocol.slice(0, -1)) && ALLOWED_DOMAINS.includes(parsedUrl.hostname)
    } catch (error) {
        return false
    }
}

const versionCheck = (req, res, next) => {
    const version = req.path.split('/')[2]
    if (!apiVersions[version]) {
        return res.status(400).json({ error: 'Invalid API version' })
    }
    next()
}

const processThumbnail = async (base64Image) => {
    if (base64Image > 1000000) throw new Error('Image is too large')

    const buff = Buffer.from(base64Image, 'base64')
    await sharp(buff).resize(200, 200).toBuffer()
    return 'http://example.com/thumbnail.jpg'
}

const schema = buildSchema(`
    type Mutation {
        uploadPic(name: String!, base64Pic: String!): PicUploadResult
    }

    type PicUploadResult {
        url: String
    }

    type Query {
        dummy: String
    }
`)

const root = {
    uploadPic: async ({ base64Pic }) => {
        const url = await processThumbnail(base64Pic)
        return { url }
    },
    dummy: () => 'dummy'
}

const passwordCheck = (password) => {
    if (password.length < 8) return 'Password must be at least 8 characters'
    if (!/[a-z]/.test(password)) return 'Password must contain at least one lowercase character'
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one uppercase character'
    if (!/[!@$%^&*.?]/.test(password)) return 'Password must contain at least one special character'
    return null
}

const sanitizedEnrichedData = (data) => {
    // Implement thorough validation and sanitization of enriched data
    // This is a simple example and should be expanded based on your specific needs
    const sanitized = {}
    if (typeof data.enrichedAddress === 'string') {
        sanitized.enrichedAddress = data.enrichedAddress.trim().slice(0, 200)
    }
    if (typeof data.latitude === 'number' && !isNaN(data.latitude)) {
        sanitized.latitude = data.latitude
    }
    if (typeof data.longitude === 'number' && !isNaN(data.longitude)) {
        sanitized.longitude = data.longitude
    }
    return sanitized
}

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'Token is required' })

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' })
        req.username = decoded.username
        req.role = decoded.role
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
    users[username] = { password: hashedPassword, role: DEFAULT_ROLE }
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
        const token = jwt.sign({ username, role: user.role }, SECRET_KEY, { expiresIn: '1h' })
        res.json({ token })
    } else {
        res.status(401).json({ error: 'Invalid username or password' })
    }
})

app.post('/api/business', [
    body('name').isString().trim().escape(),
    body('address').isString().trim().escape()
], async (req, res) => {
    const errors = validationResult(req)
    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { name, address } = req.body

    try {
        // let response = await axios.get(`https://some-api.com/data/${name}`, {
            // httpsAgent,
            // maxContentLength: 1000000,
            // validateStatus: status => status === 200,
            // maxRedirects: 5,
            // beforeRedirect: options => {
                // const redirectUrl = new URL(options.href)
                // if (!ALLOWED_REDIRECTS.includes(redirectUrl.hostname)) {
                    // throw new Error('Redirect URL is not allowed')
                // }   
            // }
        // }) // Axios with https agent and security options
        const response = { data: { enrichedAddress: 'Bandung', latitude: 1, longitude: 0 } } // pretend this is the response from an external API like axios call above
        const enrichedData = response.data

        const sanitizeEnrichedData = sanitizedEnrichedData(enrichedData)

        db.run('INSERT INTO businesses (name, address, enriched_data) VALUES (?, ?, ?)',
            [name, address, JSON.stringify(sanitizeEnrichedData)],
            err => {
            if (err) {
                res.status(500).json({ error: 'Error storing data' })
            } else {
               res.status(201).json({ message: 'Business added successfully' })
            }
        })
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
})

// v1 API (current production version)
app.get('/api/v1/users/:id', versionCheck, verifyToken, apiLimiter, (req, res) => {
  // Simulating user data retrieval
  const userData = { id: req.params.id, name: 'John Doe', email: 'john@example.com' }
  res.json(userData)
})

// v2 API (beta version with new features)
// Only accessible in non production environment
if (process.env.NODE_ENV !== 'production') {
    app.get('/api/v2/users/:id', versionCheck, verifyToken, apiLimiter, (req, res) => {
        // Simulating user data retrieval with additional sensitive information
        const userData = { 
            id: req.params.id, 
            name: 'John Doe', 
            email: 'john@example.com',
            ssn: '123-45-6789',  // Sensitive data exposed in beta
            creditCard: '1234-5678-9012-3456'  // Sensitive data exposed in beta
        }
        res.json(userData)
    })
}

app.get('/api/users/:username', (req, res) => {
    const { username } = req.params
    const user = users[username]
    if (user) {
        const { password, ...userWithoutPassword } = user
        res.json(userWithoutPassword)
    } else {
        res.status(404).json({ error: 'User not found' })
    }
})

app.post('/api/profile/upload_picture', async (req, res) => {
    const { picture_url } = req.body

    if (!picture_url && typeof picture_url !== 'string') {
        return res.status(400).json({ error: 'Invalid picture_url' })
    }

    if (!isUrlAllowed(picture_url)) {
        return res.status(400).json({ error: 'URL not allowed' })
    }

    try {
        const response = await axios.get(picture_url, {
            responseType: 'arraybuffer',
            maxRedirects: 0 // Prevent redirects
        })

        const contentType = response.headers['content-type']
        if (!contentType.startsWith('image/')) {
            return res.status(400).json({ error: 'Invalid content type' })
        }

        res.json({ message: 'Image uploaded successfully' })
    } catch (error) {
        res.status(400).json({ error: `Failed to fetch the image ${error}` })
    }
})

app.post('/api/purchase', verifyToken, purchaseLimiter, (req, res) => {
    const { quantity } = req.body
    const { username } = req

    if (purchaseHistory.has(username)) {
        return res.status(400).json({ error: 'Purchase already made today' })
    }

    if (quantity > 5) {
        return res.status(400).json({ error: 'Maximum 5 items allowed per purchase' })
    }

    if (quantity > product.stock) {
        return res.status(400).json({ error: 'Not enough stock' })
    }

    const orderId = randomUUID()
    purchaseHistory.set(username, { orderId, quantity, date: new Date() })

    product.stock -= quantity
    res.json({ message: `Successfully purchased ${quantity} units`, orderId, remainingStock: product.stock })
})

app.post('/api/invites/new', verifyToken, isAdmin, (req, res) => {
    const { username } = req.body
    const newInvite = { username, date: new Date() }
    invites.push(newInvite)
    res.status(201).json(newInvite)
})

app.get('/api/users/all', verifyToken, isAdmin, (_, res) => {
    res.json(users)
})

app.post('/reset-password', verifyToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body
    const { username } = req

    if (!currentPassword || !newPassword) {
        return res.status(400).json({ error: 'Current password and new password are required' })
    }

    const user = users[username]
    const match = await bcrypt.compare(currentPassword, user.password)
    if (!match) {
        return res.status(401).json({ error: 'Current password is incorrect' })
    }

    const passwordError = passwordCheck(newPassword)
    if (passwordError) {
        return res.status(400).json({ error: passwordError })
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS)
    users[username].password = hashedPassword

    res.json({ message: 'Password updated successfully' })
})

// Graphql endpoint with rate limit and batch limit protection
app.use('/graphql', apiLimiter, graphqlBatchLimit(10), graphqlHTTP({
    schema,
    rootValue: root,
    graphiql: true
}))

// Bonus for API4: Unrestricted Resource Consumption. Other than graphql batch limiting
let balance = 100
// Limit request that had to call monetize API to not lose thousand of dollars
app.post('/sms_forgot_password', monetizeLimiter, async (_, res) => {
    const success = await fetch('http://localhost:3000/sms/send_reset_pass_code') // pretend 3rd party API that cost
    if (success.ok) {
        res.json(await success.json())
        // do whatever it need to reset password like check code with user input then reset password
    }
})

app.get('/sms/send_reset_pass_code', (_, res) => {
    balance--
    const code = Math.floor(Math.random() * 10000)
    console.log(code, balance) // pretend to send sms
    res.json({ code })
})

app.post('/api/host/approve_booking/:id', verifyToken, (req, res) => {
    const bookingId = Number(req.params.id)
    const booking = bookings[bookingId]

    if (!booking) {
        return res.status(404).json({ error: 'Booking not found' })
    }

    // Only allow for specific property
    const allowed = ['approved', 'comment']
    for (let prop of allowed) {
        booking[prop] = req.body[prop]
    }
    
    /* Or use this code to update specific properties
    const { approved, comment } = req.body
    booking.approved = approved
    booking.comment = comment 
    */

    // Create filtered response to avoid leaking sensitive data (e.g. price)
    const bookingRes = {
        id: booking.id,
        approved: booking.approved,
        comment: booking.comment
    }

    res.json(bookingRes)
})

app.get('/shops/:shopName/revenue', verifyToken, (req, res) => {
    const shopName = req.params.shopName
    const username = req.username
    const shopRevenue = revenueData[shopName]

    if (shopRevenue) {
        // Object-level authorization
        if (shopRevenue.owner === username) {
            res.json({ revenue: shopRevenue.revenue })
        } else {
            res.status(403).json({ error: 'You are not the owner' })
        }
    } else {
        res.status(404).json({ error: 'Shop not found' })
    }
})

// Logging middleware for API inventory
app.use((req, _, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

app.use((err, _req, res, _) => {
    console.error(err)
    res.status(500).json({ error: 'An unexpected error occured' })
})

/* enable HTTPS
 const options = {
     key: readFileSync('private-key.pem'),
     cert: readFileSync('certificate.pem')
 }

 https.createServer(options, app).listen(443, () => {
     console.log('Server is running on https://localhost:443')
 })
*/

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
