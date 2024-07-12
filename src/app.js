import express from 'express'
import jwt from 'jsonwebtoken'
import bodyParser from 'body-parser'

const app = express()
app.use(bodyParser.json())

const revenueData = {
    'nike': { revenue: 10000, owner: 'john' },
    'apple': { revenue: 20000, owner: 'tim' },
    'toyota': { revenue: 30000, owner: 'farrel' }
}

const users = {
    'farrel': { id: 'farrel', password: 'secret' },
    'john': { id: 'john', password: 'password' },
    'tim': { id: 'tim', password: 'credential' }
}

const SECRET_KEY = 'secret'

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'Token is required' })

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Invalid token' })
        req.userId = decoded.id
        next()
    })
}

app.post('/login', (req, res) => {
    const { username, password } = req.body
    const user = users[username]

    if (user && user.password === password) {
        const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' })
        res.json({ token })
    } else {
        res.status(401).json({ error: 'Invalid username or password' })
    }
})

app.get('/shops/:shopName/revenue', verifyToken, (req, res) => {
    const shopName = req.params.shopName
    const userId = req.userId
    const shopRevenue = revenueData[shopName]

    if (shopRevenue) {
        // Object-level authorization
        if (shopRevenue.owner === userId) {
            res.json({ revenue: shopRevenue.revenue })
        } else {
            res.status(403).json({ error: 'You are not the owner' })
        }
    } else {
        res.status(404).json({ error: 'Shop not found' })
    }
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
