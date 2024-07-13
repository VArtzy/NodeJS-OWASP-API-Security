import express from 'express'
import sqlite3 from 'sqlite3'

const app = express()
app.use(express.json())

const db = new sqlite3.Database(':memory:')
db.run('CREATE TABLE businesses (id INTEGER PRIMARY KEY, name TEXT, address TEXT, enriched_data TEXT)')

// This implementation has several vulnerabilities:
// It communicates with the third-party API over an unencrypted channel (HTTP).
// It doesn't validate or sanitize the data received from the third-party API.
// It's vulnerable to SQL injection due to direct string interpolation in the SQL query.
// It doesn't implement timeouts for the third-party API request.
// It doesn't limit the size of the response from the third-party API.
app.post('/api/business', async (req, res) => {
    const { name, address } = req.body

    try {
        const response = { data: { some: 'data' } } // pretend this is the response from the 3rd API via fetch
        const enrichedData = response.data

        db.run(`INSERT INTO businesses (name, address, enriched_data) VALUES ('${name}', '${address}', '${JSON.stringify(enrichedData)}')`, err => {
            if (err) {
                res.status(500).json({ error: 'Failed to save business' })
            } else {
                res.status(201).json({ message: 'Business added successfully' })
            }
        })
    } catch (error) {
        res.status(500).json({ error: error })
    }
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
