import express from 'express'
import bodyParser from 'body-parser'

const app = express()
app.use(bodyParser.json())

const bookings = {
    1: { id: 1, approved: false, comment: '', price: 100 },
}

app.post('/api/host/approve_booking/:id', (req, res) => {
    const bookingId = Number(req.params.id)
    const booking = bookings[bookingId]

    if (!booking) {
        return res.status(404).json({ error: 'Booking not found' })
    }

    // Vulnerable: allows updating any property of the booking object
    Object.assign(booking, req.body)

    res.json(booking)
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
