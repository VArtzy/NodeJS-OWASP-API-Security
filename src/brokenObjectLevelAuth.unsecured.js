import express from 'express'

const app = express()

const revenueData = {
    'nike': { revenue: 10000 },
    'apple': { revenue: 20000 },
    'toyota': { revenue: 30000 }
}

app.get('/shops/:shopName/revenue', (req, res) => {
    const shopName = req.params.shopName
    const shopRevenue = revenueData[shopName]

    if (shopRevenue) {
        res.json(shopRevenue)
    } else {
        res.status(404).json({ error: 'Shop not found' })
    }
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
