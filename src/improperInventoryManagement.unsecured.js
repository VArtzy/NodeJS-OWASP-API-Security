import express from 'express'
const app = express()

app.use(express.json())

// v1 API (current production version)
app.get('/api/v1/users/:id', (req, res) => {
  // Simulating user data retrieval
  const userData = { id: req.params.id, name: 'John Doe', email: 'john@example.com' }
  res.json(userData)
})

// v2 API (beta version with new features)
app.get('/api/v2/users/:id', (req, res) => {
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

// Catch-all route for undefined endpoints
app.use((req, res) => {
  res.status(404).send('Not Found')
})

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
