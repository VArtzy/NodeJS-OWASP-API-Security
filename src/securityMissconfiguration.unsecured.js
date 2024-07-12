import express from 'express'
const app = express()

app.use(express.json())
// Security misconfiguration: better could use helmet to set security headers and cors to set cors headers

const users = [
  { id: 1, username: 'alice', email: 'alice@example.com', password: 'password123' },
  { id: 2, username: 'bob', email: 'bob@example.com', password: 'qwerty456' }
];

app.get('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id)
  const user = users.find(u => u.id === userId)

  if (user) {
     // Information disclosure: exposing user data
    res.json(user)
  } else {
    throw new Error(`User with id ${userId} not found`)
  }
});

// Security misconfiguration: exposing stack traces in error messages
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({ error: err.message, stack: err.stack })
});

// Use https as a secure protocol
app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
