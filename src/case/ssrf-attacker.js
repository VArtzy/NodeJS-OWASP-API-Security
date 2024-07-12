import express from 'express'
const app = express()

app.get('/', (_, res) => {
  res.send('This is a protected internal server')
});

app.listen(8080, () => console.log('Test server running on port 8080'))
// Run this script to start the server and run ../ssrf-port-scaning.sh to scan for open ports
