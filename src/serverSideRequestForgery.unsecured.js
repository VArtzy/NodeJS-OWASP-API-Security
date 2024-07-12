import express from 'express'
import axios from 'axios'

const app = express()
app.use(express.json())

// Vulnerable because it doesnt validate or sanitize picture_url to prevent SSRF
app.post('/api/profile/upload_picture', async (req, res) => {
  const { picture_url } = req.body;

  try {
    const response = await axios.get(picture_url, { responseType: 'arraybuffer' });
    // Process the image data...
    res.status(200).json({ message: 'Profile picture uploaded successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch the image' });
  }
});

app.listen(3000, () => console.log('Server is running on http://localhost:3000'))
