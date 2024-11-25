# Creating Secured Rest API with addressing top 10 OWASP security risk and security principal

```src/app.js``` is aggregate of secure principle to REST API

![NodeJS Security thumbnail](https://farrelnikoson.tech/nodejs-security.jpg)

[Get to read the blog walkthrough!](https://farrelnikoson.tech/blog/nodejs-security-addressing-owasp-top-10-api-security-risk)

[Official OWASP Top 10 API Security Risk Page](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

- API1: Broken Object Level Auth
- API2: Broken Auth
- API3: Broken Object Property Level Auth
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Auth
- API6: Unrestricted Access to Sensitive Business Flows
- API7: Server Side Request Forgery
- API8: Security Missconfiguration
- API9: Inproper Inventory Management (Versioning)
- API10: Unsafe Consumption of APIs

In an era where APIs (Application Programming Interfaces) form the backbone of modern software architecture, understanding and mitigating API security risks has become paramount for developers, security professionals, and organizations alike.

The Open Web Application Security Project (OWASP) Top 10 API Security Risks – 2023 serves as a crucial resource in this endeavor, offering insights into the most critical security concerns facing API ecosystems today.

This comprehensive guide delves deep into each of the top 10 API security risks identified by OWASP, providing detailed explanations, real-world examples, and practical mitigation strategies. Whether you're a seasoned security expert or a developer new to API security, this article aims to equip you with the knowledge and tools necessary to build and maintain secure APIs in an increasingly interconnected digital landscape.

By the end of this guide, you'll have a thorough understanding of the current API security landscape, the specific risks that pose the greatest threats, and the best practices for safeguarding your APIs against potential attacks.

Let's embark on this journey to better understand and address the critical security challenges facing APIs in 2023 and beyond.

## Authorization

Authorization has emerged as the most prevalent vulnerability in API security, with half of the OWASP Top 10 API Security Risks for 2023 directly related to authorization flaws. This striking statistic underscores a critical weakness in many API implementations and highlights the urgent need for developers and security professionals to prioritize robust authorization mechanisms.

The prominence of authorization-related vulnerabilities in the OWASP Top 10 is not coincidental. It reflects the complex nature of implementing effective access controls in modern, interconnected systems. From granular object-level permissions to broader function-level access, authorization touches every aspect of API functionality, making it both crucial for security and challenging to implement correctly.

### Broken Object Level Auth

Broken Object Level Authorization occurs when an API fails to properly verify that the user making a request has the necessary permissions to access or manipulate the requested object. In essence, it's a failure to answer the question: "Does this user have the right to interact with this specific piece of data?"

```js
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
```

In this vulnerable implementation, any user can access the revenue data of any shop just by knowing or guessing the shop name. There's no authentication or authorization check. Now, let's implement a secure version that includes proper object-level authorization:

```js
// Mock database
const revenueData = {
  'shop1': { revenue: 10000, ownerId: 'user1' },
  'shop2': { revenue: 20000, ownerId: 'user2' },
  'shop3': { revenue: 30000, ownerId: 'user3' }
};

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, 'your-secret-key', (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    next();
  });
};

// Secure endpoint
app.get('/shops/:shopName/revenue', verifyToken, (req, res) => {
  const { shopName } = req.params;
  const { userId } = req;
  
  if (revenueData[shopName]) {
    if (revenueData[shopName].ownerId === userId) {
      res.json({ revenue: revenueData[shopName].revenue });
    } else {
      res.status(403).json({ error: 'Access denied' });
    }
  } else {
    res.status(404).json({ error: 'Shop not found' });
  }
});
```

In this secure implementation:

- We use JWT for authentication. The verifyToken middleware checks for a valid token and extracts the user ID.
- We've added an ownerId field to each shop's data in our mock database.
- In the endpoint, we first check if the shop exists, then we verify that the user requesting the data is the owner of the shop.
- We only return the revenue data if the user is authorized to access it.

### Broken Authentication

Broken authentication deal with bad design in API. No rate limiting, allowing brute force attack. Password are stored in plain text, weak secret key for JWT signing, no password strength requirements and password reset doesn't require aunthentication.

```js
app.use(express.json());

const SECRET_KEY = 'very-secret-key';

// Mock user database
const users = {
  'user1': { password: 'password1' },
  'user2': { password: 'password2' },
};

// Vulnerable login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (users[username] && users[username].password === password) {
    const token = jwt.sign({ username }, SECRET_KEY);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Vulnerable password reset endpoint
app.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;

  if (users[username]) {
    users[username].password = newPassword;
    res.json({ message: 'Password updated successfully' });
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});
```

Now, let’s implement a secure version that includes proper authorization:

```js
app.use(express.json());

const SECRET_KEY = uuidv4(); // Generate a unique secret key on each server start
const SALT_ROUNDS = 10;

// Mock user database
const users = {};

// Rate limiting middleware
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 login requests per window
  message: 'Too many login attempts, please try again later'
});

// Password strength check
function isPasswordStrong(password) {
  return password.length >= 8 && /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password);
}

// Secure login endpoint
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users[username];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (match) {
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Secure registration endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  if (users[username]) {
    return res.status(409).json({ error: 'Username already exists' });
  }

  if (!isPasswordStrong(password)) {
    return res.status(400).json({ error: 'Password is not strong enough' });
  }

  const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
  users[username] = { password: hashedPassword };

  res.status(201).json({ message: 'User registered successfully' });
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.username = decoded.username;
    next();
  });
};

// Secure password reset endpoint
app.post('/reset-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { username } = req;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required' });
  }

  const user = users[username];
  const match = await bcrypt.compare(currentPassword, user.password);

  if (!match) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  if (!isPasswordStrong(newPassword)) {
    return res.status(400).json({ error: 'New password is not strong enough' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
  users[username].password = hashedPassword;

  res.json({ message: 'Password updated successfully' });
});
```


This secure implementation addresses the vulnerabilities:

- Uses rate limiting to prevent brute force attacks.
- Hashes passwords using bcrypt.
- Uses a strong, randomly generated secret key for JWT signing.
- Implements password strength requirements.
- Requires authentication for password reset and confirmation of the current password.
- Uses JWT with expiration for authentication.
- Implements proper input validation.

### Broken Object Property Level Authorization

This implementation is vulnerable because it allows the client to update any property of the booking object, including sensitive properties like total_stay_price.

```js
app.use(express.json());

// Mock database
const bookings = {
  1: { id: 1, approved: false, comment: '', total_stay_price: 100 }
};

// Vulnerable endpoint
app.post('/api/host/approve_booking/:id', (req, res) => {
  const bookingId = parseInt(req.params.id);
  const booking = bookings[bookingId];

  if (!booking) {
    return res.status(404).json({ error: 'Booking not found' });
  }

  // Vulnerable: allows updating any property of the booking object
  Object.assign(booking, req.body);

  res.json({ message: 'Booking updated successfully', booking });
});
```

Now, let's implement a secure version that addresses this vulnerability:

```js
app.use(express.json());

// Mock database
const bookings = {
  1: { id: 1, approved: false, comment: '', total_stay_price: 100 }
};

// Mock authentication middleware
const authenticate = (req, res, next) => {
  // In a real application, you would verify the user's token here
  req.user = { id: 'host1' };
  next();
};

// Secure endpoint
app.post('/api/host/approve_booking/:id', authenticate, (req, res) => {
  const bookingId = parseInt(req.params.id);
  const booking = bookings[bookingId];

  if (!booking) {
    return res.status(404).json({ error: 'Booking not found' });
  }

  // Only allow updating specific properties
  const allowedUpdates = ['approved', 'comment'];
  const updates = {};

  for (let prop of allowedUpdates) {
    if (req.body[prop] !== undefined) {
      updates[prop] = req.body[prop];
    }
  }

  // Update only allowed properties
  Object.assign(booking, updates);

  // Return only non-sensitive data
  const safeBooking = {
    id: booking.id,
    approved: booking.approved,
    comment: booking.comment
  };

  res.json({ message: 'Booking updated successfully', booking: safeBooking });
});
```

This secure implementation addresses the vulnerability in several ways:

- It uses an authentication middleware to ensure only authenticated users can access the endpoint.
- It explicitly defines which properties are allowed to be updated (allowedUpdates).
- It only updates the properties that are both allowed and provided in the request.
- When returning the response, it only includes non-sensitive data in the safeBooking object.

### Broken Function Level Authorization

This implementation is vulnerable because it doesn't implement function level authorization. Any authenticated user can create invites and view all users, regardless of their role.

```js
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = 'your-secret-key';

// Mock user database
const users = [
  { id: 1, username: 'user', role: 'user' },
  { id: 2, username: 'admin', role: 'admin' }
];

// Mock invite database
const invites = [];

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// Vulnerable login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user) {
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Vulnerable invite endpoint (no function level authorization)
app.post('/api/invites/new', verifyToken, (req, res) => {
  const { email, role } = req.body;
  const newInvite = { email, role };
  invites.push(newInvite);
  res.status(201).json(newInvite);
});

// Vulnerable get all users endpoint (no function level authorization)
app.get('/api/users/all', verifyToken, (req, res) => {
  res.json(users);
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's implement a secure version that addresses these vulnerabilities:

```js
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = 'your-secret-key';

// Mock user database
const users = [
  { id: 1, username: 'user', role: 'user' },
  { id: 2, username: 'admin', role: 'admin' }
];

// Mock invite database
const invites = [];

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
  if (req.userRole !== 'admin') {
    return res.status(403).json({ error: 'Access denied. Admin role required.' });
  }
  next();
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (user) {
    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Secure invite endpoint (with function level authorization)
app.post('/api/invites/new', verifyToken, isAdmin, (req, res) => {
  const { email, role } = req.body;
  const newInvite = { email, role };
  invites.push(newInvite);
  res.status(201).json(newInvite);
});

// Secure get all users endpoint (with function level authorization)
app.get('/api/users/all', verifyToken, isAdmin, (req, res) => {
  res.json(users);
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This secure implementation addresses the vulnerability by:

- Implementing an isAdmin middleware that checks if the user has an admin role.
- Applying the isAdmin middleware to sensitive endpoints that should only be accessible by administrators.

### Unrestricted Access to Sensitive Business Flows

This implementation is vulnerable because it doesn't implement any protection against excessive access to the purchase flow. An attacker could easily automate purchases and buy all the stock.

```js
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET_KEY = 'your-secret-key';

// Mock product database
let product = {
  id: 1,
  name: 'Limited Edition Gaming Console',
  price: 499.99,
  stock: 100
};

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    next();
  });
};

// Login endpoint (simplified for this example)
app.post('/login', (req, res) => {
  const { username } = req.body;
  const token = jwt.sign({ id: username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Vulnerable purchase endpoint
app.post('/api/purchase', verifyToken, (req, res) => {
  const { quantity } = req.body;

  if (quantity > product.stock) {
    return res.status(400).json({ error: 'Not enough stock' });
  }

  product.stock -= quantity;
  res.json({ message: `Successfully purchased ${quantity} units`, remainingStock: product.stock });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's implement a secure version that addresses this vulnerability:

```js
const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const SECRET_KEY = 'your-secret-key';

// Mock product database
let product = {
  id: 1,
  name: 'Limited Edition Gaming Console',
  price: 499.99,
  stock: 100
};

// Mock purchase history
const purchaseHistory = new Map();

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'No token provided' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Unauthorized' });
    req.userId = decoded.id;
    next();
  });
};

// Rate limiting middleware
const purchaseLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000, // 24 hours
  max: 1, // limit each IP to 1 purchase request per day
  message: 'Too many purchase attempts, please try again later'
});

// Login endpoint (simplified for this example)
app.post('/login', (req, res) => {
  const { username } = req.body;
  const token = jwt.sign({ id: username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Secure purchase endpoint
app.post('/api/purchase', verifyToken, purchaseLimiter, (req, res) => {
  const { quantity } = req.body;
  const userId = req.userId;

  // Check if user has already purchased
  if (purchaseHistory.has(userId)) {
    return res.status(400).json({ error: 'You have already made a purchase' });
  }

  // Limit quantity per purchase
  if (quantity > 1) {
    return res.status(400).json({ error: 'Maximum 1 unit per purchase' });
  }

  if (quantity > product.stock) {
    return res.status(400).json({ error: 'Not enough stock' });
  }

  // Generate unique order ID
  const orderId = uuidv4();

  // Record the purchase
  purchaseHistory.set(userId, { orderId, quantity, timestamp: Date.now() });

  product.stock -= quantity;
  res.json({ 
    message: `Successfully purchased ${quantity} units`, 
    orderId,
    remainingStock: product.stock 
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This secure implementation addresses the vulnerability by:

- Implementing rate limiting to restrict the number of purchase attempts per IP address.
- Limiting the quantity per purchase to 1 unit.
- Preventing users from making multiple purchases by keeping track of purchase history.
- Generating a unique order ID for each purchase.

## Resource consumption

Resource consumption-related vulnerabilities account for a quarter of the listed risks, highlighting their growing importance in the API security landscape.

Resource management in API ecosystems encompasses both the risk of attackers overwhelming system resources (API4) and the dangers of poorly managed API deployments leading to unnecessary resource exposure (API9), while API10 highlights the cascading security issues that can arise from misplaced trust in third-party APIs.

### Unrestricted Resource Consumption

This implementation is vulnerable because it doesn't limit the number of operations per request or implement any rate limiting.

Notice that this rate limiting is different with rate limiting for authorization. Authorization rate limiting is addressing brute force issues and rate limiting can also be use for restricted / protect resource in API. 

```js
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const sharp = require('sharp');

const app = express();

// Dummy function to simulate image processing
async function processThumbnail(base64Image) {
  const buffer = Buffer.from(base64Image, 'base64');
  await sharp(buffer)
    .resize(200, 200)
    .toBuffer();
  // In a real scenario, we'd save this thumbnail
  return 'http://example.com/thumbnail.jpg';
}

// GraphQL schema
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
`);

// Resolver
const root = {
  uploadPic: async ({ name, base64Pic }) => {
    const url = await processThumbnail(base64Pic);
    return { url };
  },
  dummy: () => 'dummy'
};

// GraphQL endpoint
app.use('/graphql', graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true,
}));

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's implement a secure version that addresses these vulnerabilities:

```js
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const sharp = require('sharp');
const rateLimit = require('express-rate-limit');
const { graphqlBatchLimit } = require('./graphqlBatchLimit'); // We'll create this

const app = express();

// Rate limiting middleware
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // Limit each IP to 100 requests per windowMs
});

// Apply rate limiting to all requests
app.use(apiLimiter);

async function processThumbnail(base64Image) {
  // Implement a size check
  if (base64Image.length > 1000000) { // Roughly 1MB
    throw new Error('Image too large');
  }

  const buffer = Buffer.from(base64Image, 'base64');
  await sharp(buffer)
    .resize(200, 200)
    .toBuffer();
  return 'http://example.com/thumbnail.jpg';
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
`);

const root = {
  uploadPic: async ({ name, base64Pic }) => {
    const url = await processThumbnail(base64Pic);
    return { url };
  },
  dummy: () => 'dummy'
};

// GraphQL endpoint with batch limiting
app.use('/graphql', graphqlBatchLimit(10), graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true,
}));

app.listen(3000, () => console.log('Server running on port 3000'));
```
Now, let's create the graphqlBatchLimit middleware:

```js
// graphqlBatchLimit.js
module.exports.graphqlBatchLimit = function(maxBatchSize) {
  return (req, res, next) => {
    if (Array.isArray(req.body)) {
      if (req.body.length > maxBatchSize) {
        return res.status(400).json({
          errors: [{
            message: `Batch operations are limited to ${maxBatchSize} per request.`
          }]
        });
      }
    }
    next();
  };
};
```


This secure implementation addresses the vulnerability in several ways:

- It uses express-rate-limit to implement overall API rate limiting.
- It implements a custom graphqlBatchLimit middleware to limit the number of operations in a single GraphQL request.
- It checks the size of the uploaded image before processing.

### Improper Inventory Management

This implementation has several issues:

- It exposes a beta version (v2) with sensitive data without proper protection.
- There's no clear documentation or versioning strategy.
- There's no inventory management or monitoring of API versions.
- The beta version is accessible on the same server as the production version.


```js
const express = require('express');
const app = express();

app.use(express.json());

// v1 API (current production version)
app.get('/api/v1/user/:id', (req, res) => {
  // Simulating user data retrieval
  const userData = { id: req.params.id, name: 'John Doe', email: 'john@example.com' };
  res.json(userData);
});

// v2 API (beta version with new features)
app.get('/api/v2/user/:id', (req, res) => {
  // Simulating user data retrieval with additional sensitive information
  const userData = { 
    id: req.params.id, 
    name: 'John Doe', 
    email: 'john@example.com',
    ssn: '123-45-6789',  // Sensitive data exposed in beta
    creditCard: '1234-5678-9012-3456'  // Sensitive data exposed in beta
  };
  res.json(userData);
});

// Catch-all route for undefined endpoints
app.use((req, res) => {
  res.status(404).send('Not Found');
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's create a secure implementation that addresses these issues:

```js
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');

const app = express();

app.use(express.json());
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// API documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Version management
const apiVersions = {
  'v1': '1.0.0',
  'v2': '2.0.0-beta'
};

// Middleware for API versioning
const versionCheck = (req, res, next) => {
  const version = req.path.split('/')[2];
  if (!apiVersions[version]) {
    return res.status(404).json({ error: 'API version not found' });
  }
  next();
};

// v1 API (current production version)
app.get('/api/v1/user/:id', versionCheck, (req, res) => {
  // Simulating user data retrieval
  const userData = { id: req.params.id, name: 'John Doe', email: 'john@example.com' };
  res.json(userData);
});

// v2 API (beta version with new features)
// Only accessible in non-production environments
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/v2/user/:id', versionCheck, (req, res) => {
    // Simulating user data retrieval with additional information
    const userData = { 
      id: req.params.id, 
      name: 'John Doe', 
      email: 'john@example.com',
      // Sensitive data masked even in beta
      ssn: 'XXX-XX-' + req.params.id.slice(-4),
      creditCard: 'XXXX-XXXX-XXXX-' + req.params.id.slice(-4)
    };
    res.json(userData);
  });
}

// Logging middleware for API inventory
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Catch-all route for undefined endpoints
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
```

You'll also need to create a swagger.json file for API documentation. Here's a basic example:

```json
{
  "openapi": "3.0.0",
  "info": {
    "title": "Sample API",
    "version": "1.0.0"
  },
  "paths": {
    "/api/v1/user/{id}": {
      "get": {
        "summary": "Get user information",
        "parameters": [
          {
            "in": "path",
            "name": "id",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Successful response",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "string" },
                    "name": { "type": "string" },
                    "email": { "type": "string" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

This implementation provides better inventory management by:

- Clearly documenting API versions and endpoints.
- Restricting access to beta versions in production environments.
- Implementing logging for API usage tracking.
- Providing API documentation through Swagger UI.
- Masking sensitive data even in beta versions.

Remember, this is a basic example. In a real-world scenario, you would need to implement more robust authentication, authorization, and data protection mechanisms. You should also consider using separate environments for different API versions and implementing a proper strategy for API retirement and data flow management.

### Unsafe Consumption of APIs

This implementation has several vulnerabilities:

- It communicates with the third-party API over an unencrypted channel (HTTP).
- It doesn't validate or sanitize the data received from the third-party API.
- It's vulnerable to SQL injection due to direct string interpolation in the SQL query.
- It doesn't implement timeouts for the third-party API request.
- It doesn't limit the size of the response from the third-party API.

```js
const express = require('express');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());

// Create and connect to SQLite database
const db = new sqlite3.Database(':memory:');
db.run("CREATE TABLE businesses (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, enriched_data TEXT)");

// Third-party API for address enrichment (simulated)
const thirdPartyApiUrl = 'http://third-party-api.example.com/enrich';

app.post('/api/business', async (req, res) => {
  const { name, address } = req.body;

  try {
    // Fetch enriched data from third-party API
    const response = await axios.get(`${thirdPartyApiUrl}?address=${encodeURIComponent(address)}`);
    const enrichedData = response.data;

    // Store data in database (vulnerable to SQL injection)
    db.run(`INSERT INTO businesses (name, address, enriched_data) VALUES ('${name}', '${address}', '${JSON.stringify(enrichedData)}')`, (err) => {
      if (err) {
        res.status(500).json({ error: 'Error storing data' });
      } else {
        res.status(201).json({ message: 'Business added successfully' });
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error processing request' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This secure implementation addresses the previous vulnerabilities:

- It uses HTTPS for communication with the third-party API.
- It implements input validation and sanitization for user input using express-validator.
- It validates and sanitizes data received from the third-party API.
- It uses parameterized queries to prevent SQL injection.
- It implements a timeout for the third-party API request.
- It limits the size of the response from the third-party API.
- It implements safe redirect handling with an allowlist of allowed domains.

```js
const express = require('express');
const https = require('https');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.json());

// Create and connect to SQLite database
const db = new sqlite3.Database(':memory:');
db.run("CREATE TABLE businesses (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, address TEXT, enriched_data TEXT)");

// Third-party API for address enrichment (using HTTPS)
const thirdPartyApiUrl = 'https://third-party-api.example.com/enrich';

// Allowed redirect domains
const allowedRedirectDomains = ['api1.example.com', 'api2.example.com'];

// Custom HTTPS agent with timeout
const httpsAgent = new https.Agent({
  timeout: 5000 // 5 seconds timeout
});

app.post('/api/business', [
  body('name').isString().trim().escape(),
  body('address').isString().trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { name, address } = req.body;

  try {
    // Fetch enriched data from third-party API with timeout and max response size
    const response = await axios.get(`${thirdPartyApiUrl}?address=${encodeURIComponent(address)}`, {
      httpsAgent,
      maxContentLength: 1000000, // 1MB max response size
      validateStatus: (status) => status === 200, // Only accept 200 status
      maxRedirects: 5,
      beforeRedirect: (options, { headers }) => {
        const redirectUrl = new URL(options.href);
        if (!allowedRedirectDomains.includes(redirectUrl.hostname)) {
          throw new Error('Redirect not allowed');
        }
      }
    });

    const enrichedData = response.data;

    // Validate and sanitize enriched data
    const sanitizedEnrichedData = sanitizeEnrichedData(enrichedData);

    // Store data in database (protected against SQL injection)
    db.run('INSERT INTO businesses (name, address, enriched_data) VALUES (?, ?, ?)', 
      [name, address, JSON.stringify(sanitizedEnrichedData)], 
      (err) => {
        if (err) {
          res.status(500).json({ error: 'Error storing data' });
        } else {
          res.status(201).json({ message: 'Business added successfully' });
        }
    });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'Error processing request' });
  }
});

function sanitizeEnrichedData(data) {
  // Implement thorough validation and sanitization of enriched data
  // This is a simple example and should be expanded based on your specific needs
  const sanitized = {};
  if (typeof data.enrichedAddress === 'string') {
    sanitized.enrichedAddress = data.enrichedAddress.trim().slice(0, 200);
  }
  if (typeof data.latitude === 'number' && !isNaN(data.latitude)) {
    sanitized.latitude = data.latitude;
  }
  if (typeof data.longitude === 'number' && !isNaN(data.longitude)) {
    sanitized.longitude = data.longitude;
  }
  return sanitized;
}

app.listen(3000, () => console.log('Server running on port 3000'));
```
Remember, this is a basic example. In a real-world scenario, you would need to implement more robust error handling, logging, and potentially use an ORM for database operations. You should also consider implementing rate limiting for your API and monitoring for unusual patterns in third-party API responses.

## Other security risk

### Security Misconfiguration

This implementation has several security misconfigurations:

- It doesn't use HTTPS.
- It doesn't implement proper error handling, exposing stack traces.
- It doesn't implement CORS protection.
- It doesn't include security headers.
- It exposes sensitive information (passwords) in the API response.

```js
const express = require('express');
const app = express();

app.use(express.json());

const users = [
  { id: 1, username: 'alice', email: 'alice@example.com', password: 'password123' },
  { id: 2, username: 'bob', email: 'bob@example.com', password: 'qwerty456' }
];

app.get('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);

  if (user) {
    res.json(user);
  } else {
    throw new Error(`User with id ${userId} not found`);
  }
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: err.message, stack: err.stack });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's create a secure implementation that addresses these issues:

```js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const https = require('https');
const fs = require('fs');

const app = express();

app.use(express.json());
app.use(helmet()); // Adds various security headers
app.use(cors({
  origin: 'https://trusted-origin.com',
  methods: ['GET']
}));

const users = [
  { id: 1, username: 'alice', email: 'alice@example.com' },
  { id: 2, username: 'bob', email: 'bob@example.com' }
];

app.get('/api/users/:id', (req, res) => {
  const userId = parseInt(req.params.id);
  const user = users.find(u => u.id === userId);

  if (user) {
    const { password, ...safeUser } = user;
    res.json(safeUser);
  } else {
    res.status(404).json({ error: 'User not found' });
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'An unexpected error occurred' });
});

// HTTPS configuration
const options = {
  key: fs.readFileSync('path/to/private-key.pem'),
  cert: fs.readFileSync('path/to/certificate.pem')
};

https.createServer(options, app).listen(443, () => {
  console.log('HTTPS Server running on port 443');
});
```

You'll also need to generate or obtain SSL/TLS certificates for HTTPS. For testing, you can generate self-signed certificates, but for production, you should use certificates from a trusted Certificate Authority.

This secure implementation addresses the previous vulnerabilities:

- It uses HTTPS instead of HTTP.
- It implements proper error handling without exposing stack traces.
- It implements CORS protection, allowing requests only from a trusted origin.
- It includes security headers using the helmet middleware.
- It doesn't expose sensitive information (passwords) in the API response.

### Server Side Request Forgery (SSRF attack)

This implementation is vulnerable because it doesn't validate or sanitize the picture_url input. An attacker could provide a URL pointing to an internal resource, potentially exposing sensitive information or allowing for network scanning.

```js
const express = require('express');
const axios = require('axios');
const app = express();

app.use(express.json());

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

app.listen(3000, () => console.log('Server running on port 3000'));
```

Now, let's create a secure implementation that addresses the SSRF vulnerability:

```js
const express = require('express');
const axios = require('axios');
const { URL } = require('url');
const app = express();

app.use(express.json());

// Allowlist of accepted domains and schemes
const ALLOWED_DOMAINS = ['example.com', 'trusteddomain.com'];
const ALLOWED_SCHEMES = ['https'];

function isUrlAllowed(url) {
  try {
    const parsedUrl = new URL(url);
    return (
      ALLOWED_SCHEMES.includes(parsedUrl.protocol.slice(0, -1)) &&
      ALLOWED_DOMAINS.includes(parsedUrl.hostname)
    );
  } catch (error) {
    return false;
  }
}

app.post('/api/profile/upload_picture', async (req, res) => {
  const { picture_url } = req.body;

  if (!picture_url || typeof picture_url !== 'string') {
    return res.status(400).json({ error: 'Invalid picture URL' });
  }

  if (!isUrlAllowed(picture_url)) {
    return res.status(403).json({ error: 'URL not allowed' });
  }

  try {
    const response = await axios.get(picture_url, {
      responseType: 'arraybuffer',
      maxRedirects: 0, // Disable redirects
    });

    // Validate content type
    const contentType = response.headers['content-type'];
    if (!contentType.startsWith('image/')) {
      return res.status(400).json({ error: 'Invalid content type' });
    }

    // Process the image data...
    res.status(200).json({ message: 'Profile picture uploaded successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch the image' });
  }
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

This secure implementation includes several measures to prevent SSRF:

- URL validation: We use the built-in URL class to parse and validate the URL structure.
- Allowlist for domains and schemes: We maintain lists of allowed domains and URL schemes, and only proceed if the provided URL matches these lists.
- Disable redirects: By setting maxRedirects: 0, we prevent the request from being redirected to potentially malicious URLs.
- Content type validation: We check that the response content type is an image before processing it.
- Input validation: We ensure that picture_url is provided and is a string before processing.

## Conclusion: Securing the API Landscape

As we've explored throughout this comprehensive guide to the OWASP Top 10 API Security Risks for 2023, the landscape of API security is both complex and critical.

From the pervasive challenges of authorization, accounting for half of the top risks, to the growing concerns of resource consumption and the often-overlooked dangers of unsafe API consumption, and other risk that may we've been forgot like security misconfiguration and SSRF/DDOS attack threat. It's clear that securing APIs requires a multifaceted approach.

Key takeaways from our exploration include:

- Authorization remains the Achilles' heel of API security, demanding meticulous attention to object-level, property-level, and function-level access controls.

- Resource management has emerged as a significant concern, with risks stemming from both potential attacks and poor API lifecycle management.

- The interconnected nature of modern APIs introduces new vulnerabilities, particularly in how we consume and trust third-party services.

- Effective API security requires a holistic approach, encompassing robust design, secure configuration, careful implementation, continuous monitoring, and regular updates about threat and attack form.

As the digital landscape continues to evolve, so too will the challenges facing API security. However, by understanding these top risks and implementing the mitigation strategies discussed, developers and security professionals can build more resilient, secure API ecosystems.

The journey to API security is ongoing. It requires vigilance, adaptability, and a commitment to best practices. As we look to the future, let's carry forward the insights gained from this exploration of the OWASP Top 10, using them to forge APIs that are not just functional, but fundamentally secure.

Remember, in the world of API security, knowledge is not just power—it's protection. Stay informed, stay vigilant, and keep building secure APIs that can stand up to the challenges of our interconnected digital world.

**Hopefully helpful, Farrel Nikoson.**
