require('dotenv').config();
const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const { promises: fsPromises } = require('fs');
const { auth } = require('express-openid-connect');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = process.env.PORT || 3000;

// Configure multer for file upload - make it compatible with serverless environment
let uploadDir = 'uploads/';
// In Vercel's serverless environment, use /tmp directory for file uploads
if (process.env.NODE_ENV === 'production') {
  uploadDir = '/tmp/';
}

const upload = multer({
  dest: uploadDir,
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  }
});

// Configure AWS SDK - handle both local development and Vercel environment
if (process.env.NODE_ENV === 'production') {
  console.log('Configuring AWS SDK for production environment');
  // In production (Vercel), use environment variables for AWS credentials
  AWS.config.update({
    region: process.env.AWS_REGION || 'eu-north-1'
  });
} else {
  // In local development, use profile credentials
  console.log('Configuring AWS SDK with profile authentication');
  AWS.config.update({
    region: process.env.AWS_REGION || 'eu-north-1',
    credentials: new AWS.SharedIniFileCredentials({ profile: '074993326121_DeveloperAccess' })
  });
}

const sqs = new AWS.SQS();

// Check SQS connection and log status
async function checkSQSConnection() {
  try {
    console.log('Checking AWS SQS connection...');
    
    // Check if SQS queue URL is configured
    if (!process.env.SQS_QUEUE_URL) {
      console.warn('⚠️ SQS_QUEUE_URL not configured. SQS functionality will be limited to mock data.');
      return false;
    }
    
    // In development environment, we're using profile authentication
    if (process.env.NODE_ENV !== 'production') {
      console.log('Using AWS profile authentication:', process.env.AWS_PROFILE || 'default');
    } 
    // In production, check if AWS credentials are configured
    else if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
      console.warn('⚠️ AWS credentials not configured in production. SQS functionality will be limited to mock data.');
      return false;
    }
    
    // Try to get queue attributes to verify connection
    const params = {
      QueueUrl: process.env.SQS_QUEUE_URL,
      AttributeNames: ['QueueArn']
    };
    
    const data = await sqs.getQueueAttributes(params).promise();
    
    if (data && data.Attributes && data.Attributes.QueueArn) {
      console.log('✅ Successfully connected to AWS SQS queue:', data.Attributes.QueueArn);
      return true;
    } else {
      console.warn('⚠️ Connected to AWS SQS but could not retrieve queue attributes');
      return false;
    }
  } catch (error) {
    console.error('❌ AWS SQS connection failed:', error.message);
    if (error.code === 'CredentialsError' || error.code === 'InvalidClientTokenId') {
      if (process.env.NODE_ENV !== 'production') {
        console.error('❌ AWS profile authentication failed. Check that the profile exists in your AWS credentials file.');
        console.error('❌ Current profile:', process.env.AWS_PROFILE || 'default');
        console.error('❌ Verify your ~/.aws/credentials file contains this profile.');
      } else {
        console.error('❌ AWS credentials are missing or invalid');
      }
    } else if (error.message && error.message.includes('security token')) {
      console.error('❌ AWS temporary security token has expired. Please refresh your AWS credentials.');
      console.error('❌ For temporary credentials, you need to update ACCESS_KEY_ID, SECRET_ACCESS_KEY, and SESSION_TOKEN');
    } else if (error.code === 'ProfileNotFound') {
      console.error('❌ AWS profile not found:', process.env.AWS_PROFILE || 'default');
      console.error('❌ Check your ~/.aws/credentials file and make sure the profile exists.');
    } else if (error.code === 'AWS.SimpleQueueService.NonExistentQueue') {
      console.error('❌ SQS queue does not exist:', process.env.SQS_QUEUE_URL);
    } else if (error.code === 'NetworkingError') {
      console.error('❌ Network error when connecting to AWS SQS');
    }
    return false;
  }
}

// Auth0 configuration
const config = {
  authRequired: false,
  auth0Logout: true,
  secret: process.env.AUTH0_SECRET,
  baseURL: process.env.AUTH0_BASE_URL,
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
};

// Check if Auth0 is properly configured
const isAuth0Configured = process.env.AUTH0_SECRET && 
                          process.env.AUTH0_CLIENT_ID && 
                          process.env.AUTH0_ISSUER_BASE_URL &&
                          process.env.AUTH0_CLIENT_ID !== 'your-auth0-client-id-here' &&
                          process.env.AUTH0_ISSUER_BASE_URL !== 'https://your-domain.auth0.com';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Session middleware (required for Auth0)
app.use(session({
  secret: process.env.AUTH0_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Auth0 middleware (only if properly configured)
if (isAuth0Configured) {
  console.log('✅ Auth0 is configured - enabling authentication');
  app.use(auth(config));
} else {
  console.log('⚠️ Auth0 not configured - running without authentication');
  console.log('Please update your .env file with proper Auth0 credentials to enable authentication');
}

// User management functions
function loadUsers() {
  try {
    const data = fs.readFileSync(path.join(__dirname, 'users.json'), 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error loading users:', error);
    return { users: [], totalResults: 0, itemsPerPage: 100, startIndex: 1, schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"] };
  }
}

function saveUsers(usersData) {
  try {
    fs.writeFileSync(path.join(__dirname, 'users.json'), JSON.stringify(usersData, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving users:', error);
    return false;
  }
}

function findUserById(id) {
  const usersData = loadUsers();
  return usersData.users.find(user => user.id === id);
}

function findUserByEmail(email) {
  const usersData = loadUsers();
  return usersData.users.find(user => user.emails && user.emails.some(e => e.value === email));
}

// Authentication routes
app.get('/auth/user', (req, res) => {
  if (!isAuth0Configured) {
    return res.json({ isAuthenticated: false, message: 'Auth0 not configured' });
  }
  
  if (req.oidc && req.oidc.isAuthenticated()) {
    res.json({
      isAuthenticated: true,
      user: {
        name: req.oidc.user.name,
        email: req.oidc.user.email,
        picture: req.oidc.user.picture
      }
    });
  } else {
    res.json({ isAuthenticated: false });
  }
});

app.get('/auth/profile', (req, res) => {
  if (!isAuth0Configured) {
    return res.status(401).json({ error: 'Auth0 not configured' });
  }
  
  if (req.oidc && req.oidc.isAuthenticated()) {
    res.json(req.oidc.user);
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// SCIM Bearer token authentication middleware
function authenticateSCIM(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Authorization header is required",
      status: "401"
    });
  }

  const token = authHeader.substring(7);
  if (token !== process.env.SCIM_TOKEN) {
    return res.status(401).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Invalid SCIM token",
      status: "401"
    });
  }

  next();
}

// SCIM v2 Endpoints
// Get all users
app.get('/scim/v2/Users', authenticateSCIM, (req, res) => {
  try {
    const usersData = loadUsers();
    const startIndex = parseInt(req.query.startIndex) || 1;
    const count = parseInt(req.query.count) || 100;
    
    // Apply pagination
    const startIdx = startIndex - 1;
    const endIdx = startIdx + count;
    const paginatedUsers = usersData.users.slice(startIdx, endIdx);
    
    res.json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
      totalResults: usersData.users.length,
      startIndex: startIndex,
      itemsPerPage: paginatedUsers.length,
      Resources: paginatedUsers
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Internal server error",
      status: "500"
    });
  }
});

// Get user by ID
app.get('/scim/v2/Users/:id', authenticateSCIM, (req, res) => {
  try {
    const user = findUserById(req.params.id);
    if (!user) {
      return res.status(404).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User not found",
        status: "404"
      });
    }
    res.json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Internal server error",
      status: "500"
    });
  }
});

// Create user
app.post('/scim/v2/Users', authenticateSCIM, (req, res) => {
  try {
    const userData = req.body;
    const usersData = loadUsers();
    
    // Check if user already exists
    if (userData.emails && userData.emails.length > 0) {
      const existingUser = findUserByEmail(userData.emails[0].value);
      if (existingUser) {
        return res.status(409).json({
          schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
          detail: "User already exists",
          status: "409"
        });
      }
    }
    
    // Create new user
    const newUser = {
      schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
      id: uuidv4(),
      userName: userData.userName,
      name: userData.name || {},
      emails: userData.emails || [],
      active: userData.active !== undefined ? userData.active : true,
      meta: {
        resourceType: "User",
        created: new Date().toISOString(),
        lastModified: new Date().toISOString(),
        location: `/scim/v2/Users/${uuidv4()}`
      }
    };
    
    // Update location with actual ID
    newUser.meta.location = `/scim/v2/Users/${newUser.id}`;
    
    usersData.users.push(newUser);
    usersData.totalResults = usersData.users.length;
    
    if (saveUsers(usersData)) {
      res.status(201).json(newUser);
    } else {
      res.status(500).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Failed to save user",
        status: "500"
      });
    }
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Internal server error",
      status: "500"
    });
  }
});

// Update user (PUT)
app.put('/scim/v2/Users/:id', authenticateSCIM, (req, res) => {
  try {
    const usersData = loadUsers();
    const userIndex = usersData.users.findIndex(user => user.id === req.params.id);
    
    if (userIndex === -1) {
      return res.status(404).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User not found",
        status: "404"
      });
    }
    
    const userData = req.body;
    const existingUser = usersData.users[userIndex];
    
    // Update user data
    const updatedUser = {
      ...existingUser,
      userName: userData.userName || existingUser.userName,
      name: userData.name || existingUser.name,
      emails: userData.emails || existingUser.emails,
      active: userData.active !== undefined ? userData.active : existingUser.active,
      meta: {
        ...existingUser.meta,
        lastModified: new Date().toISOString()
      }
    };
    
    usersData.users[userIndex] = updatedUser;
    
    if (saveUsers(usersData)) {
      res.json(updatedUser);
    } else {
      res.status(500).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Failed to update user",
        status: "500"
      });
    }
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Internal server error",
      status: "500"
    });
  }
});

// Delete user
app.delete('/scim/v2/Users/:id', authenticateSCIM, (req, res) => {
  try {
    const usersData = loadUsers();
    const userIndex = usersData.users.findIndex(user => user.id === req.params.id);
    
    if (userIndex === -1) {
      return res.status(404).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "User not found",
        status: "404"
      });
    }
    
    usersData.users.splice(userIndex, 1);
    usersData.totalResults = usersData.users.length;
    
    if (saveUsers(usersData)) {
      res.status(204).send();
    } else {
      res.status(500).json({
        schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
        detail: "Failed to delete user",
        status: "500"
      });
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail: "Internal server error",
      status: "500"
    });
  }
});

// SCIM Schema endpoint
app.get('/scim/v2/Schemas', authenticateSCIM, (req, res) => {
  res.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: 1,
    startIndex: 1,
    itemsPerPage: 1,
    Resources: [
      {
        schemas: ["urn:ietf:params:scim:schemas:core:2.0:Schema"],
        id: "urn:ietf:params:scim:schemas:core:2.0:User",
        name: "User",
        description: "User Account",
        attributes: [
          {
            name: "userName",
            type: "string",
            multiValued: false,
            description: "Unique identifier for the User",
            required: true,
            caseExact: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "server"
          },
          {
            name: "name",
            type: "complex",
            multiValued: false,
            description: "The components of the user's real name",
            required: false,
            subAttributes: [
              {
                name: "formatted",
                type: "string",
                multiValued: false,
                description: "The full name",
                required: false,
                caseExact: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              },
              {
                name: "familyName",
                type: "string",
                multiValued: false,
                description: "The family name of the User",
                required: false,
                caseExact: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              },
              {
                name: "givenName",
                type: "string",
                multiValued: false,
                description: "The given name of the User",
                required: false,
                caseExact: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              }
            ],
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          {
            name: "emails",
            type: "complex",
            multiValued: true,
            description: "Email addresses for the user",
            required: false,
            subAttributes: [
              {
                name: "value",
                type: "string",
                multiValued: false,
                description: "Email addresses for the user",
                required: false,
                caseExact: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              },
              {
                name: "type",
                type: "string",
                multiValued: false,
                description: "A label indicating the attribute's function",
                required: false,
                caseExact: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              },
              {
                name: "primary",
                type: "boolean",
                multiValued: false,
                description: "A Boolean value indicating the 'primary' or preferred attribute value for this attribute",
                required: false,
                mutability: "readWrite",
                returned: "default",
                uniqueness: "none"
              }
            ],
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          },
          {
            name: "active",
            type: "boolean",
            multiValued: false,
            description: "A Boolean value indicating the User's administrative status",
            required: false,
            mutability: "readWrite",
            returned: "default",
            uniqueness: "none"
          }
        ],
        meta: {
          resourceType: "Schema",
          location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"
        }
      }
    ]
  });
});

// Routes
app.get('/', (req, res) => {
  // In production, serve the static HTML file directly instead of using EJS
  if (process.env.NODE_ENV === 'production') {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    // In development, use EJS if available
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
});

// File upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ 
        error: 'No file uploaded',
        details: 'Please select a file to upload'
      });
    }

    if (!['image/jpeg', 'image/png', 'application/pdf'].includes(req.file.mimetype)) {
      return res.status(400).json({ 
        error: 'Invalid file type',
        details: 'Only JPEG, PNG, and PDF files are allowed'
      });
    }

    // Read file and convert to base64
    try {
      const fileBuffer = fs.readFileSync(req.file.path);
      const base64Data = fileBuffer.toString('base64');

      // Prepare request data
      const requestData = {
        fileName: req.file.originalname,
        companyId: req.body.companyId || 'unknown',  // Get companyId from form
        userId: req.body.userId || 'unknown',        // Get userId from form
        fileId: req.body.fileId || Date.now(),       // Get fileId from form or use timestamp
        fileData: base64Data
      };

      // Get auth token and product name from form
      const authToken = req.body.authToken;
      const productName = req.body.productName;
      
      // Make API request
      const response = await makeApiRequest(requestData, authToken, productName);
      
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      
      // Upload successful - no notification added to messages array
      
      res.json({ 
        success: true, 
        message: 'File uploaded successfully, receipt-flow is processing your receipt. it may take a few moments. Please check the notification bell for updates.', 
        apiResponse: response,
        fileName: req.file.originalname
      });
    } catch (fileError) {
      console.error('Error processing file:', fileError);
      res.status(500).json({ 
        error: 'File processing failed',
        details: fileError.message
      });
    }
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(error.response?.status || 500).json({ 
      error: 'Failed to upload file',
      details: error.message
    });
  }
});

// SQS polling function
async function pollSQSMessages() {
  try {
    // SQS queue URL should be in environment variables
    const queueUrl = process.env.SQS_QUEUE_URL;
    
    if (!queueUrl) {
      console.error('SQS_QUEUE_URL environment variable is not set');
      return [];
    }
    
    const params = {
      QueueUrl: queueUrl,
      MaxNumberOfMessages: 10,
      VisibilityTimeout: 20,
      WaitTimeSeconds: 0
    };
    
    const data = await sqs.receiveMessage(params).promise();
    
    if (!data.Messages || data.Messages.length === 0) {
      console.log('No SQS messages available');
      return [];
    }
    
    console.log(`Received ${data.Messages.length} messages from SQS`);
    
    // Process and store each message
    for (const message of data.Messages) {
      try {
        // Parse message body
        let messageBody;
        try {
          messageBody = JSON.parse(message.Body);
        } catch (e) {
          messageBody = { raw: message.Body };
        }
        
        // Store the message
        await storeMessage({
          type: 'SQS',
          timestamp: new Date().toISOString(),
          data: messageBody,
          messageId: message.MessageId
        });
        
        // Delete the message from the queue after processing
        await sqs.deleteMessage({
          QueueUrl: queueUrl,
          ReceiptHandle: message.ReceiptHandle
        }).promise();
        
        console.log(`Deleted message ${message.MessageId} from queue`);
      } catch (messageError) {
        console.error('Error processing SQS message:', messageError);
      }
    }
    
    return data.Messages;
  } catch (error) {
    console.error('Error polling SQS:', error);
    return [];
  }
}

// Store messages in memory only
let messages = [];

// Initialize empty messages array
async function loadMessages() {
  console.log('Initializing empty messages array');
  messages = [];
}

// No-op function as we're not saving messages to file anymore
async function saveMessages() {
  // Messages are kept in memory only
  return;
}

// Store message in memory only
async function storeMessage(message) {
  messages.push(message);
  if (messages.length > 10) { // Keep only last 10 messages
    messages.shift();
  }
  // No need to call saveMessages() as we're not persisting to file
}

// Verify SNS message signature (best practice for production)
function verifySnsMessage(message) {
  // In a production environment, you should verify the SNS signature
  // For now, we'll just log and return true
  console.log('SNS message verification would happen here');
  return true;
}

// API request function
async function makeApiRequest(data, authToken, productName) {
  const axios = require('axios');
  
  try {
    const response = await axios({
      method: 'POST',
      url: process.env.API_ENDPOINT || 'https://c1m6jrqkme.execute-api.eu-north-1.amazonaws.com/api/post-file',
      headers: {
        'Authorization': authToken || process.env.API_AUTH_TOKEN || 'huHMqgrSteTKbaM84B3T4izJsChFpm6R',
        'Content-Type': 'application/json',
        'Product-Name': productName || process.env.PRODUCT_NAME || 'milient-test-product'
      },
      data: data // axios will automatically stringify the JSON
    });
    
    return response.data;
  } catch (error) {
    console.error('API request error:', error.message);
    if (error.response) {
      console.error('Response status:', error.response.status);
      console.error('Response data:', error.response.data);
    }
    throw error;
  }
}

// SQS polling endpoint
app.get('/api/sqs/poll', async (req, res) => {
  try {
    console.log('SQS poll request received');
  
    // If we have a valid AWS connection (either via profile or credentials), use the real SQS service
    console.log('Using real SQS service');
    const messages = await pollSQSMessages();
    res.json(messages);
  } catch (error) {
    console.error('Error in SQS polling endpoint:', error);
    res.status(500).json({ error: 'Failed to poll SQS messages', details: error.message });
  }
});

// Messages endpoint
app.get('/messages', (req, res) => {
  res.json(messages);
});

// AWS SNS endpoint
app.post('/api/sns', bodyParser.json(), async (req, res) => {
  try {
    const message = req.body;
    console.log('Received SNS message:', message);
    
    if(message.userId === "1234") {
        console.log('Fail for test SNS DLQ');
      // Return a 500 status to force SNS to retry
      // This will eventually send the message to a Dead Letter Queue (DLQ) if configured
      console.log('Deliberately failing this message to test SNS DLQ');
      return res.status(500).send('Deliberately failing this message for SNS DLQ testing');
    }

    // Store all SNS messages for display regardless of type
    await storeMessage({
      type: 'SNS',
      timestamp: new Date().toISOString(),
      data: message
    });
    
    // Check message type and handle accordingly
    if (message.Type === 'SubscriptionConfirmation') {
      console.log('Received SNS subscription confirmation request');
      console.log('SubscribeURL:', message.SubscribeURL);
      
      // Auto-confirm the subscription by sending a GET request to the SubscribeURL
      try {
        const axios = require('axios');
        const response = await axios.get(message.SubscribeURL);
        
        console.log('Subscription confirmed successfully:', response.data);
        
        // Store success message
        await storeMessage({
          type: 'SNS',
          timestamp: new Date().toISOString(),
          data: {
            Type: 'SubscriptionConfirmationSuccess',
            TopicArn: message.TopicArn,
            Message: 'Subscription confirmed automatically',
            OriginalMessageId: message.MessageId,
            Timestamp: new Date().toISOString()
          }
        });
        
        res.status(200).send('Subscription confirmed');
      } catch (confirmError) {
        console.error('Error confirming subscription:', confirmError);
        res.status(500).send('Error confirming subscription');
      }
    } else if (message.Type === 'UnsubscribeConfirmation') {
      console.log('Received SNS unsubscribe confirmation');
      // No action needed, just acknowledge receipt
      res.status(200).send('Unsubscribe confirmation received');
    } else if (message.Type === 'Notification') {
      console.log('Received SNS notification:', message.Subject || 'No Subject');
      
      // Verify message signature in production environment
      if (verifySnsMessage(message)) {
        // Notification handling is complete, just respond with success
        res.status(200).send('Message processed successfully');
      } else {
        console.error('SNS message signature verification failed');
        res.status(403).send('Message verification failed');
      }
    } else {
      console.log('Received unknown message type:', message);
      res.status(200).send('Message received');
    }
  } catch (error) {
    console.error('Error processing SNS message:', error);
    
    // Even on error, store the message for debugging
    try {
      await storeMessage({
        type: 'SNS',
        timestamp: new Date().toISOString(),
        data: { error: error.message, originalRequest: req.body },
        error: error.message
      });
    } catch (storeError) {
      console.error('Failed to store error message:', storeError);
    }
    
    res.status(500).send('Error processing SNS message');
  }
});

// Only start the server if we're not in a serverless environment
if (process.env.NODE_ENV !== 'production') {
  // Load messages before starting the server
  loadMessages().then(async () => {
    // Check SQS connection before starting the server
    console.log('\n===  AWS SQS CONNECTION CHECK ===');
    const sqsConnected = await checkSQSConnection();
    console.log('=== SQS CONNECTION STATUS: ' + (sqsConnected ? 'CONNECTED ✅' : 'NOT CONNECTED ❌') + ' ===\n');
    
    app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  });
} else {
  // For serverless environment, load messages on module initialization
  loadMessages().then(async () => {
    // Check SQS connection in production environment
    console.log('\n=== AWS SQS CONNECTION CHECK (PRODUCTION) ===');
    const sqsConnected = await checkSQSConnection();
   console.log('=== SQS CONNECTION STATUS: ' + (sqsConnected ? 'CONNECTED ✅' : 'NOT CONNECTED ❌') + ' ===\n');
       app.listen(port, () => {
      console.log(`Server running on port ${port}`);
    });
  });
}

// Export the app for Vercel serverless deployment
module.exports = app;
