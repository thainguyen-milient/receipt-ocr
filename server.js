require('dotenv').config();
const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');

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
  // In production (Vercel), use environment variables for AWS credentials
  AWS.config.update({
    region: process.env.AWS_REGION || 'eu-north-1',
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  });
} else {
  // In local development, use profile credentials
  AWS.config.update({
    region: process.env.AWS_REGION || 'eu-north-1',
    credentials: new AWS.SharedIniFileCredentials({ profile: '074993326121_LocalDevelopmentAccess' })
  });
}

const sqs = new AWS.SQS();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));
app.set('view engine', 'ejs');

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
        message: 'File uploaded successfully', 
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

// SQS function has been removed

// Store messages for display
let messages = [];
function storeMessage(message) {
  messages.push(message);
  if (messages.length > 10) { // Keep only last 10 messages
    messages.shift();
  }
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

// SQS polling has been removed

// Messages endpoint
app.get('/messages', (req, res) => {
  res.json(messages);
});

// AWS SNS endpoint
app.post('/api/sns', bodyParser.json(), async (req, res) => {
  try {
    const message = req.body;
    console.log('Received SNS message:', message);
    
    // Store all SNS messages for display regardless of type
    storeMessage({
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
        storeMessage({
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
      storeMessage({
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
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

// Export the app for Vercel serverless deployment
module.exports = app;
