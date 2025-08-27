require('dotenv').config();
const express = require('express');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const { promises: fsPromises } = require('fs');

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
    if (error.code === 'CredentialsError') {
      console.error('❌ AWS credentials are missing or invalid');
    } else if (error.code === 'AWS.SimpleQueueService.NonExistentQueue') {
      console.error('❌ SQS queue does not exist:', process.env.SQS_QUEUE_URL);
    } else if (error.code === 'NetworkingError') {
      console.error('❌ Network error when connecting to AWS SQS');
    }
    return false;
  }
}

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

// Store messages for display with file persistence
let messages = [];
const messagesFilePath = path.join(__dirname, 'messages.json');

// Load messages from file on startup
async function loadMessages() {
  try {
    if (fs.existsSync(messagesFilePath)) {
      const data = await fsPromises.readFile(messagesFilePath, 'utf8');
      messages = JSON.parse(data);
      console.log(`Loaded ${messages.length} messages from storage`);
    } else {
      console.log('No messages file found, starting with empty messages array');
      messages = [];
    }
  } catch (error) {
    console.error('Error loading messages from file:', error);
    messages = [];
  }
}

// Save messages to file
async function saveMessages() {
  try {
    await fsPromises.writeFile(messagesFilePath, JSON.stringify(messages, null, 2));
  } catch (error) {
    console.error('Error saving messages to file:', error);
  }
}

// Store message in memory and persist to file
async function storeMessage(message) {
  messages.push(message);
  if (messages.length > 10) { // Keep only last 10 messages
    messages.shift();
  }
  await saveMessages();
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
    
    // Check if we should use mock data (no AWS credentials, failed connection, or in development)
    if (!sqsConnected || !process.env.AWS_ACCESS_KEY_ID || process.env.NODE_ENV === 'development') {
      console.log('Using mock SQS data (connection status: ' + (sqsConnected ? 'connected' : 'not connected') + ')');
      
      // Define mock messages for testing
      const mockMessages = [
        {
          MessageId: 'mock-msg-' + Date.now(),
          ReceiptHandle: 'mock-receipt-handle',
          Body: JSON.stringify({
            s3Key: 'receipts/mock-receipt-123.jpg',
            s3Bucket: 'mock-receipt-bucket',
            fileName: 'mock-receipt-123.jpg',
            customerId: 'customer-456',
            userId: 'user-789',
            productName: 'milient-test-product',
            success: true,
            message: 'Mock receipt processed successfully',
            receiptData: JSON.stringify([{
              merchantName: 'Mock Coffee Shop',
              merchantAddress: '123 Mock Street\nMock City, MC 12345',
              merchantPhoneNumber: '555-123-4567',
              date: '2025-08-27',
              time: '10:00 AM',
              total: 12.99,
              currency: 'USD',
              items: [
                { name: 'Coffee', price: 4.99, quantity: 1 },
                { name: 'Sandwich', price: 8.00, quantity: 1 }
              ],
              paymentMethod: 'Credit Card',
              cardLast4: '1234'
            }]),
            preSignedUrl: 'https://via.placeholder.com/800x600.png?text=Mock+Receipt+Image'
          })
        }
      ];
      
      // Store the mock messages
      for (const message of mockMessages) {
        try {
          let messageBody;
          try {
            messageBody = JSON.parse(message.Body);
          } catch (e) {
            messageBody = { raw: message.Body };
          }
          
          await storeMessage({
            type: 'SQS',
            timestamp: new Date().toISOString(),
            data: messageBody,
            messageId: message.MessageId
          });
          
          console.log(`Stored mock message ${message.MessageId}`);
        } catch (messageError) {
          console.error('Error processing mock SQS message:', messageError);
        }
      }
      
      return res.json(mockMessages);
    }
    
    // If we have AWS credentials, use the real SQS service
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
        res.status(500).send('Error for test DLQ');
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
  });
}

// Export the app for Vercel serverless deployment
module.exports = app;
