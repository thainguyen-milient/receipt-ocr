require('dotenv').config();
const AWS = require('aws-sdk');

// Configure AWS SDK to use default profile
AWS.config.update({
  region: process.env.AWS_REGION || 'eu-north-1'
});

// Create SQS service object
const sqs = new AWS.SQS();

// Sample SQS message that matches our expected structure
const sampleMessage = {
  s3Key: 'receipts/sample-receipt-123.jpg',
  s3Bucket: 'receipt-bucket',
  fileName: 'sample-receipt-123.jpg',
  customerId: 'customer-456',
  userId: 'user-789',
  productName: 'milient-test-product',
  success: true,
  message: 'Receipt processed successfully',
  receiptData: 'Sample receipt data content',
  preSignedUrl: 'https://via.placeholder.com/800x600.png?text=Sample+Receipt+Image'
};

// Send message to SQS queue
async function sendTestMessage() {
  const params = {
    MessageBody: JSON.stringify(sampleMessage),
    QueueUrl: process.env.SQS_QUEUE_URL
  };

  try {
    const data = await sqs.sendMessage(params).promise();
    console.log('Success', data.MessageId);
  } catch (err) {
    console.error('Error', err);
  }
}

sendTestMessage();
