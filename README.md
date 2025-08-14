# AWS SNS Message Receiver

A Node.js Express application that receives AWS SNS notifications, automatically confirms subscriptions, and displays messages in a web interface.

## Features

- Receives SNS notifications via public endpoint
- Automatically confirms SNS topic subscriptions
- Displays SNS messages in real-time
- Supports file uploads with receipt processing
- Beautiful UI with notification system

## Local Development

1. Install dependencies:
   ```
   npm install
   ```

2. Create a `.env` file with the following variables:
   ```
   AWS_REGION=your-aws-region
   API_ENDPOINT=your-api-endpoint
   API_AUTH_TOKEN=your-auth-token
   PRODUCT_NAME=your-product-name
   ```

3. Run the application:
   ```
   npm run dev
   ```

4. Access the application at `http://localhost:3000`

## Vercel Deployment

1. Install the Vercel CLI:
   ```
   npm install -g vercel
   ```

2. Login to Vercel:
   ```
   vercel login
   ```

3. Deploy the application:
   ```
   vercel
   ```

4. Set environment variables in the Vercel dashboard:
   - `AWS_REGION`
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`
   - `API_ENDPOINT`
   - `API_AUTH_TOKEN`
   - `PRODUCT_NAME`

5. For production deployment:
   ```
   vercel --prod
   ```

## AWS SNS Configuration

1. Create an SNS topic in AWS console
2. Create a subscription with:
   - Protocol: HTTPS
   - Endpoint: Your Vercel URL + `/api/sns`

## Project Structure

- `server.js` - Main application entry point
- `public/` - Static assets and frontend code
- `uploads/` - Temporary storage for file uploads
- `vercel.json` - Vercel deployment configuration
