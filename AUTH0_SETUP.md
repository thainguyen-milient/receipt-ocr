# Auth0 and SCIM Integration Setup Guide

This document provides instructions for setting up Auth0 authentication and SCIM v2 user provisioning for the Receipt Uploader application.

## Features Implemented

✅ **Auth0 Authentication**
- Login/logout functionality using Auth0
- User profile display with name and avatar
- Session management
- Protected routes

✅ **SCIM v2 User Provisioning**
- Complete SCIM v2 API endpoints
- User CRUD operations (Create, Read, Update, Delete)
- JSON file-based user storage
- Bearer token authentication for SCIM endpoints

✅ **UI Integration**
- Login button in top left corner
- "Hello [username]" display after login
- Logout button when authenticated
- User avatar display (if available)

## Auth0 Configuration

### 1. Create Auth0 Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Create a new **Regular Web Application**
3. Note down the following values:
   - Domain
   - Client ID
   - Client Secret

### 2. Configure Application Settings

In your Auth0 application settings:

**Allowed Callback URLs:**
```
http://localhost:3000/callback
```

**Allowed Logout URLs:**
```
http://localhost:3000
```

**Allowed Web Origins:**
```
http://localhost:3000
```

### 3. Environment Variables

Copy `.env.example` to `.env` and update the following variables:

```env
# Auth0 Configuration
AUTH0_SECRET=your-long-random-string-here
AUTH0_BASE_URL=http://localhost:3000
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_ISSUER_BASE_URL=https://your-domain.auth0.com

# SCIM Configuration
SCIM_TOKEN=your-secure-scim-bearer-token
```

**Important:** 
- `AUTH0_SECRET` should be a long, random string (at least 32 characters)
- `AUTH0_ISSUER_BASE_URL` should be your Auth0 domain with `https://` prefix
- `SCIM_TOKEN` should be a secure token for SCIM API authentication

## SCIM v2 Endpoints

The application provides the following SCIM v2 endpoints:

### Authentication
All SCIM endpoints require Bearer token authentication:
```
Authorization: Bearer your-scim-token-here
```

### Available Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/scim/v2/Users` | List all users with pagination |
| GET | `/scim/v2/Users/{id}` | Get user by ID |
| POST | `/scim/v2/Users` | Create new user |
| PUT | `/scim/v2/Users/{id}` | Update user |
| DELETE | `/scim/v2/Users/{id}` | Delete user |
| GET | `/scim/v2/Schemas` | Get SCIM schema information |

### Example SCIM User Object

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "id": "12345678-1234-1234-1234-123456789012",
  "userName": "john.doe@example.com",
  "name": {
    "formatted": "John Doe",
    "familyName": "Doe",
    "givenName": "John"
  },
  "emails": [
    {
      "value": "john.doe@example.com",
      "type": "work",
      "primary": true
    }
  ],
  "active": true,
  "meta": {
    "resourceType": "User",
    "created": "2023-01-01T00:00:00.000Z",
    "lastModified": "2023-01-01T00:00:00.000Z",
    "location": "/scim/v2/Users/12345678-1234-1234-1234-123456789012"
  }
}
```

## Auth0 SCIM Configuration

### 1. Enable SCIM in Auth0

1. Go to **User Management > Users** in Auth0 Dashboard
2. Click on **Extensions** tab
3. Install and configure **SCIM v2** extension

### 2. Configure SCIM Endpoint

In Auth0 SCIM configuration:

**SCIM Endpoint URL:**
```
http://your-domain.com/scim/v2
```

**Bearer Token:**
```
your-scim-bearer-token
```

## Installation and Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your Auth0 and SCIM configuration
```

### 3. Start the Application

```bash
npm run dev
```

### 4. Test Authentication

1. Navigate to `http://localhost:3000`
2. Click the "Login" button in the top left corner
3. Complete Auth0 authentication flow
4. Verify "Hello [username]" appears with logout button

## User Data Storage

User data is stored in `users.json` file with the following structure:

```json
{
  "users": [],
  "totalResults": 0,
  "itemsPerPage": 100,
  "startIndex": 1,
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
}
```

## Testing SCIM Endpoints

### Create User
```bash
curl -X POST http://localhost:3000/scim/v2/Users \
  -H "Authorization: Bearer your-scim-token" \
  -H "Content-Type: application/json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "test@example.com",
    "name": {
      "formatted": "Test User",
      "familyName": "User",
      "givenName": "Test"
    },
    "emails": [
      {
        "value": "test@example.com",
        "type": "work",
        "primary": true
      }
    ],
    "active": true
  }'
```

### List Users
```bash
curl -X GET http://localhost:3000/scim/v2/Users \
  -H "Authorization: Bearer your-scim-token"
```

### Get User by ID
```bash
curl -X GET http://localhost:3000/scim/v2/Users/{user-id} \
  -H "Authorization: Bearer your-scim-token"
```

## Security Considerations

1. **Environment Variables**: Never commit `.env` file to version control
2. **SCIM Token**: Use a strong, unique bearer token for SCIM authentication
3. **Auth0 Secret**: Generate a cryptographically secure secret key
4. **HTTPS**: Use HTTPS in production environments
5. **Session Security**: Configure secure session settings for production

## Troubleshooting

### Common Issues

1. **Auth0 Configuration Error**: Verify callback URLs and domain settings
2. **SCIM Authentication Failed**: Check bearer token configuration
3. **User Not Found**: Verify user exists in `users.json`
4. **Session Issues**: Clear browser cookies and restart application

### Debug Mode

Enable debug logging by setting:
```env
DEBUG=express-openid-connect:*
```

## Production Deployment

For production deployment:

1. Update `AUTH0_BASE_URL` to your production domain
2. Configure Auth0 application with production URLs
3. Use HTTPS for all endpoints
4. Set secure session configuration
5. Consider using a database instead of JSON file for user storage
6. Implement proper error handling and logging

## Vercel Deployment

The application is configured for Vercel deployment with the following features:

### Environment Variables for Vercel

Set these environment variables in your Vercel project settings:

```env
# Auth0 Configuration
AUTH0_SECRET=your-long-random-string-here
AUTH0_BASE_URL=https://your-vercel-domain.vercel.app
AUTH0_CLIENT_ID=your-auth0-client-id
AUTH0_ISSUER_BASE_URL=https://your-domain.auth0.com

# SCIM Configuration
SCIM_TOKEN=your-secure-scim-bearer-token

# AWS Configuration (if needed)
AWS_REGION=eu-north-1
SQS_QUEUE_URL=your-sqs-queue-url
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key

# API Configuration
API_ENDPOINT=your-api-endpoint
API_AUTH_TOKEN=your-api-token
PRODUCT_NAME=your-product-name
```

### Auth0 Configuration for Vercel

Update your Auth0 application settings with Vercel URLs:

**Allowed Callback URLs:**
```
https://your-vercel-domain.vercel.app/callback
```

**Allowed Logout URLs:**
```
https://your-vercel-domain.vercel.app
```

**Allowed Web Origins:**
```
https://your-vercel-domain.vercel.app
```

### Vercel Routes Configuration

The `vercel.json` file includes routes for:
- `/auth/*` - Auth0 authentication endpoints
- `/scim/*` - SCIM v2 API endpoints  
- `/login` - Auth0 login
- `/logout` - Auth0 logout
- `/callback` - Auth0 callback
- Static assets (`.webp` files included)

### Deployment Steps

1. **Push to Git repository**
2. **Connect repository to Vercel**
3. **Set environment variables in Vercel dashboard**
4. **Update Auth0 application settings with Vercel domain**
5. **Deploy and test authentication flow**
