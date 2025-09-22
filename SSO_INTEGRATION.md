# Windsurf SSO Gateway Integration

This document explains how the Windsurf project has been integrated with the SSO Gateway for single sign-on authentication.

## Overview

The integration allows users to:
1. Login to Windsurf via the SSO Gateway using Auth0
2. Receive a Windsurf-specific JWT token after successful authentication
3. Use the JWT token for API access
4. Logout via the SSO Gateway

## Configuration

### Environment Variables

The following environment variables must be set in the `.env` file:

```
# SSO Gateway Configuration
SSO_GATEWAY_URL=http://localhost:3000
SSO_GATEWAY_PRODUCT_ID=windsurf
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRES_IN=24h
SESSION_SECRET=windsurf-session-secret-key
BASE_URL=http://localhost:3001
```

**Note:** The `JWT_SECRET` must match the one used in the SSO Gateway for token validation.

### SSO Gateway Configuration

The SSO Gateway must be configured to recognize Windsurf as a product:

1. Add Windsurf to the allowed products in the SSO Gateway
2. Set the Windsurf URL in the SSO Gateway's `.env` file:
   ```
   WINDSURF_URL=http://localhost:3001
   ```

## Authentication Flow

### Login Flow

1. User clicks "Login" on the Windsurf homepage
2. User is redirected to the SSO Gateway login page
3. After successful authentication with Auth0, the SSO Gateway generates a JWT token
4. User is redirected to Windsurf's SSO callback endpoint with the token
5. Windsurf validates the token and creates its own JWT token
6. The Windsurf token is stored as an HTTP-only cookie and user information is stored in session
7. User is now authenticated in Windsurf

### Logout Flow

1. User clicks "Logout" on the Windsurf homepage
2. Windsurf clears its token cookie and session
3. User is redirected to the SSO Gateway logout endpoint
4. SSO Gateway logs the user out of Auth0
5. User is redirected back to the SSO Gateway

## Authentication Methods

The Windsurf project uses multiple authentication methods:

1. **JWT Token**: Stored as an HTTP-only cookie and used for API authentication
2. **Session**: Stores user information for server-side authentication
3. **Auth0 Direct**: Fallback if SSO Gateway is not configured

## API Authentication

The Windsurf API endpoints can be accessed using the JWT token in one of three ways:

1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Query Parameter**: `?token=<token>`
3. **Cookie**: The token is automatically included in requests as an HTTP-only cookie

## Testing the Integration

To test the SSO integration:

1. Start the SSO Gateway:
   ```
   cd ../SSO-Gateway
   npm run dev
   ```

2. Start the Windsurf project:
   ```
   cd ../CascadeProjects/windsurf-project
   npm run dev
   ```

3. Open a browser and navigate to `http://localhost:3001`
4. Click "Login"
5. Complete the Auth0 login process
6. You should be redirected back to Windsurf and be authenticated

## Endpoints

### Authentication Endpoints

- `GET /auth/login` - Redirect to SSO Gateway login
- `GET /auth/logout` - Logout and redirect to SSO Gateway logout
- `GET /auth/sso-callback` - Handle SSO Gateway callback with token
- `GET /auth/profile` - Get user profile (requires authentication)
- `GET /auth/status` - Check authentication status
- `POST /auth/token` - Generate JWT token (requires authentication)

## Troubleshooting

If you encounter issues with the SSO integration:

1. Check that both services are running
2. Verify that the `JWT_SECRET` matches between the two services
3. Check the console logs for error messages
4. Ensure the SSO Gateway is properly configured to recognize Windsurf as a product
5. Verify that the callback URL is correctly set up in the SSO Gateway

## Security Considerations

- The JWT token is stored as an HTTP-only cookie to prevent XSS attacks
- HTTPS should be used in production to prevent token interception
- Token expiration is set to 24 hours by default
- The JWT secret should be a strong, random string
- Session data is stored server-side for additional security
