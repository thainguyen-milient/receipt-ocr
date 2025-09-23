const express = require('express');
const jwt = require('jsonwebtoken');
const { generateToken, verifyToken, extractToken } = require('../utils/authMiddleware');
const router = express.Router();
const cookieParser = require('cookie-parser');

// Add cookie parser middleware
router.use(cookieParser());

// Login route - redirect to SSO Gateway
router.get('/login', (req, res) => {
  // Determine return URL based on environment
  const returnTo = req.query.returnTo || process.env.BASE_URL || 
    (process.env.NODE_ENV === 'production' ? 'https://receipt-flow.io.vn' : 'http://localhost:3001');
  
  // Determine SSO Gateway URL based on environment
  const ssoGatewayUrl = process.env.SSO_GATEWAY_URL || 
    (process.env.NODE_ENV === 'production' ? 'https://sso.receipt-flow.io.vn' : 'http://localhost:3000');
  
  console.log(`Login initiated, redirecting to SSO Gateway: ${ssoGatewayUrl} with returnTo: ${returnTo}`);
  
  // Always redirect to SSO Gateway for login
  return res.redirect(`${ssoGatewayUrl}/auth/login?productId=receipt&returnTo=${encodeURIComponent(returnTo)}`);
});

// Logout route
router.get('/logout', (req, res) => {
  // Cookie options for receipt subdomain
  const receiptOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: 'receipt.receipt-flow.io.vn', // Updated to match new subdomain
    path: '/'
  };

  const receiptClientOptions = {
    httpOnly: false,
    secure: true,
    sameSite: 'none',
    domain: 'receipt.receipt-flow.io.vn', // Updated to match new subdomain
    path: '/'
  };
  
  // Cookie options for main domain with leading dot
  const mainDomainOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: '.receipt-flow.io.vn', // Leading dot for subdomain sharing
    path: '/'
  };

  const mainDomainClientOptions = {
    httpOnly: false,
    secure: true,
    sameSite: 'none',
    domain: '.receipt-flow.io.vn', // Leading dot for subdomain sharing
    path: '/'
  };
  
  // Cookie options for SSO subdomain
  const ssoOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    domain: 'sso.receipt-flow.io.vn',
    path: '/'
  };

  const ssoClientOptions = {
    httpOnly: false,
    secure: true,
    sameSite: 'none',
    domain: 'sso.receipt-flow.io.vn',
    path: '/'
  };
  
  // Clear cookies on receipt subdomain
  res.clearCookie('access_token', receiptOptions);
  res.clearCookie('receipt_token', receiptOptions);
  res.clearCookie('receipt_token_client', receiptClientOptions);
  res.clearCookie('sso_token', receiptOptions);
  res.clearCookie('sso_token_client', receiptClientOptions);
  res.clearCookie('id_token', receiptOptions);
  res.clearCookie('windsurf_token', receiptOptions);
  
  // Clear cookies on main domain with leading dot
  res.clearCookie('access_token', mainDomainOptions);
  res.clearCookie('access_token_shared', mainDomainOptions);
  res.clearCookie('receipt_token', mainDomainOptions);
  res.clearCookie('receipt_token_client', mainDomainClientOptions);
  res.clearCookie('sso_token', mainDomainOptions);
  res.clearCookie('sso_token_client', mainDomainClientOptions);
  res.clearCookie('id_token', mainDomainOptions);
  res.clearCookie('windsurf_token', mainDomainOptions);
  
  // Clear cookies on SSO subdomain
  res.clearCookie('access_token', ssoOptions);
  res.clearCookie('sso_token', ssoOptions);
  res.clearCookie('sso_token_client', ssoClientOptions);
  res.clearCookie('id_token', ssoOptions);
  
  // Also try clearing without domain for local cookies
  res.clearCookie('access_token');
  res.clearCookie('receipt_token');
  res.clearCookie('receipt_token_client');
  res.clearCookie('sso_token');
  res.clearCookie('sso_token_client');
  res.clearCookie('id_token');
  res.clearCookie('windsurf_token');
  
  // Clear session
  if (req.session) {
    req.session.destroy();
  }
  
  // Check if this is a global logout
  const isGlobalLogout = req.query.global === 'true';
  const returnTo = req.query.returnTo || process.env.BASE_URL || 
    (process.env.NODE_ENV === 'production' ? 'https://receipt-flow.io.vn' : 'http://localhost:3001');
  
  // Determine SSO Gateway URL
  const ssoGatewayUrl = process.env.SSO_GATEWAY_URL || 
    (process.env.NODE_ENV === 'production' ? 'https://sso.receipt-flow.io.vn' : 'http://localhost:3000');
  
  console.log(`Logout initiated (${isGlobalLogout ? 'global' : 'local'})`);
  
  // For global logout, redirect to SSO Gateway with global=true parameter
  if (isGlobalLogout) {
    return res.redirect(`${ssoGatewayUrl}/auth/logout?global=true&returnTo=${encodeURIComponent(returnTo)}`);
  }
  
  // For regular logout, just redirect to SSO Gateway
  return res.redirect(`${ssoGatewayUrl}/auth/logout?returnTo=${encodeURIComponent(returnTo)}`);
});

// SSO Callback route - handle token from SSO Gateway
router.get('/sso-callback', (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json({
      success: false,
      error: 'No token provided in callback'
    });
  }
  
  try {
    // Verify the token from SSO Gateway
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    
    // Generate a receipt-specific token
    const receiptTokenPayload = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      source: 'sso-gateway'
    };
    
    const receiptToken = generateToken(receiptTokenPayload);
    
    // Set token as HTTP-only cookie specifically for this domain
    res.cookie('access_token', receiptToken, {
      httpOnly: true,
      secure: true, // Always use secure for production domains
      sameSite: 'none', // Required for cross-domain cookies
      domain: 'receipt.receipt-flow.io.vn', // Updated to match new subdomain
      path: '/',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Also set a non-httpOnly cookie for client-side access
    res.cookie('receipt_token_client', receiptToken, {
      httpOnly: false,
      secure: true, // Always use secure for production domains
      sameSite: 'none', // Required for cross-domain cookies
      domain: 'receipt.receipt-flow.io.vn', // Updated to match new subdomain
      path: '/',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    
    // Also set specific receipt tokens
    res.cookie('receipt_token', receiptToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: 'receipt.receipt-flow.io.vn', // Updated to match new subdomain
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });
    
    // Set shared SSO token for cross-domain access with leading dot
    res.cookie('sso_token_client', receiptToken, {
      httpOnly: false,
      secure: true,
      sameSite: 'none',
      domain: '.receipt-flow.io.vn', // Main domain with leading dot for subdomain sharing
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });
    
    // Set shared access token with leading dot
    res.cookie('access_token_shared', receiptToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      domain: '.receipt-flow.io.vn', // Main domain with leading dot for subdomain sharing
      path: '/',
      maxAge: 24 * 60 * 60 * 1000
    });
    
    // Store user info in session
    req.session.user = {
      sub: payload.sub,
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
      roles: payload.roles || [],
      permissions: payload.permissions || [],
      loginTime: new Date().toISOString()
    };
    
    // Determine if we should use client-side token storage as fallback
    const useClientStorage = req.query.clientStorage === 'true' || process.env.NODE_ENV === 'production';
    
    if (useClientStorage) {
      // Redirect with token in URL for client-side storage (will be handled by auth-helper.js)
      return res.redirect(`/?token=${receiptToken}`);
    } else {
      // Standard redirect to dashboard or home page
      return res.redirect('/');
    }
  } catch (error) {
    console.error('SSO callback error:', error);
    res.status(401).send(`<html>
      <head>
        <title>Authentication Error</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🔐 Authentication Error</h1>
          </div>
          <div class="main-content">
            <div class="welcome">
              <h2>SSO Authentication Failed</h2>
              <p>There was an error processing your SSO token. This could be due to an invalid or expired token.</p>
              <p>Error details: ${error.message}</p>
              <div class="login-options">
                <a href="/" class="btn btn-primary">Return to Home</a>
                <a href="/auth/login" class="btn btn-secondary">Try Again</a>
              </div>
            </div>
          </div>
        </div>
      </body>
    </html>`);
  }
});

// Profile route - requires authentication
router.get('/profile', verifyToken, (req, res) => {
  // Check for JWT token or session authentication
  const user = req.user || req.session.user;
  
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required',
      redirectTo: '/auth/login'
    });
  }
  
  res.json({
    user: user,
    isAuthenticated: true
  });
});

// Check authentication status
router.get('/status', (req, res) => {
  // Check for JWT token authentication
  const token = extractToken(req);
  let isTokenAuthenticated = false;
  let tokenUser = null;
  
  if (token) {
    try {
      tokenUser = jwt.verify(token, process.env.JWT_SECRET);
      isTokenAuthenticated = true;
    } catch (error) {
      console.error('Token verification failed:', error);
    }
  }
  
  // Check for session authentication
  const isSessionAuthenticated = req.session && req.session.user;
  const sessionUser = req.session.user;
  
  const isAuthenticated = isTokenAuthenticated || isSessionAuthenticated;
  const user = tokenUser || sessionUser;
  
  res.json({
    isAuthenticated: isAuthenticated,
    user: user,
    authMethod: isTokenAuthenticated ? 'jwt' : (isSessionAuthenticated ? 'session' : 'none')
  });
});

// Generate JWT token for client use
router.post('/token', (req, res) => {
  try {
    // Check for session authentication
    const sessionUser = req.session && req.session.user;
    
    if (!sessionUser) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        redirectTo: '/auth/login'
      });
    }
    
    const tokenPayload = {
      sub: sessionUser.sub,
      email: sessionUser.email,
      name: sessionUser.name,
      picture: sessionUser.picture,
      roles: sessionUser.roles || [],
      permissions: sessionUser.permissions || [],
      source: 'receipt-direct'
    };
    
    const accessToken = generateToken(tokenPayload);
    
    res.json({
      success: true,
      accessToken,
      tokenType: 'Bearer',
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      user: tokenPayload,
    });
  } catch (error) {
    console.error('Token generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Token generation failed',
    });
  }
});

module.exports = router;
