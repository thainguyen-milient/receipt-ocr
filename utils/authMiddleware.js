const jwt = require('jsonwebtoken');

/**
 * Middleware to extract and verify JWT tokens
 */
const extractToken = (req) => {
  let token = null;

  // Priority 1: Check Authorization header (Bearer token) - preferred method
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.substring(7);
  }
  // Priority 2: Check query parameter (for SSO redirects)
  else if (req.query && req.query.token) {
    token = req.query.token;
  }
  // Priority 3: Check cookies (fallback for legacy support)
  else if (req.cookies) {
    // Try access_token (from SSO Gateway)
    if (req.cookies.access_token) {
      token = req.cookies.access_token;
    }
    // Try other possible cookie names from SSO Gateway
    else if (req.cookies.sso_token) {
      token = req.cookies.sso_token;
    }
  }

  return token;
};

/**
 * Middleware to verify JWT tokens from SSO Gateway
 */
const verifyToken = (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token is required',
        redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
      });
    }

    // Verify token
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    console.error('Token verification failed:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired',
        redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
      });
    }
    
    return res.status(401).json({
      success: false,
      error: 'Invalid token',
      redirectTo: `${process.env.SSO_GATEWAY_URL}/auth/login?productId=${process.env.SSO_GATEWAY_PRODUCT_ID}&returnTo=${encodeURIComponent(req.originalUrl)}`
    });
  }
};

/**
 * Generate custom JWT token for Windsurf
 */
const generateToken = (payload, expiresIn = process.env.JWT_EXPIRES_IN || '24h') => {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn,
    issuer: 'windsurf-project',
  });
};

/**
 * Middleware to check if user is authenticated via session or token
 */
const requireAuth = (req, res, next) => {
  // Check if user is authenticated via session
  if (req.session && req.session.user) {
    return next();
  }

  // Check for JWT token
  const token = extractToken(req);
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded;
      return next();
    } catch (error) {
      console.error('Token verification failed:', error);
    }
  }

  return res.status(401).json({
    success: false,
    error: 'Authentication required',
    redirectTo: '/auth/login'
  });
};

module.exports = {
  verifyToken,
  requireAuth,
  generateToken,
  extractToken
};
