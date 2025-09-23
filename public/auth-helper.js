/**
 * Auth Helper Functions for Windsurf Project
 * Provides client-side authentication utilities for token management
 */

// Store token in localStorage
function storeToken(token) {
  localStorage.setItem('windsurf_token', token);
}

// Get token from localStorage
function getToken() {
  return localStorage.getItem('windsurf_token');
}

// Clear all tokens from all storage locations
function clearToken() {
  console.log('Clearing all tokens from client storage');
  
  // Clear from localStorage - all possible token names
  localStorage.removeItem('windsurf_token');
  localStorage.removeItem('receipt_token');
  localStorage.removeItem('access_token');
  localStorage.removeItem('sso_token');
  localStorage.removeItem('id_token');
  localStorage.removeItem('auth_token');
  
  // Clear from sessionStorage - all possible token names
  sessionStorage.removeItem('windsurf_token');
  sessionStorage.removeItem('receipt_token');
  sessionStorage.removeItem('access_token');
  sessionStorage.removeItem('sso_token');
  sessionStorage.removeItem('id_token');
  sessionStorage.removeItem('auth_token');
  
  // Try to clear cookies (may not work for httpOnly cookies)
  const cookiesToClear = [
    'windsurf_token',
    'receipt_token',
    'receipt_token_client',
    'access_token',
    'sso_token',
    'id_token',
    'auth_token'
  ];
  
  try {
    cookiesToClear.forEach(cookieName => {
      document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
      // Also try with domain attribute
      document.cookie = `${cookieName}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; domain=${window.location.hostname};`;
    });
  } catch (e) {
    console.error('Error clearing cookies:', e);
  }
  
  console.log('All tokens cleared from client storage');
}

// Add token to API requests
function addAuthHeader(headers = {}) {
  const token = getToken();
  if (token) {
    return {
      ...headers,
      'Authorization': `Bearer ${token}`
    };
  }
  return headers;
}

// Check if user is authenticated
function isAuthenticated() {
  return !!getToken();
}

// Handle SSO callback with token in URL
function handleSSOCallback() {
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get('token');
  
  if (token) {
    storeToken(token);
    
    // Remove token from URL to prevent security issues
    const cleanUrl = window.location.pathname;
    window.history.replaceState({}, document.title, cleanUrl);
    
    return true;
  }
  
  return false;
}

// Redirect to login
function redirectToLogin() {
  window.location.href = '/auth/login';
}

// Global logout - logs out from all systems
function globalLogout() {
  console.log('Initiating global logout');
  
  // First clear all local tokens
  clearToken();
  
  // Then redirect to the SSO Gateway logout endpoint with global=true
  const ssoGatewayUrl = getSsoGatewayUrl();
  const returnTo = window.location.origin;
  window.location.href = `${ssoGatewayUrl}/auth/logout?global=true&returnTo=${encodeURIComponent(returnTo)}`;
}

// Get SSO Gateway URL from meta tag or use default
function getSsoGatewayUrl() {
  // Try to get from meta tag
  const metaTag = document.querySelector('meta[name="sso-gateway-url"]');
  if (metaTag && metaTag.content) {
    return metaTag.content;
  }
  
  // Default fallback
  return 'http://localhost:3000';
}

// Export functions for use in other scripts
window.AuthHelper = {
  storeToken,
  getToken,
  clearToken,
  addAuthHeader,
  isAuthenticated,
  handleSSOCallback,
  redirectToLogin,
  globalLogout,
  getSsoGatewayUrl
};
