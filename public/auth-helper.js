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

// Clear token from localStorage
function clearToken() {
  localStorage.removeItem('windsurf_token');
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

// Export functions for use in other scripts
window.AuthHelper = {
  storeToken,
  getToken,
  clearToken,
  addAuthHeader,
  isAuthenticated,
  handleSSOCallback,
  redirectToLogin
};
