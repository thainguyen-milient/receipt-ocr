/**
 * Bearer Token Authentication Helper for Cross-Domain SSO - Receipt Project
 * This script handles Bearer token authentication across different subdomains
 */

class BearerAuthHelper {
    constructor() {
        this.ssoGatewayUrl = 'https://sso.receipt-flow.io.vn';
        this.tokenKey = 'sso_access_token';
        this.init();
    }

    init() {
        // Handle token from URL parameters (SSO redirect)
        this.handleTokenFromUrl();
        
        // Set up automatic token injection for fetch requests
        this.setupFetchInterceptor();
    }

    /**
     * Handle token from URL parameters (when redirected from SSO Gateway)
     */
    handleTokenFromUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        
        if (token) {
            console.log('Token received from SSO Gateway');
            this.setToken(token);
            
            // Clean URL by removing token parameter
            const url = new URL(window.location);
            url.searchParams.delete('token');
            window.history.replaceState({}, document.title, url.toString());
            
            return true;
        }
        
        return false;
    }

    /**
     * Store token in localStorage
     */
    setToken(token) {
        localStorage.setItem(this.tokenKey, token);
    }

    /**
     * Get token from localStorage
     */
    getToken() {
        return localStorage.getItem(this.tokenKey);
    }

    /**
     * Remove token from localStorage
     */
    removeToken() {
        localStorage.removeItem(this.tokenKey);
    }

    /**
     * Check if user is authenticated (has valid token)
     */
    isAuthenticated() {
        const token = this.getToken();
        if (!token) return false;

        try {
            // Basic JWT validation (check if not expired)
            const payload = JSON.parse(atob(token.split('.')[1]));
            const now = Date.now() / 1000;
            return payload.exp > now;
        } catch (error) {
            console.error('Token validation error:', error);
            this.removeToken();
            return false;
        }
    }

    /**
     * Get user info from token
     */
    getUserInfo() {
        const token = this.getToken();
        if (!token) return null;

        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return {
                sub: payload.sub,
                email: payload.email,
                name: payload.name,
                picture: payload.picture,
                roles: payload.roles || [],
                permissions: payload.permissions || []
            };
        } catch (error) {
            console.error('Error parsing token:', error);
            return null;
        }
    }

    /**
     * Redirect to SSO Gateway for authentication
     */
    redirectToLogin(returnUrl = window.location.href) {
        const loginUrl = `${this.ssoGatewayUrl}/auth/login?productId=receipt&returnTo=${encodeURIComponent(returnUrl)}`;
        window.location.href = loginUrl;
    }

    /**
     * Logout and redirect to SSO Gateway
     */
    logout(returnUrl = window.location.origin) {
        this.removeToken();
        const logoutUrl = `${this.ssoGatewayUrl}/auth/global-logout?returnTo=${encodeURIComponent(returnUrl)}`;
        window.location.href = logoutUrl;
    }

    /**
     * Make authenticated API request with Bearer token
     */
    async authenticatedFetch(url, options = {}) {
        const token = this.getToken();
        
        if (!token) {
            throw new Error('No authentication token available');
        }

        const headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers
        });

        // If unauthorized, redirect to login
        if (response.status === 401) {
            this.removeToken();
            this.redirectToLogin();
            throw new Error('Authentication required');
        }

        return response;
    }

    /**
     * Setup automatic Bearer token injection for all fetch requests
     */
    setupFetchInterceptor() {
        const originalFetch = window.fetch;
        const self = this;

        window.fetch = function(url, options = {}) {
            const token = self.getToken();
            
            // Only add token for same-origin requests or specific domains
            const shouldAddToken = token && (
                url.startsWith('/') || 
                url.includes('receipt-flow.io.vn') ||
                url.includes('localhost')
            );

            if (shouldAddToken) {
                options.headers = {
                    'Authorization': `Bearer ${token}`,
                    ...options.headers
                };
            }

            return originalFetch.call(this, url, options);
        };
    }

    /**
     * Get token for SSO Gateway requests
     */
    async getTokenFromSSO() {
        try {
            const response = await fetch(`${this.ssoGatewayUrl}/auth/token`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.accessToken) {
                    this.setToken(data.accessToken);
                    return data.accessToken;
                }
            }
        } catch (error) {
            console.error('Error getting token from SSO:', error);
        }
        
        return null;
    }
}

// Create global instance
window.BearerAuthHelper = new BearerAuthHelper();

// Backward compatibility
window.AuthHelper = {
    handleSSOCallback: () => window.BearerAuthHelper.handleTokenFromUrl(),
    isAuthenticated: () => window.BearerAuthHelper.isAuthenticated(),
    getUserInfo: () => window.BearerAuthHelper.getUserInfo(),
    logout: () => window.BearerAuthHelper.logout(),
    redirectToLogin: () => window.BearerAuthHelper.redirectToLogin()
};

console.log('Bearer Auth Helper initialized for Receipt project');
