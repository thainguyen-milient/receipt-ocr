/**
 * Enhanced Session Authentication Helper for Cross-Subdomain SSO - Receipt Project
 * This script handles session-based authentication across different subdomains
 */

class SessionAuthHelper {
    constructor() {
        this.ssoGatewayUrl = process.env.NODE_ENV === 'production' 
            ? 'https://sso.receipt-flow.io.vn' 
            : 'http://localhost:3000';
        this.sessionKey = 'sso_session_data';
        this.lastCheckTime = 0;
        this.checkInterval = 30000; // Check every 30 seconds
        this.init();
    }

    init() {
        // Handle token from URL parameters (SSO redirect)
        this.handleTokenFromUrl();
        
        // Set up periodic session validation
        this.setupSessionValidation();
        
        // Set up automatic session sync
        this.setupSessionSync();
    }

    /**
     * Handle token from URL parameters (when redirected from SSO Gateway)
     */
    handleTokenFromUrl() {
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        
        if (token) {
            console.log('Token received from SSO Gateway, syncing session...');
            this.syncSessionFromSSO();
            
            // Clean URL by removing token parameter
            const url = new URL(window.location);
            url.searchParams.delete('token');
            window.history.replaceState({}, document.title, url.toString());
            
            return true;
        }
        
        return false;
    }

    /**
     * Sync session data from SSO Gateway
     */
    async syncSessionFromSSO() {
        try {
            // First try to get token from session
            const tokenResponse = await fetch(`${this.ssoGatewayUrl}/auth/token-from-session`, {
                credentials: 'include',
                headers: {
                    'Accept': 'application/json',
                }
            });
            
            if (tokenResponse.ok) {
                const tokenData = await tokenResponse.json();
                if (tokenData.success && tokenData.accessToken) {
                    this.setSessionData(tokenData);
                    console.log('Access token and session synced successfully from SSO Gateway');
                    return tokenData;
                }
            }
            
            // Fallback to regular session endpoint
            const response = await fetch(`${this.ssoGatewayUrl}/auth/session`, {
                credentials: 'include',
                headers: {
                    'Accept': 'application/json',
                }
            });
            
            if (response.ok) {
                const sessionData = await response.json();
                if (sessionData.success && sessionData.authenticated) {
                    this.setSessionData(sessionData);
                    console.log('Session synced successfully from SSO Gateway');
                    return sessionData;
                } else {
                    this.clearSessionData();
                }
            } else {
                console.warn('Failed to sync session from SSO Gateway:', response.status);
                this.clearSessionData();
            }
        } catch (error) {
            console.error('Error syncing session from SSO Gateway:', error);
            this.clearSessionData();
        }
        
        return null;
    }

    /**
     * Store session data in localStorage
     */
    setSessionData(sessionData) {
        const dataToStore = {
            ...sessionData,
            timestamp: Date.now(),
            domain: window.location.hostname
        };
        localStorage.setItem(this.sessionKey, JSON.stringify(dataToStore));
    }

    /**
     * Get session data from localStorage
     */
    getSessionData() {
        try {
            const stored = localStorage.getItem(this.sessionKey);
            if (stored) {
                const data = JSON.parse(stored);
                
                // Check if data is not too old (max 1 hour without sync)
                const maxAge = 60 * 60 * 1000; // 1 hour
                if (Date.now() - data.timestamp < maxAge) {
                    return data;
                }
            }
        } catch (error) {
            console.error('Error reading session data:', error);
        }
        
        return null;
    }

    /**
     * Remove session data from localStorage
     */
    clearSessionData() {
        localStorage.removeItem(this.sessionKey);
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        const sessionData = this.getSessionData();
        return sessionData && sessionData.authenticated;
    }

    /**
     * Get user info from session
     */
    getUserInfo() {
        const sessionData = this.getSessionData();
        return sessionData?.user || null;
    }

    /**
     * Get access token from session
     */
    getAccessToken() {
        const sessionData = this.getSessionData();
        return sessionData?.accessToken || null;
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
        this.clearSessionData();
        const logoutUrl = `${this.ssoGatewayUrl}/auth/global-logout?returnTo=${encodeURIComponent(returnUrl)}`;
        window.location.href = logoutUrl;
    }

    /**
     * Make authenticated API request
     */
    async authenticatedFetch(url, options = {}) {
        const token = this.getAccessToken();
        
        if (!token) {
            throw new Error('No authentication token available');
        }

        // Try both cookie-based and header-based authentication
        const headers = {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            ...options.headers
        };

        const response = await fetch(url, {
            ...options,
            headers,
            credentials: 'include' // Include cookies for session-based auth
        });

        // If unauthorized, try to refresh session
        if (response.status === 401) {
            const refreshedSession = await this.syncSessionFromSSO();
            if (refreshedSession) {
                // Retry with refreshed token
                headers['Authorization'] = `Bearer ${refreshedSession.accessToken}`;
                return fetch(url, { ...options, headers, credentials: 'include' });
            } else {
                this.redirectToLogin();
                throw new Error('Authentication required');
            }
        }

        return response;
    }

    /**
     * Setup periodic session validation
     */
    setupSessionValidation() {
        setInterval(() => {
            if (this.isAuthenticated()) {
                this.validateSession();
            }
        }, this.checkInterval);
    }

    /**
     * Validate current session with SSO Gateway
     */
    async validateSession() {
        const now = Date.now();
        
        // Don't check too frequently
        if (now - this.lastCheckTime < this.checkInterval) {
            return;
        }
        
        this.lastCheckTime = now;
        
        try {
            const response = await fetch(`${this.ssoGatewayUrl}/auth/status`, {
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                if (!data.authenticated) {
                    console.log('Session expired, clearing local data');
                    this.clearSessionData();
                    // Optionally redirect to login
                    // this.redirectToLogin();
                }
            }
        } catch (error) {
            console.warn('Session validation failed:', error);
        }
    }

    /**
     * Setup automatic session synchronization
     */
    setupSessionSync() {
        // Sync session when page becomes visible (tab switching)
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden && this.isAuthenticated()) {
                this.syncSessionFromSSO();
            }
        });

        // Sync session when window gains focus
        window.addEventListener('focus', () => {
            if (this.isAuthenticated()) {
                this.syncSessionFromSSO();
            }
        });

        // Initial sync if we have session data but it's old
        const sessionData = this.getSessionData();
        if (sessionData && Date.now() - sessionData.timestamp > 5 * 60 * 1000) { // 5 minutes
            this.syncSessionFromSSO();
        }
    }

    /**
     * Force session refresh
     */
    async refreshSession() {
        return await this.syncSessionFromSSO();
    }
}

// Create global instance
window.SessionAuthHelper = new SessionAuthHelper();

// Backward compatibility
window.AuthHelper = {
    handleSSOCallback: () => window.SessionAuthHelper.handleTokenFromUrl(),
    isAuthenticated: () => window.SessionAuthHelper.isAuthenticated(),
    getUserInfo: () => window.SessionAuthHelper.getUserInfo(),
    logout: () => window.SessionAuthHelper.logout(),
    redirectToLogin: () => window.SessionAuthHelper.redirectToLogin()
};

console.log('Enhanced Session Auth Helper initialized for Receipt project');
