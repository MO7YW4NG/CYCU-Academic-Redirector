// background.js
// CYCU SSO Auto-login with Enhanced Security
// --- CONFIG ---
const SSO_URL = "https://sso.lib.cycu.edu.tw/api/cylis";
const CONNECT_URL = "https://sso.lib.cycu.edu.tw/api/connect";
const SSO_COOKIE_DOMAIN = ".lib.cycu.edu.tw";
const REQUEST_TIMEOUT = 30000; // 30 seconds
const MAX_RETRY_ATTEMPTS = 3;
const RATE_LIMIT_DELAY = 1000; // 1 second between requests

// Load security utilities
importScripts("security.js");
importScripts("decrypt.js");
importScripts("monitoring.js");

// Initialize secure storage and monitoring
const secureStorage = new SecureStorage();
const monitor = initializeMonitoring();

// Rate limiting and request management
class RequestManager {
    constructor() {
        this.lastRequestTime = 0;
        this.activeRequests = new Set();
        this.retryAttempts = new Map();
    }

    async makeRequest(url, options, requestId = null) {
        const startTime = Date.now();
        
        // Rate limiting
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        if (timeSinceLastRequest < RATE_LIMIT_DELAY) {
            await this.delay(RATE_LIMIT_DELAY - timeSinceLastRequest);
        }
        this.lastRequestTime = Date.now();

        // Request tracking
        const reqId = requestId || `req_${Date.now()}_${Math.random()}`;
        if (this.activeRequests.has(reqId)) {
            monitor.logSecurityEvent('DUPLICATE_REQUEST', { requestId: reqId, url }, 'medium');
            throw new Error('Duplicate request detected');
        }

        this.activeRequests.add(reqId);

        try {
            // Add timeout to options
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
            
            const requestOptions = {
                ...options,
                signal: controller.signal
            };

            const response = await fetch(url, requestOptions);
            clearTimeout(timeoutId);
            
            const duration = Date.now() - startTime;
            monitor.logNetworkRequest(url, options.method || 'GET', response.status, duration);

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return response;
        } catch (error) {
            const duration = Date.now() - startTime;
            const status = error.name === 'AbortError' ? 408 : 0;
            monitor.logNetworkRequest(url, options.method || 'GET', status, duration);
            
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        } finally {
            this.activeRequests.delete(reqId);
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    cleanup() {
        this.activeRequests.clear();
        this.retryAttempts.clear();
    }
}

const requestManager = new RequestManager();

// Enhanced credential management
let credentialCache = {
    username: null,
    password: null,
    lastUpdated: null,
    isValid: false
};

// Load credentials with enhanced security
async function loadCredentials() {
    try {
        // First try to get from secure storage
        const result = await chrome.storage.local.get(['secure_credentials', 'credential_hash']);
        
        if (result.secure_credentials && result.credential_hash) {
            // Credentials are encrypted, need master password
            credentialCache.isValid = false;
            return;
        }

        // Fallback to legacy storage (migrate to secure storage)
        const legacyResult = await chrome.storage.local.get(["sso_username", "sso_password"]);
        if (legacyResult.sso_username && legacyResult.sso_password) {
            credentialCache.username = legacyResult.sso_username;
            credentialCache.password = legacyResult.sso_password;
            credentialCache.lastUpdated = Date.now();
            credentialCache.isValid = true;
            
            console.warn('Using legacy credentials. Please update to secure storage.');
        }
    } catch (error) {
        console.error('Failed to load credentials:', InputValidator.sanitizeError(error));
        credentialCache.isValid = false;
    }
}

// Enhanced login function with security improvements
const loginSSO = withPerformanceLogging('sso_login', async function(retryCount = 0) {
    if (!credentialCache.isValid || !credentialCache.username || !credentialCache.password) {
        console.warn("SSO credentials not available or invalid.");
        monitor.logAuthAttempt(false, 'unknown', 'credentials_not_configured');
        return { success: false, error: 'Credentials not configured' };
    }

    try {
        // Validate credentials before use
        const usernameValidation = InputValidator.validateUsername(credentialCache.username);
        const passwordValidation = InputValidator.validatePassword(credentialCache.password);
        
        if (!usernameValidation.valid || !passwordValidation.valid) {
            throw new Error('Invalid credential format');
        }

        // Step 1: Fetch CSRF token
        console.log('Fetching CSRF token...');
        const connectResponse = await requestManager.makeRequest(CONNECT_URL, {
            method: "POST",
            credentials: "include",
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'CYCU Academic Redirector/1.3'
            }
        });

        if (!connectResponse.ok) {
            throw new Error(`Failed to fetch CSRF token: ${connectResponse.status}`);
        }

        const tokenData = await connectResponse.json();
        if (!tokenData.token) {
            throw new Error('Invalid token response');
        }

        const token = tokenData.token;
        console.log('CSRF token obtained successfully');

        // Step 2: Encode credentials securely
        const encodedUsername = strencode(usernameValidation.value, token);
        const encodedPassword = strencode(passwordValidation.value, token);

        // Step 3: Authenticate with SSO
        console.log('Authenticating with SSO...');
        const ssoResponse = await requestManager.makeRequest(SSO_URL, {
            method: "POST",
            body: new URLSearchParams({
                "username": encodedUsername,
                "password": encodedPassword,
                "token": token,
            }),
            credentials: "include",
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'CYCU Academic Redirector/1.3'
            }
        });

        if (!ssoResponse.ok) {
            throw new Error(`SSO authentication failed: ${ssoResponse.status}`);
        }

        const ssoData = await ssoResponse.json();
        
        if (!ssoData.login) {
            throw new Error('Authentication unsuccessful');
        }

        // Step 4: Save access token securely
        if (ssoData.access) {
            await chrome.storage.local.set({
                cycuLibToken: ssoData.access,
                tokenTimestamp: Date.now()
            });
        }

        // Step 5: Additional patron info request
        console.log('Fetching patron information...');
        const patronResponse = await requestManager.makeRequest("https://cylis.lib.cycu.edu.tw/patroninfo~S1?/", {
            method: "POST",
            body: new URLSearchParams({
                "extpatid": ssoData.patronlogin ? "" : usernameValidation.value,
                "extpatpw": ssoData.patronlogin ? "" : passwordValidation.value,
                "SUBMIT": "送出/SUBMIT",
                "code": ssoData.patronlogin ? usernameValidation.value : "",
                "pin": ssoData.patronlogin ? passwordValidation.value : "",
            }),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': 'https://cylis.lib.cycu.edu.tw/patroninfo~S1?'
            }
        });

        if (!patronResponse.ok) {
            console.warn(`Patron info request failed: ${patronResponse.status}`);
        }

        console.log('SSO login completed successfully');
        monitor.logAuthAttempt(true, usernameValidation.value, null);
        return { success: true, data: ssoData };

    } catch (error) {
        console.error('SSO login failed:', InputValidator.sanitizeError(error));
        monitor.logAuthAttempt(false, usernameValidation?.value || 'unknown', error.message);
        
        // Retry logic for transient failures
        if (retryCount < MAX_RETRY_ATTEMPTS && isRetryableError(error)) {
            console.log(`Retrying login attempt ${retryCount + 1}/${MAX_RETRY_ATTEMPTS}`);
            await requestManager.delay(1000 * (retryCount + 1)); // Exponential backoff
            return loginSSO(retryCount + 1);
        }

        return { success: false, error: InputValidator.sanitizeError(error) };
    }
});

// Check if error is retryable
function isRetryableError(error) {
    const retryableErrors = [
        'Request timeout',
        'Network error',
        'Failed to fetch',
        'ERR_NETWORK',
        'ERR_INTERNET_DISCONNECTED'
    ];
    
    return retryableErrors.some(retryError => 
        error.message.includes(retryError) || 
        error.name.includes(retryError)
    );
}

// Enhanced tab listener with security improvements
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Only process loading state changes
    if (changeInfo.status !== 'loading') return;
    
    // Validate tab URL
    if (!tab.url || typeof tab.url !== 'string') return;
    
    // Check if it's a CYCU library URL that needs authentication
    const targetPattern = /^https:\/\/cylis\.lib\.cycu\.edu\.tw\/patroninfo.*url=/;
    if (!targetPattern.test(tab.url)) return;

    // Ensure credentials are available
    if (!credentialCache.isValid) {
        console.warn("SSO credentials not configured for auto-login");
        return;
    }

    try {
        console.log('Auto-login triggered for tab:', tabId);
        const loginResult = await loginSSO();
        
        if (loginResult.success) {
            // Extract and validate redirect URL
            const urlMatch = tab.url.match(/url=([^&]+)/);
            if (urlMatch && urlMatch[1]) {
                const redirectUrl = decodeURIComponent(urlMatch[1]);
                
                // Validate redirect URL for security
                if (isValidRedirectUrl(redirectUrl)) {
                    await chrome.tabs.update(tabId, { url: redirectUrl });
                    console.log('Auto-login successful, redirected to:', redirectUrl);
                } else {
                    console.warn('Invalid redirect URL detected:', redirectUrl);
                }
            }
        } else {
            console.error('Auto-login failed:', loginResult.error);
        }
    } catch (error) {
        console.error('Auto-login error:', InputValidator.sanitizeError(error));
    }
});

// Validate redirect URLs to prevent open redirect attacks
function isValidRedirectUrl(url) {
    try {
        const parsedUrl = new URL(url);
        
        // Only allow HTTPS URLs
        if (parsedUrl.protocol !== 'https:') return false;
        
        // Only allow CYCU domains and trusted academic domains
        const allowedDomains = [
            'cycu.edu.tw',
            'lib.cycu.edu.tw',
            'cylis.lib.cycu.edu.tw'
        ];
        
        return allowedDomains.some(domain => 
            parsedUrl.hostname === domain || 
            parsedUrl.hostname.endsWith('.' + domain)
        );
    } catch (error) {
        console.error('URL validation error:', error);
        return false;
    }
}

// Message handling for popup communication
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    (async () => {
        try {
            switch (message.type) {
                case 'GET_CREDENTIALS':
                    sendResponse({ 
                        hasCredentials: credentialCache.isValid,
                        username: credentialCache.username || null
                    });
                    break;
                    
                case 'TEST_LOGIN':
                    const result = await loginSSO();
                    sendResponse(result);
                    break;
                    
                case 'CLEAR_CREDENTIALS':
                    await secureStorage.clearCredentials();
                    credentialCache = {
                        username: null,
                        password: null,
                        lastUpdated: null,
                        isValid: false
                    };
                    sendResponse({ success: true });
                    break;
                    
                default:
                    sendResponse({ error: 'Unknown message type' });
            }
        } catch (error) {
            console.error('Message handling error:', error);
            sendResponse({ error: InputValidator.sanitizeError(error) });
        }
    })();
    
    return true; // Keep message channel open for async response
});

// Cleanup on extension unload
chrome.runtime.onSuspend.addListener(() => {
    requestManager.cleanup();
    console.log('Background script cleanup completed');
});

// Initialize credentials on startup
loadCredentials().catch(error => {
    console.error('Failed to initialize credentials:', InputValidator.sanitizeError(error));
});