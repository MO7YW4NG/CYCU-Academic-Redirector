// security.js
// Secure credential management and encryption utilities

/**
 * Secure credential storage with AES encryption
 */
class SecureStorage {
    constructor() {
        this.algorithm = 'AES-GCM';
        this.keyLength = 256;
    }

    /**
     * Generate a cryptographically secure key from password
     * @param {string} password - User password
     * @param {Uint8Array} salt - Salt for key derivation
     * @returns {Promise<CryptoKey>} Derived key
     */
    async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: this.algorithm, length: this.keyLength },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt credentials securely
     * @param {string} data - Data to encrypt
     * @param {string} password - Encryption password
     * @returns {Promise<Object>} Encrypted data with metadata
     */
    async encryptCredentials(data, password) {
        try {
            const encoder = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const key = await this.deriveKey(password, salt);
            const encodedData = encoder.encode(data);
            
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: this.algorithm,
                    iv: iv
                },
                key,
                encodedData
            );

            return {
                encryptedData: Array.from(new Uint8Array(encryptedData)),
                salt: Array.from(salt),
                iv: Array.from(iv),
                timestamp: Date.now()
            };
        } catch (error) {
            console.error('Encryption failed:', error.message);
            throw new Error('Failed to encrypt credentials');
        }
    }

    /**
     * Decrypt credentials securely
     * @param {Object} encryptedObj - Encrypted data object
     * @param {string} password - Decryption password
     * @returns {Promise<string>} Decrypted data
     */
    async decryptCredentials(encryptedObj, password) {
        try {
            const { encryptedData, salt, iv } = encryptedObj;
            const key = await this.deriveKey(password, new Uint8Array(salt));
            
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: this.algorithm,
                    iv: new Uint8Array(iv)
                },
                key,
                new Uint8Array(encryptedData)
            );

            const decoder = new TextDecoder();
            return decoder.decode(decryptedData);
        } catch (error) {
            console.error('Decryption failed:', error.message);
            throw new Error('Failed to decrypt credentials');
        }
    }

    /**
     * Securely store credentials in chrome storage
     * @param {string} username - Username to store
     * @param {string} password - Password to store
     * @param {string} masterPassword - Master password for encryption
     * @returns {Promise<boolean>} Success status
     */
    async storeCredentials(username, password, masterPassword) {
        try {
            const credentials = JSON.stringify({ username, password });
            const encrypted = await this.encryptCredentials(credentials, masterPassword);
            
            await chrome.storage.local.set({
                'secure_credentials': encrypted,
                'credential_hash': await this.hashData(masterPassword)
            });
            
            return true;
        } catch (error) {
            console.error('Failed to store credentials:', error.message);
            return false;
        }
    }

    /**
     * Retrieve and decrypt stored credentials
     * @param {string} masterPassword - Master password for decryption
     * @returns {Promise<Object|null>} Decrypted credentials or null
     */
    async retrieveCredentials(masterPassword) {
        try {
            const result = await chrome.storage.local.get(['secure_credentials', 'credential_hash']);
            
            if (!result.secure_credentials || !result.credential_hash) {
                return null;
            }

            // Verify master password
            const passwordHash = await this.hashData(masterPassword);
            if (passwordHash !== result.credential_hash) {
                throw new Error('Invalid master password');
            }

            const decryptedData = await this.decryptCredentials(result.secure_credentials, masterPassword);
            return JSON.parse(decryptedData);
        } catch (error) {
            console.error('Failed to retrieve credentials:', error.message);
            return null;
        }
    }

    /**
     * Hash data using SHA-256
     * @param {string} data - Data to hash
     * @returns {Promise<string>} Hex encoded hash
     */
    async hashData(data) {
        const encoder = new TextEncoder();
        const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Clear all stored credentials
     * @returns {Promise<void>}
     */
    async clearCredentials() {
        await chrome.storage.local.remove(['secure_credentials', 'credential_hash']);
    }
}

/**
 * Input validation and sanitization utilities
 */
class InputValidator {
    /**
     * Validate and sanitize username input
     * @param {string} username - Username to validate
     * @returns {Object} Validation result
     */
    static validateUsername(username) {
        if (!username || typeof username !== 'string') {
            return { valid: false, error: 'Username is required' };
        }

        const trimmed = username.trim();
        if (trimmed.length < 3 || trimmed.length > 50) {
            return { valid: false, error: 'Username must be 3-50 characters' };
        }

        // Allow alphanumeric and common special characters
        const usernameRegex = /^[a-zA-Z0-9._-]+$/;
        if (!usernameRegex.test(trimmed)) {
            return { valid: false, error: 'Username contains invalid characters' };
        }

        return { valid: true, value: trimmed };
    }

    /**
     * Validate password strength
     * @param {string} password - Password to validate
     * @returns {Object} Validation result
     */
    static validatePassword(password) {
        if (!password || typeof password !== 'string') {
            return { valid: false, error: 'Password is required' };
        }

        if (password.length < 6) {
            return { valid: false, error: 'Password must be at least 6 characters' };
        }

        if (password.length > 128) {
            return { valid: false, error: 'Password too long' };
        }

        return { valid: true, value: password };
    }

    /**
     * Sanitize error messages to prevent information disclosure
     * @param {Error} error - Error object
     * @returns {string} Sanitized error message
     */
    static sanitizeError(error) {
        const safeMessages = [
            'Authentication failed',
            'Network error occurred',
            'Invalid credentials',
            'Service temporarily unavailable',
            'Request timeout'
        ];

        // Return generic message for security
        return 'An error occurred. Please try again.';
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SecureStorage, InputValidator };
}