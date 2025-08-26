// popup.js
// Enhanced SSO credential management with security improvements

// Import security utilities (will be loaded via script tag)
// Note: security.js classes will be available globally

class PopupManager {
    constructor() {
        this.secureStorage = new SecureStorage();
        this.isLoading = false;
        this.masterPassword = null;
        this.initializeElements();
        this.setupEventListeners();
        this.loadCredentials();
    }

    initializeElements() {
        this.elements = {
            usernameInput: document.getElementById('username'),
            passwordInput: document.getElementById('password'),
            masterPasswordInput: document.getElementById('masterPassword'),
            statusDiv: document.getElementById('status'),
            loginForm: document.getElementById('loginForm'),
            masterPasswordSection: document.getElementById('masterPasswordSection'),
            credentialSection: document.getElementById('credentialSection'),
            testButton: document.getElementById('testLogin'),
            clearButton: document.getElementById('clearCredentials'),
            toggleMasterPassword: document.getElementById('toggleMasterPassword'),
            securityInfo: document.getElementById('securityInfo')
        };

        // Add loading indicator
        this.addLoadingIndicator();
    }

    addLoadingIndicator() {
        const loadingDiv = document.createElement('div');
        loadingDiv.id = 'loading';
        loadingDiv.className = 'loading hidden';
        loadingDiv.innerHTML = '<div class="spinner"></div><span>Processing...</span>';
        this.elements.statusDiv.parentNode.insertBefore(loadingDiv, this.elements.statusDiv);
        this.elements.loadingDiv = loadingDiv;
    }

    setupEventListeners() {
        // Main form submission
        this.elements.loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleCredentialSave();
        });

        // Test login button
        if (this.elements.testButton) {
            this.elements.testButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.testLogin();
            });
        }

        // Clear credentials button
        if (this.elements.clearButton) {
            this.elements.clearButton.addEventListener('click', (e) => {
                e.preventDefault();
                this.clearCredentials();
            });
        }

        // Master password toggle
        if (this.elements.toggleMasterPassword) {
            this.elements.toggleMasterPassword.addEventListener('click', () => {
                this.toggleMasterPasswordVisibility();
            });
        }

        // Input validation on blur
        this.elements.usernameInput.addEventListener('blur', () => {
            this.validateUsername();
        });

        this.elements.passwordInput.addEventListener('blur', () => {
            this.validatePassword();
        });

        // Real-time validation
        this.elements.usernameInput.addEventListener('input', () => {
            this.clearFieldError('username');
        });

        this.elements.passwordInput.addEventListener('input', () => {
            this.clearFieldError('password');
        });

        if (this.elements.masterPasswordInput) {
            this.elements.masterPasswordInput.addEventListener('input', () => {
                this.clearFieldError('masterPassword');
            });
        }
    }

    async loadCredentials() {
        try {
            this.setLoading(true);
            
            // Check if we have secure credentials
            const result = await chrome.storage.local.get(['secure_credentials', 'credential_hash']);
            
            if (result.secure_credentials && result.credential_hash) {
                this.showMasterPasswordSection();
            } else {
                // Check for legacy credentials
                const legacyResult = await chrome.storage.local.get(['sso_username', 'sso_password']);
                if (legacyResult.sso_username && legacyResult.sso_password) {
                    this.elements.usernameInput.value = legacyResult.sso_username;
                    this.elements.passwordInput.value = legacyResult.sso_password;
                    this.showSecurityWarning('Legacy credentials detected. Please save to upgrade to secure storage.');
                }
                this.showCredentialSection();
            }
        } catch (error) {
            this.showError('Failed to load credentials: ' + InputValidator.sanitizeError(error));
        } finally {
            this.setLoading(false);
        }
    }

    showMasterPasswordSection() {
        if (this.elements.masterPasswordSection) {
            this.elements.masterPasswordSection.classList.remove('hidden');
        }
        if (this.elements.credentialSection) {
            this.elements.credentialSection.classList.add('hidden');
        }
    }

    showCredentialSection() {
        if (this.elements.credentialSection) {
            this.elements.credentialSection.classList.remove('hidden');
        }
        if (this.elements.masterPasswordSection) {
            this.elements.masterPasswordSection.classList.add('hidden');
        }
    }

    async handleMasterPasswordSubmit() {
        const masterPassword = this.elements.masterPasswordInput.value;
        
        if (!masterPassword) {
            this.showFieldError('masterPassword', 'Master password is required');
            return;
        }

        try {
            this.setLoading(true);
            const credentials = await this.secureStorage.retrieveCredentials(masterPassword);
            
            if (credentials) {
                this.masterPassword = masterPassword;
                this.elements.usernameInput.value = credentials.username;
                this.elements.passwordInput.value = credentials.password;
                this.showCredentialSection();
                this.showSuccess('Credentials loaded successfully');
            } else {
                this.showFieldError('masterPassword', 'Invalid master password');
            }
        } catch (error) {
            this.showFieldError('masterPassword', 'Failed to decrypt credentials');
        } finally {
            this.setLoading(false);
        }
    }

    async handleCredentialSave() {
        if (this.isLoading) return;

        // Validate inputs
        const usernameValidation = this.validateUsername();
        const passwordValidation = this.validatePassword();

        if (!usernameValidation.valid || !passwordValidation.valid) {
            return;
        }

        const username = usernameValidation.value;
        const password = passwordValidation.value;

        try {
            this.setLoading(true);

            // If we don't have a master password, prompt for one
            if (!this.masterPassword) {
                this.masterPassword = await this.promptForMasterPassword();
                if (!this.masterPassword) {
                    this.showError('Master password is required for secure storage');
                    return;
                }
            }

            // Store credentials securely
            const success = await this.secureStorage.storeCredentials(username, password, this.masterPassword);
            
            if (success) {
                // Clear legacy credentials
                await chrome.storage.local.remove(['sso_username', 'sso_password']);
                
                this.showSuccess('Credentials saved securely!');
                
                // Notify background script of credential update
                chrome.runtime.sendMessage({ type: 'CREDENTIALS_UPDATED' });
            } else {
                this.showError('Failed to save credentials');
            }
        } catch (error) {
            this.showError('Failed to save credentials: ' + InputValidator.sanitizeError(error));
        } finally {
            this.setLoading(false);
        }
    }

    async promptForMasterPassword() {
        return new Promise((resolve) => {
            const modal = document.createElement('div');
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="modal">
                    <h3>Set Master Password</h3>
                    <p>Create a master password to encrypt your credentials:</p>
                    <input type="password" id="newMasterPassword" placeholder="Master Password" minlength="8">
                    <input type="password" id="confirmMasterPassword" placeholder="Confirm Password">
                    <div class="modal-buttons">
                        <button type="button" id="confirmMaster">Save</button>
                        <button type="button" id="cancelMaster">Cancel</button>
                    </div>
                    <div id="masterError" class="error-message"></div>
                </div>
            `;

            document.body.appendChild(modal);

            const newPasswordInput = modal.querySelector('#newMasterPassword');
            const confirmPasswordInput = modal.querySelector('#confirmMasterPassword');
            const confirmButton = modal.querySelector('#confirmMaster');
            const cancelButton = modal.querySelector('#cancelMaster');
            const errorDiv = modal.querySelector('#masterError');

            confirmButton.addEventListener('click', () => {
                const newPassword = newPasswordInput.value;
                const confirmPassword = confirmPasswordInput.value;

                if (!newPassword || newPassword.length < 8) {
                    errorDiv.textContent = 'Master password must be at least 8 characters';
                    return;
                }

                if (newPassword !== confirmPassword) {
                    errorDiv.textContent = 'Passwords do not match';
                    return;
                }

                document.body.removeChild(modal);
                resolve(newPassword);
            });

            cancelButton.addEventListener('click', () => {
                document.body.removeChild(modal);
                resolve(null);
            });

            newPasswordInput.focus();
        });
    }

    validateUsername() {
        const username = this.elements.usernameInput.value;
        const validation = InputValidator.validateUsername(username);
        
        if (!validation.valid) {
            this.showFieldError('username', validation.error);
        } else {
            this.clearFieldError('username');
        }
        
        return validation;
    }

    validatePassword() {
        const password = this.elements.passwordInput.value;
        const validation = InputValidator.validatePassword(password);
        
        if (!validation.valid) {
            this.showFieldError('password', validation.error);
        } else {
            this.clearFieldError('password');
        }
        
        return validation;
    }

    async testLogin() {
        if (this.isLoading) return;

        try {
            this.setLoading(true);
            this.showStatus('Testing login...', 'info');

            const response = await chrome.runtime.sendMessage({ type: 'TEST_LOGIN' });
            
            if (response.success) {
                this.showSuccess('Login test successful!');
            } else {
                this.showError('Login test failed: ' + (response.error || 'Unknown error'));
            }
        } catch (error) {
            this.showError('Login test failed: ' + InputValidator.sanitizeError(error));
        } finally {
            this.setLoading(false);
        }
    }

    async clearCredentials() {
        if (this.isLoading) return;

        if (!confirm('Are you sure you want to clear all saved credentials?')) {
            return;
        }

        try {
            this.setLoading(true);
            
            await this.secureStorage.clearCredentials();
            await chrome.storage.local.remove(['sso_username', 'sso_password']);
            
            // Clear form
            this.elements.usernameInput.value = '';
            this.elements.passwordInput.value = '';
            if (this.elements.masterPasswordInput) {
                this.elements.masterPasswordInput.value = '';
            }
            
            this.masterPassword = null;
            this.showCredentialSection();
            this.showSuccess('All credentials cleared');
            
            chrome.runtime.sendMessage({ type: 'CREDENTIALS_CLEARED' });
        } catch (error) {
            this.showError('Failed to clear credentials: ' + InputValidator.sanitizeError(error));
        } finally {
            this.setLoading(false);
        }
    }

    toggleMasterPasswordVisibility() {
        const input = this.elements.masterPasswordInput;
        const button = this.elements.toggleMasterPassword;
        
        if (input.type === 'password') {
            input.type = 'text';
            button.textContent = '👁️';
        } else {
            input.type = 'password';
            button.textContent = '👁️‍🗨️';
        }
    }

    showFieldError(fieldName, message) {
        const field = this.elements[fieldName + 'Input'];
        if (field) {
            field.classList.add('error');
            field.setAttribute('title', message);
            
            // Create or update error message
            let errorElement = field.parentNode.querySelector('.field-error');
            if (!errorElement) {
                errorElement = document.createElement('div');
                errorElement.className = 'field-error';
                field.parentNode.appendChild(errorElement);
            }
            errorElement.textContent = message;
        }
    }

    clearFieldError(fieldName) {
        const field = this.elements[fieldName + 'Input'];
        if (field) {
            field.classList.remove('error');
            field.removeAttribute('title');
            
            const errorElement = field.parentNode.querySelector('.field-error');
            if (errorElement) {
                errorElement.remove();
            }
        }
    }

    showStatus(message, type = 'info') {
        this.elements.statusDiv.textContent = message;
        this.elements.statusDiv.className = `status ${type}`;
        
        if (type === 'success') {
            setTimeout(() => {
                this.elements.statusDiv.textContent = '';
                this.elements.statusDiv.className = 'status';
            }, 3000);
        }
    }

    showSuccess(message) {
        this.showStatus(message, 'success');
    }

    showError(message) {
        this.showStatus(message, 'error');
    }

    showSecurityWarning(message) {
        this.showStatus(message, 'warning');
    }

    setLoading(loading) {
        this.isLoading = loading;
        
        if (loading) {
            this.elements.loadingDiv.classList.remove('hidden');
            this.elements.loginForm.classList.add('disabled');
        } else {
            this.elements.loadingDiv.classList.add('hidden');
            this.elements.loginForm.classList.remove('disabled');
        }
        
        // Disable/enable form elements
        const formElements = this.elements.loginForm.querySelectorAll('input, button');
        formElements.forEach(element => {
            element.disabled = loading;
        });
    }
}

// Initialize popup manager when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Load security utilities first
    const script = document.createElement('script');
    script.src = 'security.js';
    script.onload = () => {
        new PopupManager();
    };
    script.onerror = () => {
        console.error('Failed to load security utilities');
        // Fallback to basic functionality
        document.getElementById('status').textContent = 'Security utilities failed to load';
    };
    document.head.appendChild(script);
});
