// popup.js
// Handles saving and loading SSO credentials for the extension popup

document.addEventListener('DOMContentLoaded', () => {
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const masterInput = document.getElementById('masterPassword');
  const statusDiv = document.getElementById('status');
  const secure = new (window.SecureStorage || SecureStorage)();
  const storePlaintextCheckbox = document.getElementById('storePlaintext');

  // Load saved encrypted credentials meta for UX (do not auto-fill password)
  chrome.storage.local.get(['secure_credentials', 'store_plaintext', 'sso_username', 'sso_password'], (result) => {
    if (result.secure_credentials) {
      statusDiv.textContent = 'Encrypted credentials found';
      setTimeout(() => statusDiv.textContent = '', 1500);
    }
    if (typeof result.store_plaintext === 'boolean') {
      storePlaintextCheckbox.checked = result.store_plaintext;
      masterInput.disabled = !!result.store_plaintext;
    }
    // If plaintext mode is on, prefill for convenience
    if (result.store_plaintext && result.sso_username) {
      document.getElementById('username').value = result.sso_username || '';
    }
    if (result.store_plaintext && result.sso_password) {
      document.getElementById('password').value = result.sso_password || '';
    }
  });

  // Toggle master field enable/disable with checkbox
  storePlaintextCheckbox.addEventListener('change', () => {
    masterInput.disabled = storePlaintextCheckbox.checked;
  });

  // Save credentials (encrypt to local, cache plaintext in session for current browser session)
  document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const username = usernameInput.value;
    const password = passwordInput.value;
    const master = masterInput.value;
    const storePlaintext = storePlaintextCheckbox.checked;

    if (storePlaintext) {
      chrome.storage.local.set({ sso_username: username, sso_password: password, store_plaintext: true }, async () => {
        await chrome.storage.session.set({ sso_username: username, sso_password: password });
        statusDiv.textContent = 'Saved (plaintext, less secure)';
        setTimeout(() => statusDiv.textContent = '', 1500);
      });
      return;
    }

    if (!master) {
      statusDiv.textContent = 'Master password required';
      setTimeout(() => statusDiv.textContent = '', 2000);
      return;
    }

    secure.encryptCredentials(JSON.stringify({ username, password }), master)
      .then(async (encrypted) => {
        await chrome.storage.local.set({ secure_credentials: encrypted, store_plaintext: false, sso_username: null, sso_password: null });
        await chrome.storage.session.set({ sso_username: username, sso_password: password });
        statusDiv.textContent = 'Saved securely!';
        setTimeout(() => statusDiv.textContent = '', 1500);
      })
      .catch(() => {
        statusDiv.textContent = 'Save failed';
        setTimeout(() => statusDiv.textContent = '', 2000);
      });
  });
});
