// popup.js
// Handles saving and loading SSO credentials for the extension popup

document.addEventListener('DOMContentLoaded', () => {
  const usernameInput = document.getElementById('username');
  const passwordInput = document.getElementById('password');
  const statusDiv = document.getElementById('status');

  // Load saved credentials
  chrome.storage.local.get(['sso_username', 'sso_password'], (result) => {
    if (result.sso_username) usernameInput.value = result.sso_username;
    if (result.sso_password) passwordInput.value = result.sso_password;
  });

  // Save credentials
  document.getElementById('loginForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const username = usernameInput.value;
    const password = passwordInput.value;
    chrome.storage.local.set({
      sso_username: username,
      sso_password: password
    }, () => {
      statusDiv.textContent = 'Saved!';
      setTimeout(() => statusDiv.textContent = '', 1500);
    });
  });
});
