// background.js
// CYCU SSO Auto-login and Cookie Retriever
// --- CONFIG ---
const SSO_URL = "https://sso.lib.cycu.edu.tw/api/cylis";
const CONNECT_URL = "https://sso.lib.cycu.edu.tw/api/connect";
const SSO_COOKIE_DOMAIN = ".lib.cycu.edu.tw";
let USERNAME = "";
let PASSWORD = "";

// Load script for encoding credentials
importScripts("decrypt.js");

// Load credentials from session storage (plaintext only for current session)
chrome.storage.session.get(["sso_username", "sso_password"], (result) => {
  if (result.sso_username) USERNAME = result.sso_username;
  if (result.sso_password) PASSWORD = result.sso_password;
  // Fallback: if session empty and user enabled plaintext storage, read from local
  if ((!USERNAME || !PASSWORD)) {
    chrome.storage.local.get(["store_plaintext", "sso_username", "sso_password"], (localRes) => {
      if (localRes.store_plaintext) {
        if (localRes.sso_username) USERNAME = localRes.sso_username;
        if (localRes.sso_password) PASSWORD = localRes.sso_password;
      }
    });
  }
});

// --- LOGIN FUNCTION ---
async function loginSSO() {
  if (!USERNAME || !PASSWORD) {
    console.warn("SSO credentials not set.");
    return;
  }

    // Fetch CSRF token from the connect URL
    let response = await fetch(CONNECT_URL, {
        method: "POST",
        keepalive: true,
        referrer: "https://cylis.lib.cycu.edu.tw/",
        credentials: "include"
    });
    // Check if response is ok
    if (!response.ok) throw new Error("Failed to fetch CSRF token: " + response.status + " " + response.statusText);
    var data = await response.json();
    let token = data.token;
    console.log("CSRF token fetched:", token);
    // Encode credentials as required by SSO
    const encodedUsername = strencode(USERNAME, token);
    const encodedPassword = strencode(PASSWORD, token);
    // Connect to SSO service
    response = await fetch(SSO_URL, {
        method: "POST",
        body: new URLSearchParams({
            "username": encodedUsername,
            "password": encodedPassword,
            "token": token,
        }),
        keepalive: true,
        referrer: "https://cylis.lib.cycu.edu.tw/",
        credentials: "include"
    });
    // print error message if response is not ok
    if (!response.ok) throw new Error("Login failed: "+ response.status + " " + response.statusText);
    data = await response.json();
    if (data.login) {
        // Save access token
        chrome.storage.local.set({cycuLibToken: data.access});
        
        response = await fetch("https://cylis.lib.cycu.edu.tw/patroninfo~S1?/", {
            method: "POST",
            body: new URLSearchParams({
                "extpatid": data.patronlogin ? "" : USERNAME,
                "extpatpw": data.patronlogin ? "" : PASSWORD,
                "SUBMIT": "送出/SUBMIT",
                "code": data.patronlogin ? USERNAME: "",
                "pin": data.patronlogin ? PASSWORD : "",
            }),
            referrer: "https://cylis.lib.cycu.edu.tw/patroninfo~S1?",
        })
        if (!response.ok) throw new Error("Failed to fetch patron info: " + response.status + " " + response.statusText);
        console.log("SSO login successful:", await response.text());
    } else {
        console.warn("SSO login unsuccessful");
    }
}

// --- AUTO LOGIN ON CYLIS PAGE LOAD ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!USERNAME || !PASSWORD) {
    console.warn("SSO credentials not set.");
    return;
  }
  if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('https://cylis.lib.cycu.edu.tw/patroninfo') && tab.url.includes("url=")) {
    loginSSO().then(() => {
      // Redirect to url after login
      chrome.tabs.update(tabId, { url: decodeURIComponent(tab.url.split("url=")[1]) });
    });
  }
});