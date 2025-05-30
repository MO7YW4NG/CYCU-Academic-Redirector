// background.js
// CYCU SSO Auto-login and Cookie Retriever
// --- CONFIG ---
const SSO_URL = "https://sso.lib.cycu.edu.tw/api/cylis";
const SSO_COOKIE_DOMAIN = ".lib.cycu.edu.tw";
let USERNAME = "";
let PASSWORD = "";
const LOGIN_INTERVAL_MINUTES = 30; // How often to refresh login

// Load script for encoding credentials
importScripts("decrypt.js");

// Load credentials from storage
chrome.storage.local.get(["sso_username", "sso_password"], (result) => {
  if (result.sso_username) USERNAME = result.sso_username;
  if (result.sso_password) PASSWORD = result.sso_password;
  scheduleLogin();
});

// --- LOGIN FUNCTION ---
async function loginSSO() {
  if (!USERNAME || !PASSWORD) {
    console.warn("SSO credentials not set.");
    return;
  }
    // Encode credentials as required by SSO
    const encodedUsername = strencode(USERNAME);
    const encodedPassword = strencode(PASSWORD);

    let response = await fetch(SSO_URL, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": "https://cylis.lib.cycu.edu.tw/",
            "Host": "sso.lib.cycu.edu.tw",
            "Origin": "https://cylis.lib.cycu.edu.tw",
        },
        body: new URLSearchParams({
            "username": encodedUsername,
            "password": encodedPassword
        }),
        keepalive: true,
        referrer: "https://cylis.lib.cycu.edu.tw/",
        credentials: "include"
    });
    // print error message if response is not ok
    if (!response.ok) throw new Error("Login failed: "+ response.status + " " + response.statusText);
    const data = await response.json();
    if (data.login) {
        // Save access token
        chrome.storage.local.set({cycuLibToken: data.access});
        
        response = await fetch("https://cylis.lib.cycu.edu.tw/patroninfo", {
            method: "POST",
            body: new URLSearchParams({
                "extpatid": data.patronlogin ? "" : USERNAME,
                "extpatpw": data.patronlogin ? "" : PASSWORD,
                "code": data.patronlogin ? USERNAME: "",
                "pin": data.patronlogin ? PASSWORD : "",
            }),
        })
        if (!response.ok) throw new Error("Failed to fetch patron info: " + response.status + " " + response.statusText);
        console.log("SSO login successful");
      // Optionally, store token or update state
    } else {
        console.warn("SSO login unsuccessful");
    }
}

// --- COOKIE RETRIEVAL ---
function getSSOCookies(callback) {
  if (!chrome.cookies) {
    console.warn("Cookie API not available");
    return;
  }
  chrome.cookies.getAll({ domain: SSO_COOKIE_DOMAIN }, function(cookies) {
    callback(cookies);
  });
}

// --- SESSION REFRESH ---
function scheduleLogin() {
  loginSSO();
  if (chrome.alarms) {
    chrome.alarms.create("ssoLogin", { periodInMinutes: LOGIN_INTERVAL_MINUTES });
  }
}

if (chrome.alarms) {
  chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === "ssoLogin") {
      chrome.storage.local.get(["sso_username", "sso_password"], (result) => {
        if (result.sso_username) USERNAME = result.sso_username;
        if (result.sso_password) PASSWORD = result.sso_password;
      });
      loginSSO();
    }
  });
}

// --- AUTO LOGIN ON CYLIS PAGE LOAD ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!USERNAME || !PASSWORD) {
    console.warn("SSO credentials not set.");
    return;
  }
  if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('https://cylis.lib.cycu.edu.tw/patroninfo')) {
    loginSSO().then(() => {
      // Redirect to url after login
      chrome.tabs.update(tabId, { url: decodeURIComponent(tab.url.split("url=")[1]) });
    });
  }
});

// --- MESSAGE HANDLER (for popup/options) ---
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg === "getSSOCookies") {
    getSSOCookies(sendResponse);
    return true; // async response
  }
});
