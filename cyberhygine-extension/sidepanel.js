const MESSAGE = Object.freeze({
  GET_ACTIVE_CONTEXT: "GET_ACTIVE_CONTEXT",
  GET_PHISHING_RISK: "GET_PHISHING_RISK",
  GET_AUTH_STATUS: "GET_AUTH_STATUS",
  OPEN_LOGIN: "OPEN_LOGIN",
  SYNC_TOKEN_FROM_APP: "SYNC_TOKEN_FROM_APP",
  SET_TOKEN: "SET_TOKEN",
  REQUEST_BIOMETRIC_GATE: "REQUEST_BIOMETRIC_GATE",
  GRANT_BIOMETRIC_UNLOCK: "GRANT_BIOMETRIC_UNLOCK",
  FETCH_VAULT_FOR_ACTIVE_TAB: "FETCH_VAULT_FOR_ACTIVE_TAB",
  PERFORM_AUTOFILL: "PERFORM_AUTOFILL",
  CAPTURE_LOGIN_CREDENTIAL: "CAPTURE_LOGIN_CREDENTIAL",
  SET_NEVER_AUTOFILL: "SET_NEVER_AUTOFILL"
});

const CODE = Object.freeze({
  NO_TOKEN: "NO_TOKEN",
  UNAUTHORIZED: "UNAUTHORIZED",
  SITE_BLOCKED: "SITE_BLOCKED",
  UNSUPPORTED_PAGE: "UNSUPPORTED_PAGE",
  CREDENTIAL_NOT_FOUND: "CREDENTIAL_NOT_FOUND",
  NETWORK_ERROR: "NETWORK_ERROR",
  NO_PASSWORD_FIELD: "NO_PASSWORD_FIELD",
  DOMAIN_MISMATCH: "DOMAIN_MISMATCH",
  PHISHING_BLOCKED: "PHISHING_BLOCKED",
  BIOMETRIC_FAILED: "BIOMETRIC_FAILED",
  PASSWORD_ONLY_FILLED: "PASSWORD_ONLY_FILLED",
  AUTOFILL_SUCCESS: "AUTOFILL_SUCCESS"
});

const CONFIG = Object.freeze({
  API_BASE_URL: "http://localhost:9000/api",
  TOKEN_KEY: "jwt_token",
  NEVER_AUTOFILL_KEY: "never_autofill_domains",
  REQUEST_TIMEOUT_MS: 10000
});

const SECOND_LEVEL_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "co.in",
  "com.au",
  "com.br",
  "com.mx",
  "co.jp",
  "co.nz",
  "com.sg"
]);

const state = {
  tabId: null,
  domain: "",
  blocked: false,
  authorized: false,
  risk: null,
  credentials: [],
  isLoading: false,
  autoLoginOpened: false,
  extensionPasskeyEnabled: false,
  extensionPasskeyCount: 0,
  extensionPasskeySupported: false,
  extensionPasskeyBusy: false
};

let loadingTimeoutId = null;
let tokenChangeReloadTimer = null;

function clearLoadingTimeout() {
  if (loadingTimeoutId) {
    clearTimeout(loadingTimeoutId);
    loadingTimeoutId = null;
  }
}

function applyLoadingUi(isLoading) {
  if (el.loading) el.loading.classList.toggle("hidden", !isLoading);
  if (el.autofillBtn) el.autofillBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.refreshBtn) el.refreshBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.loginBtn) el.loginBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.syncBtn) el.syncBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.neverBtn) el.neverBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.addOpenBtn) el.addOpenBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.saveAddBtn) el.saveAddBtn.disabled = isLoading || state.extensionPasskeyBusy;
  if (el.cancelAddBtn) el.cancelAddBtn.disabled = isLoading || state.extensionPasskeyBusy;
}

const el = {
  domainValue: document.getElementById("domainValue"),
  status: document.getElementById("status"),
  riskSection: document.getElementById("riskSection"),
  riskLabel: document.getElementById("riskLabel"),
  riskBadge: document.getElementById("riskBadge"),
  riskScore: document.getElementById("riskScore"),
  riskReasons: document.getElementById("riskReasons"),
  extensionPasskeySection: document.getElementById("extensionPasskeySection"),
  extensionPasskeyText: document.getElementById("extensionPasskeyText"),
  extensionPasskeyBtn: document.getElementById("extensionPasskeyBtn"),
  loading: document.getElementById("loading"),
  loadingText: document.getElementById("loadingText"),
  credentialsSection: document.getElementById("credentialsSection"),
  credentialSelect: document.getElementById("credentialSelect"),
  autofillBtn: document.getElementById("autofillBtn"),
  emptySection: document.getElementById("emptySection"),
  addSection: document.getElementById("addSection"),
  addUsername: document.getElementById("addUsername"),
  addPassword: document.getElementById("addPassword"),
  saveAddBtn: document.getElementById("saveAddBtn"),
  cancelAddBtn: document.getElementById("cancelAddBtn"),
  addOpenBtn: document.getElementById("addOpenBtn"),
  loginBtn: document.getElementById("loginBtn"),
  syncBtn: document.getElementById("syncBtn"),
  neverBtn: document.getElementById("neverBtn"),
  refreshBtn: document.getElementById("refreshBtn")
};

function sendMessage(message, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    let completed = false;
    const timer = window.setTimeout(() => {
      if (completed) return;
      completed = true;
      reject(new Error("Background message timed out."));
    }, timeoutMs);

    chrome.runtime.sendMessage(message, (response) => {
      if (completed) return;
      completed = true;
      window.clearTimeout(timer);
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve(response || {});
    });
  });
}

function setStatus(message, type = "info") {
  el.status.textContent = message;
  el.status.className = `card status ${type}`;
}

function setLoadingMessage(message) {
  if (el.loadingText) {
    el.loadingText.textContent = message;
  }
}

function normalizeString(value, maxLen = 4096) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function getBaseDomainFromHostname(hostnameInput) {
  let hostname = normalizeString(hostnameInput, 2048).toLowerCase();
  if (!hostname) return "";
  hostname = hostname.replace(/\.+$/, "");
  if (!hostname) return "";

  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  if (hostname === "localhost" || isIPv4 || hostname.includes(":")) {
    return hostname;
  }

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;

  const last2 = parts.slice(-2).join(".");
  if (SECOND_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }

  return last2;
}

function getBaseDomain(value) {
  const input = normalizeString(value, 2048);
  if (!input) return "";
  try {
    if (/^https?:\/\//i.test(input)) {
      return getBaseDomainFromHostname(new URL(input).hostname);
    }
    return getBaseDomainFromHostname(new URL(`https://${input}`).hostname);
  } catch {
    return "";
  }
}

function estimatePasswordStrength(password) {
  const value = normalizeString(password);
  if (!value) return "weak";

  let score = 0;
  if (value.length >= 8) score += 1;
  if (value.length >= 12) score += 1;
  if (value.length >= 16) score += 1;
  if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score += 1;
  if (/\d/.test(value)) score += 1;
  if (/[^A-Za-z0-9]/.test(value)) score += 1;
  if (score <= 2) return "weak";
  if (score <= 4) return "medium";
  return "strong";
}

function fetchWithTimeout(url, options = {}, timeoutMs = CONFIG.REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...options, signal: controller.signal }).finally(() => {
    clearTimeout(timer);
  });
}

async function parseJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

async function apiRequest(path, { method = "GET", token = "", body = null } = {}) {
  const headers = { Accept: "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (body !== null) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetchWithTimeout(`${CONFIG.API_BASE_URL}${path}`, {
    method,
    headers,
    body: body === null ? undefined : JSON.stringify(body),
    cache: "no-store"
  });

  const payload = await parseJsonResponse(response);
  return { response, payload };
}

function storageGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function storageSet(items) {
  return new Promise((resolve) => chrome.storage.local.set(items, resolve));
}

function queryTabs(queryInfo) {
  return new Promise((resolve, reject) => {
    chrome.tabs.query(queryInfo, (tabs) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve(Array.isArray(tabs) ? tabs : []);
    });
  });
}

async function getStoredToken() {
  const data = await storageGet([CONFIG.TOKEN_KEY]);
  return normalizeString(data[CONFIG.TOKEN_KEY], 4096);
}

async function setStoredToken(token) {
  await storageSet({ [CONFIG.TOKEN_KEY]: token });
}

function isTrustedAppUrl(urlValue) {
  try {
    const parsed = new URL(urlValue);
    const protocol = parsed.protocol.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    const port = parsed.port || (protocol === "https:" ? "443" : protocol === "http:" ? "80" : "");

    if (!/^https?:$/.test(protocol)) {
      return false;
    }

    if (
      port === "3000" &&
      (hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "[::1]" ||
        hostname.endsWith(".localhost"))
    ) {
      return true;
    }

    return hostname === "cyberhygine.com" || hostname.endsWith(".cyberhygine.com");
  } catch {
    return false;
  }
}

function sendMessageToTab(tabId, message, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    let completed = false;
    const timer = window.setTimeout(() => {
      if (completed) return;
      completed = true;
      reject(new Error("Tab message timed out."));
    }, timeoutMs);

    chrome.tabs.sendMessage(tabId, message, (response) => {
      if (completed) return;
      completed = true;
      window.clearTimeout(timer);
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve(response || {});
    });
  });
}

async function findTrustedAppTabDirect() {
  const tabs = await queryTabs({});
  return tabs.find((tab) => tab && tab.id && tab.url && isTrustedAppUrl(tab.url)) || null;
}

async function syncTokenFromAppTabDirect() {
  const appTab = await findTrustedAppTabDirect();
  if (!appTab || !appTab.id) {
    return { ok: false, code: CODE.NO_TOKEN };
  }

  try {
    const response = await sendMessageToTab(appTab.id, { type: "CYBERHYGIENE_READ_APP_TOKEN" });
    const token = normalizeString(response && response.token, 4096);
    if (!token || isJwtExpired(token)) {
      return { ok: false, code: CODE.UNAUTHORIZED };
    }

    await setStoredToken(token);
    try {
      await sendMessage({ type: "SET_TOKEN", token }, 3000);
    } catch {
      // non-fatal
    }
    return { ok: true, token };
  } catch {
    return { ok: false, code: CODE.NO_TOKEN };
  }
}

async function ensureAuthorizedToken() {
  let token = await getStoredToken();
  if (token && !isJwtExpired(token)) {
    return { ok: true, token };
  }

  const directSync = await syncTokenFromAppTabDirect();
  if (directSync.ok) {
    token = normalizeString(directSync.token, 4096);
  }

  if (!token || isJwtExpired(token)) {
    try {
      const syncResult = await sendMessage({ type: MESSAGE.SYNC_TOKEN_FROM_APP }, 5000);
      if (syncResult && syncResult.ok) {
        token = await getStoredToken();
      }
    } catch {
      // non-fatal
    }
  }

  if (!token) {
    return { ok: false, code: CODE.NO_TOKEN };
  }

  if (isJwtExpired(token)) {
    return { ok: false, code: CODE.UNAUTHORIZED };
  }

  return { ok: true, token };
}

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const json = atob(padded);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function isJwtExpired(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return true;
  return Date.now() >= payload.exp * 1000;
}

function isUnknownMessageType(result) {
  const message = normalizeString(result && result.message, 512).toLowerCase();
  return message.includes("unknown message type");
}

function supportsPopupWebAuthn() {
  return typeof window.PublicKeyCredential !== "undefined" && !!navigator.credentials;
}

function getExtensionOrigin() {
  return normalizeString(window.location.origin, 2048);
}

function base64UrlToArrayBuffer(base64url) {
  const base64 = normalizeString(base64url, 16384).replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function toCreationOptions(optionsJSON) {
  return {
    ...optionsJSON,
    challenge: base64UrlToArrayBuffer(optionsJSON.challenge),
    user: {
      ...optionsJSON.user,
      id: base64UrlToArrayBuffer(optionsJSON.user.id)
    },
    excludeCredentials: (optionsJSON.excludeCredentials || []).map((cred) => ({
      ...cred,
      id: base64UrlToArrayBuffer(cred.id)
    }))
  };
}

function toRequestOptions(optionsJSON) {
  const allowCredentials = Array.isArray(optionsJSON.allowCredentials)
    ? optionsJSON.allowCredentials
    : [];
  return {
    ...optionsJSON,
    challenge: base64UrlToArrayBuffer(optionsJSON.challenge),
    allowCredentials: allowCredentials.map((cred) => ({
      ...cred,
      id: base64UrlToArrayBuffer(cred.id)
    }))
  };
}

function serializeRegistrationCredential(credential) {
  const response = credential && credential.response;
  const publicKey = response && response.getPublicKey ? response.getPublicKey() : null;
  const authenticatorData = response && response.getAuthenticatorData ? response.getAuthenticatorData() : null;

  if (!credential || !response || !publicKey || !authenticatorData) {
    throw new Error("This browser does not support extension fingerprint registration here.");
  }

  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      attestationObject: arrayBufferToBase64Url(response.attestationObject),
      authenticatorData: arrayBufferToBase64Url(authenticatorData),
      publicKey: arrayBufferToBase64Url(publicKey),
      transports: response.getTransports ? response.getTransports() : []
    }
  };
}

function serializeAuthenticationCredential(credential) {
  const response = credential && credential.response;
  if (!credential || !response) {
    throw new Error("Fingerprint verification failed.");
  }

  return {
    id: credential.id,
    rawId: arrayBufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: arrayBufferToBase64Url(response.clientDataJSON),
      authenticatorData: arrayBufferToBase64Url(response.authenticatorData),
      signature: arrayBufferToBase64Url(response.signature),
      userHandle: response.userHandle ? arrayBufferToBase64Url(response.userHandle) : null
    }
  };
}

function getWebAuthnErrorMessage(error, fallbackMessage) {
  if (!error) return fallbackMessage;
  if (error.name === "NotAllowedError") {
    return "Fingerprint verification was cancelled or timed out.";
  }
  if (error.name === "InvalidStateError") {
    return "This extension fingerprint is already registered on this device.";
  }
  if (error.name === "NotSupportedError") {
    return "Fingerprint verification is not supported in this extension popup on this browser.";
  }
  return normalizeString(error.message, 256) || fallbackMessage;
}

function withTimeout(promise, timeoutMs, message) {
  return Promise.race([
    promise,
    new Promise((resolve) => {
      window.setTimeout(() => {
        resolve({
          ok: false,
          code: CODE.NETWORK_ERROR,
          message
        });
      }, timeoutMs);
    })
  ]);
}

async function getNeverAutofillDomains() {
  const data = await storageGet([CONFIG.NEVER_AUTOFILL_KEY]);
  const raw = Array.isArray(data[CONFIG.NEVER_AUTOFILL_KEY])
    ? data[CONFIG.NEVER_AUTOFILL_KEY]
    : [];
  return [...new Set(raw.map((item) => getBaseDomain(item)).filter(Boolean))];
}

async function getActiveContextDirect() {
  try {
    const tabs = await queryTabs({ active: true, currentWindow: true });
    const tab = tabs && tabs.length > 0 ? tabs[0] : null;
    if (!tab || !tab.id || !tab.url) {
      return {
        ok: false,
        code: CODE.UNSUPPORTED_PAGE,
        message: "No active tab."
      };
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(tab.url);
    } catch {
      return {
        ok: false,
        code: CODE.UNSUPPORTED_PAGE,
        message: "Unsupported tab URL."
      };
    }

    if (!/^https?:$/.test(parsedUrl.protocol)) {
      return {
        ok: false,
        code: CODE.UNSUPPORTED_PAGE,
        message: "Autofill works only on http/https pages."
      };
    }

    const domain = getBaseDomainFromHostname(parsedUrl.hostname);
    if (!domain) {
      return {
        ok: false,
        code: CODE.UNSUPPORTED_PAGE,
        message: "Unable to detect domain."
      };
    }

    const blockedDomains = await getNeverAutofillDomains();

    return {
      ok: true,
      code: CODE.OK,
      tabId: Number(tab.id) || null,
      domain,
      blocked: blockedDomains.includes(domain)
    };
  } catch {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Could not read the active tab."
    };
  }
}

async function saveCredentialDirect(domain, username, password) {
  const token = await getStoredToken();
  if (!token) {
    return {
      ok: false,
      code: CODE.NO_TOKEN,
      message: "Please login to Cyber Hygiene."
    };
  }

  const siteDomain = getBaseDomain(domain);
  if (!siteDomain) {
    return {
      ok: false,
      code: "INVALID_DOMAIN",
      message: "Invalid domain."
    };
  }

  let existingId = null;
  try {
    const listRes = await fetchWithTimeout(`${CONFIG.API_BASE_URL}/credentials`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/json"
      },
      cache: "no-store"
    });

    if (listRes.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired. Please login again."
      };
    }

    if (!listRes.ok) {
      return {
        ok: false,
        code: CODE.NETWORK_ERROR,
        message: "Could not reach credentials API."
      };
    }

    const rows = await listRes.json();
    const usernameLower = normalizeString(username, 1024).toLowerCase();
    if (Array.isArray(rows)) {
      const match = rows.find((row) => {
        const rowDomain = getBaseDomain(row && row.site);
        const rowUser = normalizeString(row && row.username, 1024).toLowerCase();
        return rowDomain === siteDomain && rowUser === usernameLower;
      });
      if (match && (match.id || match.id === 0)) {
        existingId = String(match.id);
      }
    }
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while saving credential."
    };
  }

  const payload = {
    site: siteDomain,
    username: normalizeString(username, 1024),
    password: normalizeString(password, 4096),
    strength: estimatePasswordStrength(password)
  };

  try {
    const url = existingId
      ? `${CONFIG.API_BASE_URL}/credentials/${encodeURIComponent(existingId)}`
      : `${CONFIG.API_BASE_URL}/credentials`;
    const method = existingId ? "PUT" : "POST";

    const saveRes = await fetchWithTimeout(url, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify(payload),
      cache: "no-store"
    });

    if (saveRes.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired. Please login again."
      };
    }

    if (!saveRes.ok) {
      return {
        ok: false,
        code: CODE.NETWORK_ERROR,
        message: "Failed to save credential."
      };
    }

    return { ok: true };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while saving credential."
    };
  }
}

function maskUsername(username) {
  const value = normalizeString(username, 256);
  if (!value) return "Account";

  if (value.includes("@")) {
    const [name, host] = value.split("@");
    const left =
      name.length <= 2 ? `${name[0] || "*"}*` : `${name.slice(0, 2)}***`;
    return `${left}@${host}`;
  }

  if (value.length <= 2) return `${value[0] || "*"}*`;
  return `${value.slice(0, 2)}***`;
}

async function fetchVaultDirect(domain) {
  const token = await getStoredToken();
  if (!token) {
    return {
      ok: false,
      code: CODE.NO_TOKEN,
      message: "Please login to Cyber Hygiene."
    };
  }

  if (isJwtExpired(token)) {
    return {
      ok: false,
      code: CODE.UNAUTHORIZED,
      message: "Session expired. Please login again."
    };
  }

  const requestedDomain = getBaseDomain(domain);
  if (!requestedDomain) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Invalid domain."
    };
  }

  try {
    const response = await fetchWithTimeout(
      `${CONFIG.API_BASE_URL}/vault?domain=${encodeURIComponent(requestedDomain)}`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json"
        },
        cache: "no-store"
      }
    );

    if (response.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired. Please login again."
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        code: CODE.NETWORK_ERROR,
        message: "Could not load vault credentials."
      };
    }

    const payload = await response.json();
    const records = Array.isArray(payload && payload.credentials) ? payload.credentials : [];
    const credentials = records
      .map((item) => {
        const id = normalizeString(String(item && item.id), 128);
        const username = normalizeString(item && item.username, 1024);
        const itemDomain = getBaseDomain(item && (item.domain || item.site));
        if (!id || !username || itemDomain !== requestedDomain) return null;
        return {
          id,
          label: maskUsername(username)
        };
      })
      .filter(Boolean);

    return {
      ok: true,
      code: CODE.OK,
      credentials
    };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while loading vault credentials."
    };
  }
}

async function fetchExtensionPasskeyStatus(token) {
  const origin = encodeURIComponent(getExtensionOrigin());
  const { response, payload } = await apiRequest(`/extension-passkeys/status?origin=${origin}`, {
    token
  });

  if (response.status === 401) {
    return { ok: false, code: CODE.UNAUTHORIZED, message: "Session expired. Please login again." };
  }

  if (!response.ok) {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: normalizeString(payload.detail, 256) || "Could not load extension fingerprint status."
    };
  }

  return {
    ok: true,
    hasPasskey: Boolean(payload.has_passkey),
    passkeyCount: Number(payload.passkey_count) || 0
  };
}

async function deleteExtensionPasskeys(token) {
  const origin = encodeURIComponent(getExtensionOrigin());
  const { response, payload } = await apiRequest(`/extension-passkeys?origin=${origin}`, {
    method: "DELETE",
    token
  });

  if (response.status === 401) {
    return { ok: false, code: CODE.UNAUTHORIZED, message: "Session expired. Please login again." };
  }

  if (!response.ok) {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message:
        normalizeString(payload.detail, 256) || "Could not replace the extension fingerprint."
    };
  }

  return { ok: true, deletedCount: Number(payload.deleted_count) || 0 };
}

function renderExtensionPasskey(errorMessage = "") {
  const shouldShow = state.authorized;
  el.extensionPasskeySection.classList.toggle("hidden", !shouldShow);
  if (!shouldShow) return;

  if (!state.extensionPasskeySupported) {
    el.extensionPasskeyText.textContent =
      "This browser does not support fingerprint prompts inside the extension popup.";
    el.extensionPasskeyBtn.textContent = "Unavailable";
    el.extensionPasskeyBtn.disabled = true;
    return;
  }

  el.extensionPasskeyBtn.disabled = state.isLoading || state.extensionPasskeyBusy;

  if (state.extensionPasskeyEnabled) {
    const countLabel =
      state.extensionPasskeyCount > 1
        ? `${state.extensionPasskeyCount} extension fingerprints are registered.`
        : "1 extension fingerprint is registered.";
    el.extensionPasskeyText.textContent =
      errorMessage || `${countLabel} Autofill will ask for fingerprint inside the extension.`;
    el.extensionPasskeyBtn.textContent = state.extensionPasskeyBusy
      ? "Setting up..."
      : "Re-register extension fingerprint";
    return;
  }

  el.extensionPasskeyText.textContent =
    errorMessage ||
    "Enable a separate fingerprint for this extension so autofill stays inside Cyber Hygiene.";
  el.extensionPasskeyBtn.textContent = state.extensionPasskeyBusy
    ? "Setting up..."
    : "Enable fingerprint in extension";
}

async function refreshExtensionPasskeyState() {
  state.extensionPasskeySupported = supportsPopupWebAuthn();

  if (!state.authorized) {
    state.extensionPasskeyEnabled = false;
    state.extensionPasskeyCount = 0;
    renderExtensionPasskey();
    return { ok: false, code: CODE.NO_TOKEN };
  }

  if (!state.extensionPasskeySupported) {
    state.extensionPasskeyEnabled = false;
    state.extensionPasskeyCount = 0;
    renderExtensionPasskey();
    return { ok: false, code: CODE.BIOMETRIC_FAILED };
  }

  const token = await getStoredToken();
  if (!token || isJwtExpired(token)) {
    state.extensionPasskeyEnabled = false;
    state.extensionPasskeyCount = 0;
    renderExtensionPasskey();
    return { ok: false, code: CODE.UNAUTHORIZED };
  }

  try {
    const result = await fetchExtensionPasskeyStatus(token);
    if (!result.ok) {
      if (result.code === CODE.UNAUTHORIZED) {
        state.authorized = false;
      }
      state.extensionPasskeyEnabled = false;
      state.extensionPasskeyCount = 0;
      renderExtensionPasskey(result.message);
      return result;
    }

    state.extensionPasskeyEnabled = result.hasPasskey;
    state.extensionPasskeyCount = result.passkeyCount;
    renderExtensionPasskey();
    return { ok: true };
  } catch {
    state.extensionPasskeyEnabled = false;
    state.extensionPasskeyCount = 0;
    renderExtensionPasskey("Could not contact backend for extension fingerprint status.");
    return { ok: false, code: CODE.NETWORK_ERROR };
  }
}

async function registerExtensionPasskey() {
  const token = await getStoredToken();
  if (!token || isJwtExpired(token)) {
    return { ok: false, code: CODE.UNAUTHORIZED, message: "Please login to Cyber Hygiene again." };
  }

  if (!supportsPopupWebAuthn()) {
    return {
      ok: false,
      code: CODE.BIOMETRIC_FAILED,
      message: "Fingerprint prompts are not supported in this extension popup."
    };
  }

  try {
    const origin = getExtensionOrigin();
    const optionsResult = await apiRequest("/extension-passkeys/register/options", {
      method: "POST",
      token,
      body: { origin }
    });

    if (optionsResult.response.status === 401) {
      return { ok: false, code: CODE.UNAUTHORIZED, message: "Session expired. Please login again." };
    }

    if (!optionsResult.response.ok) {
      return {
        ok: false,
        code: CODE.NETWORK_ERROR,
        message:
          normalizeString(optionsResult.payload.detail, 256) ||
          "Could not start extension fingerprint registration."
      };
    }

    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: toCreationOptions(optionsResult.payload.options)
      });
    } catch (error) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: getWebAuthnErrorMessage(error, "Fingerprint registration was cancelled.")
      };
    }

    if (!credential) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: "Fingerprint registration was cancelled."
      };
    }

    const verifyResult = await apiRequest("/extension-passkeys/register/verify", {
      method: "POST",
      token,
      body: {
        origin,
        credential: serializeRegistrationCredential(credential)
      }
    });

    if (verifyResult.response.status === 401) {
      return { ok: false, code: CODE.UNAUTHORIZED, message: "Session expired. Please login again." };
    }

    if (!verifyResult.response.ok) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message:
          normalizeString(verifyResult.payload.detail, 256) ||
          "Could not finish extension fingerprint registration."
      };
    }

    return { ok: true, message: "Extension fingerprint registered successfully." };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while registering extension fingerprint."
    };
  }
}

async function authenticateWithExtensionPasskey() {
  if (!state.extensionPasskeyEnabled) {
    return {
      ok: false,
      code: CODE.BIOMETRIC_FAILED,
      message: "Enable extension fingerprint first."
    };
  }

  if (!supportsPopupWebAuthn()) {
    return {
      ok: false,
      code: CODE.BIOMETRIC_FAILED,
      message: "Fingerprint prompts are not supported in this extension popup."
    };
  }

  try {
    const origin = getExtensionOrigin();
    const optionsResult = await apiRequest("/extension-passkeys/login/options", {
      method: "POST",
      body: { origin }
    });

    if (!optionsResult.response.ok) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message:
          normalizeString(optionsResult.payload.detail, 256) ||
          "Could not start fingerprint verification."
      };
    }

    let credential;
    try {
      credential = await navigator.credentials.get({
        publicKey: toRequestOptions(optionsResult.payload.options)
      });
    } catch (error) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: getWebAuthnErrorMessage(error, "Fingerprint verification was cancelled.")
      };
    }

    if (!credential) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: "Fingerprint verification was cancelled."
      };
    }

    const verifyResult = await apiRequest("/extension-passkeys/login/verify", {
      method: "POST",
      body: {
        origin,
        attempt_id: optionsResult.payload.attempt_id,
        credential: serializeAuthenticationCredential(credential)
      }
    });

    if (!verifyResult.response.ok) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message:
          normalizeString(verifyResult.payload.detail, 256) ||
          "Fingerprint verification failed."
      };
    }

    const token = normalizeString(verifyResult.payload.token, 4096);
    if (!token) {
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: "Fingerprint verification did not return a login token."
      };
    }

    await setStoredToken(token);
    return { ok: true, token };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error during fingerprint verification."
    };
  }
}

async function unlockForAutofill() {
  const result = await authenticateWithExtensionPasskey();
  if (!result.ok) return result;

  const grant = await sendMessage({
    type: MESSAGE.GRANT_BIOMETRIC_UNLOCK,
    token: result.token,
    tabId: state.tabId,
    domain: state.domain
  });

  if (!grant.ok) {
    return {
      ok: false,
      code: grant.code || CODE.BIOMETRIC_FAILED,
      message: grant.message || "Could not unlock autofill after fingerprint verification."
    };
  }

  return { ok: true, token: result.token };
}

function setLoading(isLoading) {
  state.isLoading = isLoading;

  clearLoadingTimeout();
  if (isLoading) {
    loadingTimeoutId = setTimeout(() => {
      console.warn("setLoading timeout: forcing loader hide");
      state.isLoading = false;
      applyLoadingUi(false);
      setStatus("Loading timed out. Retry.", "warn");
      renderExtensionPasskey();
    }, 12000);
  }

  try {
    applyLoadingUi(isLoading);
    if (isLoading) {
      setLoadingMessage("Loading credentials...");
    }
    renderExtensionPasskey();
  } catch (error) {
    console.error("setLoading error", error);
    // ensure we don't leave stale loading indicator on error
    if (!isLoading) applyLoadingUi(false);
  }
}

function setExtensionPasskeyBusy(isBusy) {
  state.extensionPasskeyBusy = isBusy;
  renderExtensionPasskey();
}

function showSection(target) {
  el.credentialsSection.classList.add("hidden");
  el.emptySection.classList.add("hidden");

  if (target === "credentials") el.credentialsSection.classList.remove("hidden");
  if (target === "empty") el.emptySection.classList.remove("hidden");
}

function showLoginButton(show) {
  el.loginBtn.classList.toggle("hidden", !show);
}

function showSyncButton(show) {
  el.syncBtn.classList.toggle("hidden", !show);
}

function showNeverButton(show) {
  el.neverBtn.classList.toggle("hidden", !show);
}

function showAddButton(show) {
  el.addOpenBtn.classList.toggle("hidden", !show);
}

function showAddSection(show) {
  el.addSection.classList.toggle("hidden", !show);
}

function clearAddForm() {
  el.addUsername.value = "";
  el.addPassword.value = "";
}

function renderRisk(risk) {
  if (!risk) {
    el.riskSection.classList.add("hidden");
    el.riskLabel.textContent = "Checking page risk...";
    el.riskBadge.textContent = "Safe";
    el.riskBadge.className = "risk-badge safe";
    el.riskScore.textContent = "";
    el.riskReasons.innerHTML = "";
    return;
  }

  el.riskSection.classList.remove("hidden");
  el.riskLabel.textContent = risk.label || "Safe";
  el.riskBadge.textContent = risk.label || "Safe";
  el.riskScore.textContent = `Risk score: ${Number(risk.score) || 0}/100`;

  if (risk.level === "high") {
    el.riskBadge.className = "risk-badge danger";
  } else if (risk.level === "medium") {
    el.riskBadge.className = "risk-badge warn";
  } else {
    el.riskBadge.className = "risk-badge safe";
  }

  el.riskReasons.innerHTML = "";
  const reasons = Array.isArray(risk.reasons) ? risk.reasons : [];
  if (reasons.length === 0) {
    const item = document.createElement("div");
    item.className = "risk-reason";
    item.textContent =
      risk.level === "low"
        ? "No major phishing signals were detected on this page."
        : "This page triggered phishing heuristics, but no detailed reasons were returned.";
    el.riskReasons.appendChild(item);
    return;
  }

  reasons.forEach((reason) => {
    const item = document.createElement("div");
    item.className = "risk-reason";
    item.textContent = reason;
    el.riskReasons.appendChild(item);
  });
}

function hideAddForm() {
  showAddSection(false);
  clearAddForm();
}

function updateNeverButton() {
  if (!state.domain) {
    showNeverButton(false);
    return;
  }
  showNeverButton(true);
  if (state.blocked) {
    el.neverBtn.textContent = "Allow autofill on this site";
    el.neverBtn.className = "btn-secondary";
  } else {
    el.neverBtn.textContent = "Never autofill on this site";
    el.neverBtn.className = "btn-danger";
  }
}

function populateCredentialSelect(credentials) {
  el.credentialSelect.innerHTML = "";
  credentials.forEach((cred, idx) => {
    const opt = document.createElement("option");
    opt.value = cred.id;
    opt.textContent = cred.label || `Account ${idx + 1}`;
    el.credentialSelect.appendChild(opt);
  });
}

async function openLogin() {
  await sendMessage({ type: MESSAGE.OPEN_LOGIN });
}

async function redirectToLogin(statusMessage) {
  state.authorized = false;
  renderExtensionPasskey();
  showLoginButton(true);
  showSyncButton(true);
  showAddButton(false);
  hideAddForm();
  showSection(null);
  setStatus(statusMessage, "warn");

  if (!state.autoLoginOpened) {
    state.autoLoginOpened = true;
    try {
      await openLogin();
    } catch {
      // no-op
    }
  }
}

async function loadPhishingRisk() {
  if (!state.tabId || !state.domain) {
    state.risk = null;
    renderRisk(null);
    return;
  }

  try {
    const phishing = await withTimeout(
      sendMessage({
        type: MESSAGE.GET_PHISHING_RISK,
        tabId: state.tabId,
        domain: state.domain
      }),
      5000,
      "Page safety check timed out."
    );

    if (phishing && phishing.ok && phishing.risk) {
      state.risk = phishing.risk;
      renderRisk(state.risk);

      if (state.risk.level === "high") {
        showSection(null);
        setStatus("Likely phishing detected. Autofill has been blocked.", "error");
        return;
      }

      if (state.risk.level === "medium") {
        if (!state.credentials.length) {
          setStatus("This page looks suspicious. Review it carefully before trusting it.", "warn");
        } else if (state.extensionPasskeyEnabled) {
          setStatus("This page looks suspicious. Review the site carefully before autofill.", "warn");
        }
      }
      return;
    }
  } catch {
    // non-fatal
  }

  state.risk = null;
  renderRisk(null);
}

async function refreshPasskeyStateAfterRender(hasCredentials) {
  const result = await withTimeout(
    refreshExtensionPasskeyState(),
    8000,
    "Extension fingerprint check timed out."
  );

  if (!result.ok && result.code === CODE.UNAUTHORIZED) {
    await redirectToLogin("Session expired. Please login to Cyber Hygiene.");
    return;
  }

  if (hasCredentials && !state.extensionPasskeyEnabled) {
    setStatus("Enable extension fingerprint to autofill without leaving this popup.", "warn");
  }
}

async function loadPopupData() {
  setLoading(true);
  setLoadingMessage("Resolving current site...");
  hideAddForm();
  showSection(null);
  showLoginButton(false);
  showSyncButton(false);
  showAddButton(false);

  try {
    const context = await withTimeout(
      getActiveContextDirect(),
      4000,
      "Active tab lookup timed out."
    );

    if (!context.ok) {
      state.tabId = null;
      state.domain = "";
      state.blocked = false;
      state.risk = null;
      state.authorized = false;
      el.domainValue.textContent = "-";
      showNeverButton(false);
      showAddButton(false);
      renderRisk(null);
      renderExtensionPasskey();
      setStatus(context.message || "Unsupported page.", "warn");
      return;
    }

    state.tabId = Number(context.tabId) || null;
    state.domain = context.domain || "";
    state.blocked = Boolean(context.blocked);
    el.domainValue.textContent = state.domain || "-";
    updateNeverButton();

    const tokenState = await ensureAuthorizedToken();
    const tokenExpired = tokenState.code === CODE.UNAUTHORIZED;
    state.authorized = Boolean(tokenState.ok);
    state.extensionPasskeySupported = supportsPopupWebAuthn();

    state.risk = null;
    renderRisk(null);

    if (!state.authorized) {
      renderExtensionPasskey();
      const msg = tokenExpired
        ? "Session expired. Please login to Cyber Hygiene."
        : "Please login to Cyber Hygiene.";
      showLoginButton(true);
      showSyncButton(true);
      showAddButton(false);
      showSection(null);
      setStatus(msg, "warn");
      return;
    }

    showAddButton(true);

    if (state.blocked) {
      showSection(null);
      setStatus("Autofill is disabled for this site.", "warn");
      void refreshPasskeyStateAfterRender(false);
      void loadPhishingRisk();
      return;
    }

    setLoadingMessage("Loading saved credentials...");
    setStatus("Loading credentials...", "info");
    const vault = await withTimeout(
      fetchVaultDirect(state.domain),
      8000,
      "Credential loading timed out."
    );

    if (!vault.ok) {
      if (vault.code === CODE.NO_TOKEN || vault.code === CODE.UNAUTHORIZED) {
        await redirectToLogin("Session expired. Please login to Cyber Hygiene.");
        return;
      }

      if (vault.code === CODE.SITE_BLOCKED) {
        state.blocked = true;
        updateNeverButton();
        showSection(null);
        setStatus("Autofill is disabled for this site.", "warn");
        return;
      }

      if (vault.code === CODE.PHISHING_BLOCKED) {
        showSection(null);
        setStatus(vault.message || "Likely phishing detected. Autofill blocked.", "error");
        return;
      }

      if (vault.code === CODE.UNSUPPORTED_PAGE) {
        showSection(null);
        setStatus(vault.message || "Unsupported page.", "warn");
        return;
      }

      if (vault.code === CODE.NETWORK_ERROR) {
        showSection(null);
        setStatus("Network error. Check backend connectivity.", "error");
        return;
      }

      showSection(null);
      setStatus(vault.message || "Failed to fetch vault credentials.", "error");
      return;
    }

    const credentials = Array.isArray(vault.credentials) ? vault.credentials : [];
    state.credentials = credentials;

    if (credentials.length === 0) {
      showSection("empty");
      setStatus("No credentials found for this domain.", "info");
      void refreshPasskeyStateAfterRender(false);
      void loadPhishingRisk();
      return;
    }

    populateCredentialSelect(credentials);
    showSection("credentials");
    setStatus("Credential found. Click Autofill to continue.", "success");
    void refreshPasskeyStateAfterRender(true);
    void loadPhishingRisk();
  } catch {
    showSection(null);
    renderRisk(null);
    renderExtensionPasskey("Unexpected extension error.");
    setStatus("Unexpected extension error.", "error");
  } finally {
    setLoading(false);
  }
}

async function syncSessionFromApp() {
  setLoading(true);
  try {
    const result = await sendMessage({ type: MESSAGE.SYNC_TOKEN_FROM_APP });
    if (!result.ok) {
      setStatus(result.message || "Could not sync login session.", "warn");
      return;
    }
    setStatus("Login session synced. Loading vault...", "success");
    await loadPopupData();
  } catch {
    setStatus("Could not sync login session.", "error");
  } finally {
    setLoading(false);
  }
}

async function onExtensionPasskeyClick() {
  if (!state.authorized) {
    await redirectToLogin("Please login to Cyber Hygiene.");
    return;
  }

  try {
    const url = chrome.runtime.getURL("passkey-setup.html");
    await chrome.tabs.create({ url });
    setStatus(
      state.extensionPasskeyEnabled
        ? "Opened extension fingerprint replacement page."
        : "Opened extension fingerprint setup page.",
      "info"
    );
  } catch {
    setStatus("Could not open extension fingerprint setup page.", "error");
  }
}

async function onAutofillClick() {
  if (!state.authorized) {
    await redirectToLogin("Please login to Cyber Hygiene.");
    return;
  }

  if (state.blocked) {
    setStatus("Autofill is disabled for this site.", "warn");
    return;
  }

  if (state.risk && state.risk.level === "high") {
    setStatus("Likely phishing detected. Autofill has been blocked.", "error");
    return;
  }

  if (!state.extensionPasskeyEnabled) {
    setStatus("Enable extension fingerprint first so autofill can stay inside this popup.", "warn");
    return;
  }

  const credentialId = el.credentialSelect.value;
  if (!credentialId) {
    setStatus("No credential selected.", "warn");
    return;
  }

  const selected = state.credentials.find((item) => item.id === credentialId);
  const label = encodeURIComponent(selected ? selected.label : "Saved account");
  const url =
    chrome.runtime.getURL("autofill-auth.html") +
    `?tabId=${encodeURIComponent(String(state.tabId || ""))}` +
    `&domain=${encodeURIComponent(state.domain || "")}` +
    `&credentialId=${encodeURIComponent(credentialId)}` +
    `&account=${label}`;

  try {
    await chrome.tabs.create({ url });
    setStatus("Opened extension fingerprint window for autofill.", "info");
  } catch {
    setStatus("Could not open autofill fingerprint window.", "error");
  }
}

async function onNeverToggleClick() {
  if (!state.domain) return;
  setLoading(true);

  try {
    const nextEnabled = !state.blocked;
    const result = await sendMessage({
      type: MESSAGE.SET_NEVER_AUTOFILL,
      domain: state.domain,
      enabled: nextEnabled
    });

    if (!result.ok) {
      setStatus(result.message || "Could not update site rule.", "error");
      return;
    }

    state.blocked = Boolean(result.blocked);
    updateNeverButton();

    if (state.blocked) {
      showSection(null);
      setStatus("This site has been blocked for autofill.", "warn");
    } else {
      setStatus("Site unblocked. Fetching credentials...", "info");
      await loadPopupData();
    }
  } catch {
    setStatus("Could not update site rule.", "error");
  } finally {
    setLoading(false);
  }
}

async function onAddOpenClick() {
  if (!state.domain) {
    setStatus("Open a website tab first.", "warn");
    return;
  }

  if (!state.authorized) {
    await redirectToLogin("Please login to Cyber Hygiene.");
    return;
  }

  showAddSection(true);
  setStatus(`Add credential for ${state.domain}.`, "info");
}

async function onSaveAddClick() {
  if (!state.domain) {
    setStatus("No active domain detected.", "warn");
    return;
  }

  if (!state.authorized) {
    await redirectToLogin("Please login to Cyber Hygiene.");
    return;
  }

  const username = (el.addUsername.value || "").trim();
  const password = (el.addPassword.value || "").trim();

  if (!username || !password) {
    setStatus("Enter username and password.", "warn");
    return;
  }

  setLoading(true);
  setStatus("Saving credential...", "info");

  try {
    let result;
    try {
      result = await sendMessage({
        type: MESSAGE.CAPTURE_LOGIN_CREDENTIAL,
        domain: state.domain,
        site: state.domain,
        username,
        password
      });
    } catch {
      result = await saveCredentialDirect(state.domain, username, password);
    }

    if (!result.ok && isUnknownMessageType(result)) {
      result = await saveCredentialDirect(state.domain, username, password);
    }

    if (!result.ok) {
      if (result.code === CODE.NO_TOKEN || result.code === CODE.UNAUTHORIZED) {
        await redirectToLogin("Session expired. Please login to Cyber Hygiene.");
        return;
      }

      if (result.code === CODE.NETWORK_ERROR) {
        setStatus("Network error. Check backend connectivity.", "error");
        return;
      }

      setStatus(result.message || "Could not save credential.", "error");
      return;
    }

    hideAddForm();
    setStatus("Credential saved successfully.", "success");
    await loadPopupData();
  } catch {
    setStatus("Could not save credential.", "error");
  } finally {
    setLoading(false);
  }
}

function bindEvents() {
  el.loginBtn.addEventListener("click", async () => {
    try {
      await openLogin();
    } catch {
      setStatus("Unable to open login page.", "error");
    }
  });

  el.syncBtn.addEventListener("click", async () => {
    await syncSessionFromApp();
  });

  el.refreshBtn.addEventListener("click", () => {
    state.autoLoginOpened = false;
    loadPopupData();
  });

  el.extensionPasskeyBtn.addEventListener("click", onExtensionPasskeyClick);
  el.autofillBtn.addEventListener("click", onAutofillClick);
  el.neverBtn.addEventListener("click", onNeverToggleClick);
  el.addOpenBtn.addEventListener("click", onAddOpenClick);
  el.cancelAddBtn.addEventListener("click", () => {
    hideAddForm();
    setStatus("Add credential cancelled.", "info");
  });
  el.saveAddBtn.addEventListener("click", onSaveAddClick);
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await loadPopupData();
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || !changes[CONFIG.TOKEN_KEY]) {
    return;
  }

  if (tokenChangeReloadTimer) {
    window.clearTimeout(tokenChangeReloadTimer);
  }

  tokenChangeReloadTimer = window.setTimeout(() => {
    tokenChangeReloadTimer = null;
    state.autoLoginOpened = false;
    loadPopupData();
  }, 250);
});

window.addEventListener("focus", () => {
  state.autoLoginOpened = false;
  loadPopupData();
});
