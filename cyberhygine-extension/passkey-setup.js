const CONFIG = Object.freeze({
  API_BASE_URL: "http://localhost:9000/api",
  LOGIN_URL: "http://localhost:3000/login",
  TOKEN_KEY: "jwt_token",
  REQUEST_TIMEOUT_MS: 10000
});

const MESSAGE = Object.freeze({
  SYNC_TOKEN_FROM_APP: "SYNC_TOKEN_FROM_APP",
  OPEN_LOGIN: "OPEN_LOGIN",
  SET_TOKEN: "SET_TOKEN"
});

const statusEl = document.getElementById("status");
const originValueEl = document.getElementById("originValue");
const passkeyStateEl = document.getElementById("passkeyState");
const setupBtn = document.getElementById("setupBtn");
const syncBtn = document.getElementById("syncBtn");
const loginBtn = document.getElementById("loginBtn");
const closeBtn = document.getElementById("closeBtn");

let busy = false;

function normalizeString(value, maxLen = 4096) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function setStatus(message, type = "info") {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
}

function setBusy(nextBusy) {
  busy = nextBusy;
  setupBtn.disabled = nextBusy;
  syncBtn.disabled = nextBusy;
  loginBtn.disabled = nextBusy;
}

function storageGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function storageSet(items) {
  return new Promise((resolve) => chrome.storage.local.set(items, resolve));
}

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

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function isJwtExpired(token) {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== "number") return true;
  return Date.now() >= payload.exp * 1000;
}

async function getStoredToken() {
  const data = await storageGet([CONFIG.TOKEN_KEY]);
  return normalizeString(data[CONFIG.TOKEN_KEY], 4096);
}

async function setStoredToken(token) {
  await storageSet({ [CONFIG.TOKEN_KEY]: token });
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
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== null) headers["Content-Type"] = "application/json";

  const response = await fetchWithTimeout(`${CONFIG.API_BASE_URL}${path}`, {
    method,
    headers,
    body: body === null ? undefined : JSON.stringify(body),
    cache: "no-store"
  });
  const payload = await parseJsonResponse(response);
  return { response, payload };
}

function getExtensionOrigin() {
  return normalizeString(window.location.origin, 2048);
}

function supportsWebAuthn() {
  return typeof window.PublicKeyCredential !== "undefined" && !!navigator.credentials;
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

function getWebAuthnErrorMessage(error, fallbackMessage) {
  if (!error) return fallbackMessage;
  if (error.name === "NotAllowedError") {
    return "Fingerprint registration was cancelled or timed out.";
  }
  if (error.name === "InvalidStateError") {
    return "An extension fingerprint already exists for this origin on this device. If this keeps happening, remove the old unpacked extension, reload this one, and try again once.";
  }
  if (error.name === "NotSupportedError") {
    return "This browser does not support extension fingerprint setup here.";
  }
  return normalizeString(error.message, 256) || fallbackMessage;
}

async function syncSessionFromApp() {
  try {
    const result = await sendMessage({ type: MESSAGE.SYNC_TOKEN_FROM_APP }, 6000);
    if (!result || !result.ok) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

async function ensureToken() {
  let token = await getStoredToken();
  if (token && !isJwtExpired(token)) {
    return token;
  }

  const synced = await syncSessionFromApp();
  if (!synced) {
    return "";
  }

  token = await getStoredToken();
  if (!token || isJwtExpired(token)) {
    return "";
  }

  return token;
}

async function loadStatus() {
  originValueEl.textContent = getExtensionOrigin();

  if (!supportsWebAuthn()) {
    passkeyStateEl.textContent = "WebAuthn not supported in this browser";
    setupBtn.disabled = true;
    setStatus("This browser cannot register an extension fingerprint here.", "error");
    return;
  }

  const token = await ensureToken();
  if (!token) {
    passkeyStateEl.textContent = "Not logged in";
    setStatus("Login to Cyber Hygiene first, then click Sync login from Cyber Hygiene.", "warn");
    return;
  }

  const origin = encodeURIComponent(getExtensionOrigin());
  const { response, payload } = await apiRequest(`/extension-passkeys/status?origin=${origin}`, {
    token
  });

  if (response.status === 401) {
    passkeyStateEl.textContent = "Session expired";
    setStatus("Your session expired. Login to Cyber Hygiene again.", "warn");
    return;
  }

  if (!response.ok) {
    passkeyStateEl.textContent = "Status unavailable";
    setStatus(
      normalizeString(payload.detail, 256) || "Could not load extension fingerprint status.",
      "error"
    );
    return;
  }

  const count = Number(payload.passkey_count) || 0;
  if (count > 0) {
    passkeyStateEl.textContent = `${count} registered for this extension origin`;
    setupBtn.textContent = "Replace extension fingerprint";
    setStatus("You can replace the current extension fingerprint from here.", "info");
  } else {
    passkeyStateEl.textContent = "No fingerprint registered for this extension origin";
    setupBtn.textContent = "Enable fingerprint in extension";
    setStatus("Register a fingerprint for this extension.", "info");
  }
}

async function replaceAndRegister() {
  if (!supportsWebAuthn()) {
    setStatus("This browser does not support extension fingerprint setup here.", "error");
    return;
  }

  setBusy(true);
  try {
    const token = await ensureToken();
    if (!token) {
      setStatus("Login to Cyber Hygiene first, then click Sync login from Cyber Hygiene.", "warn");
      return;
    }

    const origin = getExtensionOrigin();
    setStatus("Preparing extension fingerprint registration...", "info");

    await apiRequest(`/extension-passkeys?origin=${encodeURIComponent(origin)}`, {
      method: "DELETE",
      token
    });

    const optionsResult = await apiRequest("/extension-passkeys/register/options", {
      method: "POST",
      token,
      body: { origin }
    });

    if (optionsResult.response.status === 401) {
      setStatus("Your session expired. Login to Cyber Hygiene again.", "warn");
      return;
    }

    if (!optionsResult.response.ok) {
      setStatus(
        normalizeString(optionsResult.payload.detail, 256) ||
          "Could not start extension fingerprint registration.",
        "error"
      );
      return;
    }

    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: toCreationOptions(optionsResult.payload.options)
      });
    } catch (error) {
      setStatus(getWebAuthnErrorMessage(error, "Fingerprint registration failed."), "error");
      return;
    }

    if (!credential) {
      setStatus("Fingerprint registration was cancelled.", "warn");
      return;
    }

    const verifyResult = await apiRequest("/extension-passkeys/register/verify", {
      method: "POST",
      token,
      body: {
        origin,
        credential: serializeRegistrationCredential(credential)
      }
    });

    if (!verifyResult.response.ok) {
      setStatus(
        normalizeString(verifyResult.payload.detail, 256) ||
          "Could not finish extension fingerprint registration.",
        "error"
      );
      return;
    }

    await setStoredToken(token);
    try {
      await sendMessage({ type: MESSAGE.SET_TOKEN, token }, 3000);
    } catch {
      // non-fatal
    }

    passkeyStateEl.textContent = "1 registered for this extension origin";
    setupBtn.textContent = "Replace extension fingerprint";
    setStatus("Extension fingerprint registered successfully. You can go back to the side panel now.", "success");
  } catch {
    setStatus("Unexpected error while registering extension fingerprint.", "error");
  } finally {
    setBusy(false);
  }
}

setupBtn.addEventListener("click", replaceAndRegister);

syncBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    const synced = await syncSessionFromApp();
    if (!synced) {
      setStatus("Could not sync login from the Cyber Hygiene app tab.", "error");
      return;
    }
    setStatus("Login synced. Checking extension fingerprint status...", "success");
    await loadStatus();
  } finally {
    setBusy(false);
  }
});

loginBtn.addEventListener("click", async () => {
  try {
    await sendMessage({ type: MESSAGE.OPEN_LOGIN }, 4000);
  } catch {
    chrome.tabs.create({ url: CONFIG.LOGIN_URL });
  }
});

closeBtn.addEventListener("click", () => {
  window.close();
});

document.addEventListener("DOMContentLoaded", () => {
  loadStatus();
});
