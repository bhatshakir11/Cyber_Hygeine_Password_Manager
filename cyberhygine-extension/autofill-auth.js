const CONFIG = Object.freeze({
  API_BASE_URL: "http://localhost:9000/api",
  TOKEN_KEY: "jwt_token",
  REQUEST_TIMEOUT_MS: 10000
});

const MESSAGE = Object.freeze({
  GRANT_BIOMETRIC_UNLOCK: "GRANT_BIOMETRIC_UNLOCK",
  PERFORM_AUTOFILL: "PERFORM_AUTOFILL",
  SET_TOKEN: "SET_TOKEN"
});

const statusEl = document.getElementById("status");
const domainLabelEl = document.getElementById("domainLabel");
const accountLabelEl = document.getElementById("accountLabel");
const retryBtn = document.getElementById("retryBtn");
const closeBtn = document.getElementById("closeBtn");

function normalizeString(value, maxLen = 4096) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function setStatus(message, type = "info") {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
}

function storageGet(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

function storageSet(items) {
  return new Promise((resolve) => chrome.storage.local.set(items, resolve));
}

async function getStoredToken() {
  const data = await storageGet([CONFIG.TOKEN_KEY]);
  return normalizeString(data[CONFIG.TOKEN_KEY], 4096);
}

async function setStoredToken(token) {
  await storageSet({ [CONFIG.TOKEN_KEY]: token });
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

async function apiRequest(path, { method = "GET", body = null } = {}) {
  const headers = { Accept: "application/json" };
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
  if (error.name === "NotSupportedError") {
    return "This browser does not support extension fingerprint verification here.";
  }
  return normalizeString(error.message, 256) || fallbackMessage;
}

async function authenticateWithExtensionPasskey() {
  const origin = getExtensionOrigin();
  const optionsResult = await apiRequest("/extension-passkeys/login/options", {
    method: "POST",
    body: { origin }
  });

  if (!optionsResult.response.ok) {
    return {
      ok: false,
      message:
        normalizeString(optionsResult.payload.detail, 256) ||
        "Could not start fingerprint verification."
    };
  }

  let credential;
  try {
    if (navigator.credentials && typeof navigator.credentials.preventSilentAccess === "function") {
      try {
        await navigator.credentials.preventSilentAccess();
      } catch {
        // no-op
      }
    }

    credential = await navigator.credentials.get({
      publicKey: toRequestOptions(optionsResult.payload.options),
      mediation: "required"
    });
  } catch (error) {
    return {
      ok: false,
      message: getWebAuthnErrorMessage(error, "Fingerprint verification failed.")
    };
  }

  if (!credential) {
    return {
      ok: false,
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
      message:
        normalizeString(verifyResult.payload.detail, 256) || "Fingerprint verification failed."
    };
  }

  const token = normalizeString(verifyResult.payload.token, 4096);
  if (!token) {
    return {
      ok: false,
      message: "Fingerprint verification did not return a login token."
    };
  }

  await setStoredToken(token);
  try {
    await sendMessage({ type: MESSAGE.SET_TOKEN, token }, 3000);
  } catch {
    // non-fatal
  }

  return { ok: true, token };
}

function getParams() {
  const url = new URL(window.location.href);
  return {
    tabId: Number(url.searchParams.get("tabId")) || null,
    domain: normalizeString(url.searchParams.get("domain"), 256),
    credentialId: normalizeString(url.searchParams.get("credentialId"), 256),
    account: normalizeString(url.searchParams.get("account"), 256)
  };
}

async function runAutofill() {
  const params = getParams();
  domainLabelEl.textContent = `Domain: ${params.domain || "-"}`;
  accountLabelEl.textContent = `Account: ${params.account || "-"}`;

  if (!params.tabId || !params.domain || !params.credentialId) {
    setStatus("Missing autofill details. Close this page and try again.", "error");
    return;
  }

  setStatus("Touch your fingerprint sensor to continue...", "info");
  const unlock = await authenticateWithExtensionPasskey();
  if (!unlock.ok) {
    setStatus(unlock.message || "Fingerprint verification failed.", "error");
    return;
  }

  const grant = await sendMessage({
    type: MESSAGE.GRANT_BIOMETRIC_UNLOCK,
    token: unlock.token,
    tabId: params.tabId,
    domain: params.domain
  }, 8000);

  if (!grant.ok) {
    setStatus(grant.message || "Could not unlock autofill.", "error");
    return;
  }

  setStatus("Fingerprint verified. Filling credentials...", "info");
  const result = await sendMessage({
    type: MESSAGE.PERFORM_AUTOFILL,
    credentialId: params.credentialId,
    tabId: params.tabId,
    domain: params.domain
  }, 8000);

  if (!result.ok) {
    setStatus(result.message || "Autofill failed.", "error");
    return;
  }

  setStatus(result.message || "Credentials autofilled successfully.", "success");
  window.setTimeout(() => window.close(), 1000);
}

retryBtn.addEventListener("click", () => {
  runAutofill();
});

closeBtn.addEventListener("click", () => {
  window.close();
});

document.addEventListener("DOMContentLoaded", () => {
  runAutofill();
});
