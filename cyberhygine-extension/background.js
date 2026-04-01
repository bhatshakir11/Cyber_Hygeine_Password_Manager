const CONFIG = Object.freeze({
  API_BASE_URL: "http://localhost:9000/api",
  LOGIN_URL: "http://localhost:3000/login",
  APP_ORIGINS: ["http://localhost:3000", "https://localhost:3000"],
  TOKEN_KEY: "jwt_token",
  NEVER_AUTOFILL_KEY: "never_autofill_domains",
  REQUEST_TIMEOUT_MS: 10000,
  BIOMETRIC_UNLOCK_TTL_MS: 30000
});

const MESSAGE = Object.freeze({
  GET_ACTIVE_CONTEXT: "GET_ACTIVE_CONTEXT",
  GET_PHISHING_RISK: "GET_PHISHING_RISK",
  GET_AUTH_STATUS: "GET_AUTH_STATUS",
  OPEN_LOGIN: "OPEN_LOGIN",
  SYNC_TOKEN_FROM_APP: "SYNC_TOKEN_FROM_APP",
  REQUEST_BIOMETRIC_GATE: "REQUEST_BIOMETRIC_GATE",
  GRANT_BIOMETRIC_UNLOCK: "GRANT_BIOMETRIC_UNLOCK",
  FETCH_VAULT_FOR_ACTIVE_TAB: "FETCH_VAULT_FOR_ACTIVE_TAB",
  PERFORM_AUTOFILL: "PERFORM_AUTOFILL",
  CAPTURE_LOGIN_CREDENTIAL: "CAPTURE_LOGIN_CREDENTIAL",
  SET_NEVER_AUTOFILL: "SET_NEVER_AUTOFILL",
  GET_NEVER_AUTOFILL_STATUS: "GET_NEVER_AUTOFILL_STATUS",
  SET_TOKEN: "SET_TOKEN",
  CLEAR_TOKEN: "CLEAR_TOKEN"
});

const CODE = Object.freeze({
  OK: "OK",
  NO_TOKEN: "NO_TOKEN",
  UNAUTHORIZED: "UNAUTHORIZED",
  UNSUPPORTED_PAGE: "UNSUPPORTED_PAGE",
  SITE_BLOCKED: "SITE_BLOCKED",
  NETWORK_ERROR: "NETWORK_ERROR",
  API_ERROR: "API_ERROR",
  INVALID_RESPONSE: "INVALID_RESPONSE",
  CREDENTIAL_NOT_FOUND: "CREDENTIAL_NOT_FOUND",
  DOMAIN_MISMATCH: "DOMAIN_MISMATCH",
  PHISHING_BLOCKED: "PHISHING_BLOCKED",
  PHISHING_WARNING: "PHISHING_WARNING",
  INTERNAL_ERROR: "INTERNAL_ERROR",
  BIOMETRIC_FAILED: "BIOMETRIC_FAILED"
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

const storageGet = (keys) =>
  new Promise((resolve) => chrome.storage.local.get(keys, resolve));

const storageSet = (items) =>
  new Promise((resolve) => chrome.storage.local.set(items, resolve));

const storageRemove = (keys) =>
  new Promise((resolve) => chrome.storage.local.remove(keys, resolve));

let biometricUnlock = {
  tabId: null,
  domain: "",
  expiresAt: 0
};

const riskCache = new Map();

function normalizeString(value, maxLen = 1024) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
}

function isIPv4(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}

function extractHostname(value) {
  const input = normalizeString(value, 2048);
  if (!input) return "";
  try {
    if (/^https?:\/\//i.test(input)) {
      return new URL(input).hostname.toLowerCase();
    }
    return new URL(`https://${input}`).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function getBaseDomainFromHostname(hostnameInput) {
  let hostname = normalizeString(hostnameInput).toLowerCase();
  if (!hostname) return "";
  hostname = hostname.replace(/\.+$/, "");
  if (!hostname) return "";

  if (hostname === "localhost" || isIPv4(hostname) || hostname.includes(":")) {
    return hostname;
  }

  const parts = hostname.split(".").filter(Boolean);
  if (parts.length <= 2) return hostname;

  const last2 = parts.slice(-2).join(".");
  const last3 = parts.slice(-3).join(".");

  if (SECOND_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) {
    return last3;
  }

  return last2;
}

function getBaseDomain(value) {
  const hostname = extractHostname(value);
  return getBaseDomainFromHostname(hostname);
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

function looksLikeJwt(token) {
  const value = normalizeString(token, 4096);
  return /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/.test(value);
}

async function getToken() {
  const data = await storageGet([CONFIG.TOKEN_KEY]);
  const token = normalizeString(data[CONFIG.TOKEN_KEY], 4096);
  return token || "";
}

async function setToken(token) {
  await storageSet({ [CONFIG.TOKEN_KEY]: token });
}

async function clearToken() {
  await storageRemove([CONFIG.TOKEN_KEY]);
}

async function getNeverAutofillDomains() {
  const data = await storageGet([CONFIG.NEVER_AUTOFILL_KEY]);
  const raw = Array.isArray(data[CONFIG.NEVER_AUTOFILL_KEY])
    ? data[CONFIG.NEVER_AUTOFILL_KEY]
    : [];
  const normalized = raw.map((d) => getBaseDomain(d)).filter(Boolean);
  return [...new Set(normalized)];
}

async function isNeverAutofill(domain) {
  const baseDomain = getBaseDomain(domain);
  if (!baseDomain) return false;
  const list = await getNeverAutofillDomains();
  return list.includes(baseDomain);
}

async function setNeverAutofill(domain, enabled) {
  const baseDomain = getBaseDomain(domain);
  if (!baseDomain) return false;

  const list = await getNeverAutofillDomains();
  const next = new Set(list);

  if (enabled) next.add(baseDomain);
  else next.delete(baseDomain);

  await storageSet({ [CONFIG.NEVER_AUTOFILL_KEY]: [...next] });
  return enabled;
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs.length > 0 ? tabs[0] : null;
}

function isTrustedAppUrl(urlValue) {
  try {
    const url = new URL(urlValue);
    const protocol = url.protocol.toLowerCase();
    const hostname = url.hostname.toLowerCase();
    const port = url.port || (protocol === "https:" ? "443" : protocol === "http:" ? "80" : "");

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

async function findTrustedAppTab() {
  const tabs = await chrome.tabs.query({});
  return tabs.find((tab) => tab && tab.id && tab.url && isTrustedAppUrl(tab.url)) || null;
}

async function trySyncTokenFromAppTabs() {
  const appTab = await findTrustedAppTab();
  if (!appTab || !appTab.id) {
    return { ok: false, code: CODE.NO_TOKEN, message: "Open Cyber Hygiene app and login first." };
  }

  try {
    const response = await sendMessageToTab(appTab.id, { type: "CYBERHYGIENE_READ_APP_TOKEN" });
    const token = normalizeString(response && response.token, 4096);
    if (!looksLikeJwt(token) || isJwtExpired(token)) {
      return { ok: false, code: CODE.UNAUTHORIZED, message: "Login session not found or expired." };
    }
    await setToken(token);
    return { ok: true, code: CODE.OK };
  } catch {
    try {
      await ensureContentScript(appTab.id);
      const response = await sendMessageToTab(appTab.id, { type: "CYBERHYGIENE_READ_APP_TOKEN" });
      const token = normalizeString(response && response.token, 4096);
      if (!looksLikeJwt(token) || isJwtExpired(token)) {
        return { ok: false, code: CODE.UNAUTHORIZED, message: "Login session not found or expired." };
      }
      await setToken(token);
      return { ok: true, code: CODE.OK };
    } catch {
      return { ok: false, code: CODE.INTERNAL_ERROR, message: "Could not sync token from app tab." };
    }
  }
}

async function requestBiometricGateViaAppTab(requestMessage) {
  const targetContext = await getContextForRequest(requestMessage);
  if (!targetContext.ok) {
    clearBiometricUnlock();
    return targetContext;
  }

  const appTab = await findTrustedAppTab();
  if (!appTab || !appTab.id) {
    clearBiometricUnlock();
    return {
      ok: false,
      code: CODE.BIOMETRIC_FAILED,
      message: "Open Cyber Hygiene app tab and login before autofill."
    };
  }

  const biometricMessage = { type: "CYBERHYGIENE_BIOMETRIC_GATE" };

  const parseResult = async (response) => {
    if (!response || !response.ok) {
      clearBiometricUnlock();
      return {
        ok: false,
        code: CODE.BIOMETRIC_FAILED,
        message: (response && response.message) || "Biometric verification failed."
      };
    }

    const newToken = normalizeString(response.token, 4096);
    if (looksLikeJwt(newToken) && !isJwtExpired(newToken)) {
      await setToken(newToken);
    }

    setBiometricUnlock(targetContext.tabId, targetContext.domain);
    return { ok: true, code: CODE.OK };
  };

  const runBiometricRequest = async () => {
    try {
      const response = await sendMessageToTab(appTab.id, biometricMessage);
      return parseResult(response);
    } catch {
      try {
        await ensureContentScript(appTab.id);
        const response = await sendMessageToTab(appTab.id, biometricMessage);
        return parseResult(response);
      } catch {
        return {
          ok: false,
          code: CODE.BIOMETRIC_FAILED,
          message: "Unable to start biometric verification."
        };
      }
    }
  };

  // First attempt without switching tabs; if browser blocks it, fallback to focused app tab.
  let result = await runBiometricRequest();

  if (!result.ok) {
    const originalTab = await getActiveTab();
    let switched = false;

    try {
      if (appTab.windowId) {
        await chrome.windows.update(appTab.windowId, { focused: true });
      }
      await chrome.tabs.update(appTab.id, { active: true });
      switched = true;
    } catch {
      switched = false;
    }

    result = await runBiometricRequest();

    if (switched) {
      try {
        if (originalTab && originalTab.id) {
          if (originalTab.windowId) {
            await chrome.windows.update(originalTab.windowId, { focused: true });
          }
          await chrome.tabs.update(originalTab.id, { active: true });
        }
      } catch {
        // non-fatal
      }
    }
  }

  if (!result || !result.ok) {
    clearBiometricUnlock();
  }

  return result;
}


async function getContextFromTab(tab, emptyMessage = "No active tab.") {
  if (!tab || !tab.id || !tab.url) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: emptyMessage
    };
  }

  let url;
  try {
    url = new URL(tab.url);
  } catch {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Unsupported tab URL."
    };
  }

  if (!/^https?:$/.test(url.protocol)) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Autofill works only on http/https pages."
    };
  }

  const domain = getBaseDomainFromHostname(url.hostname);
  if (!domain) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Unable to detect domain."
    };
  }

  const blocked = await isNeverAutofill(domain);

  return {
    ok: true,
    code: CODE.OK,
    tabId: tab.id,
    url: tab.url,
    domain,
    blocked
  };
}

async function getActiveContext() {
  const tab = await getActiveTab();
  return getContextFromTab(tab, "No active tab.");
}

async function getContextByTabId(tabId) {
  const parsed = Number(tabId);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Invalid target tab."
    };
  }

  try {
    const tab = await chrome.tabs.get(parsed);
    return getContextFromTab(tab, "Target tab is not available.");
  } catch {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Target tab is not available."
    };
  }
}

async function getContextForRequest(message) {
  const requestedTabId = Number(message && message.tabId);
  const requestedDomain = getBaseDomain(message && message.domain);

  if (Number.isInteger(requestedTabId) && requestedTabId > 0) {
    const context = await getContextByTabId(requestedTabId);
    if (!context.ok) return context;

    if (requestedDomain && context.domain !== requestedDomain) {
      return {
        ok: false,
        code: CODE.DOMAIN_MISMATCH,
        message: "Active site changed. Open the target login tab and retry."
      };
    }

    return context;
  }

  const activeContext = await getActiveContext();
  if (!activeContext.ok) return activeContext;

  if (requestedDomain && activeContext.domain !== requestedDomain) {
    return {
      ok: false,
      code: CODE.DOMAIN_MISMATCH,
      message: "Active site changed. Open the target login tab and retry."
    };
  }

  return activeContext;
}

function clearBiometricUnlock() {
  biometricUnlock = {
    tabId: null,
    domain: "",
    expiresAt: 0
  };
}

function setBiometricUnlock(tabId, domain) {
  const normalizedDomain = getBaseDomain(domain);
  if (!tabId || !normalizedDomain) {
    clearBiometricUnlock();
    return;
  }

  biometricUnlock = {
    tabId,
    domain: normalizedDomain,
    expiresAt: Date.now() + CONFIG.BIOMETRIC_UNLOCK_TTL_MS
  };
}

function hasValidBiometricUnlock(context) {
  if (!context || !context.ok) return false;
  if (!biometricUnlock || !biometricUnlock.tabId || !biometricUnlock.domain) return false;
  if (Date.now() > biometricUnlock.expiresAt) return false;
  return (
    biometricUnlock.tabId === context.tabId &&
    biometricUnlock.domain === context.domain
  );
}

function getRiskCacheKey(tabId, url) {
  const parsedTabId = Number(tabId);
  const normalizedUrl = normalizeString(url, 4096);
  return `${parsedTabId || 0}|${normalizedUrl}`;
}

function getCachedRisk(tabId, url, maxAgeMs = 5000) {
  const key = getRiskCacheKey(tabId, url);
  const cached = riskCache.get(key);
  if (!cached) return null;
  if (Date.now() - cached.timestamp > maxAgeMs) {
    riskCache.delete(key);
    return null;
  }
  return cached.value;
}

function setCachedRisk(tabId, url, value) {
  const key = getRiskCacheKey(tabId, url);
  riskCache.set(key, {
    timestamp: Date.now(),
    value
  });
}

async function analyzePageRiskForContext(context, maxAgeMs = 5000) {
  if (!context || !context.ok) {
    return {
      ok: false,
      code: CODE.UNSUPPORTED_PAGE,
      message: "Unsupported page."
    };
  }

  const cached = getCachedRisk(context.tabId, context.url, maxAgeMs);
  if (cached) {
    return cached;
  }

  const result = await analyzePageRiskInTab(context.tabId);
  if (result && typeof result === "object" && result.ok) {
    setCachedRisk(context.tabId, context.url, result);
  }
  return result;
}

async function initializeSidePanelBehavior() {
  if (!chrome.sidePanel || !chrome.sidePanel.setPanelBehavior) {
    return;
  }

  try {
    await chrome.sidePanel.setPanelBehavior({
      openPanelOnActionClick: true
    });
  } catch {
    // non-fatal
  }
}

function firstNonEmptyString(...values) {
  for (const value of values) {
    const v = normalizeString(value, 4096);
    if (v) return v;
  }
  return "";
}

function hashString(input) {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash +=
      (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16);
}

function normalizeCredentialRecord(record, requestedDomain) {
  if (!record || typeof record !== "object") return null;

  const domainCandidate = firstNonEmptyString(
    record.domain,
    record.site,
    record.hostname,
    record.url
  );

  const credentialDomain = getBaseDomain(domainCandidate || requestedDomain);
  if (!credentialDomain || credentialDomain !== requestedDomain) return null;

  const username = firstNonEmptyString(
    record.username,
    record.email,
    record.login,
    record.decrypted_username,
    record.decryptedUsername,
    record.autofill && record.autofill.username
  );

  const password = firstNonEmptyString(
    record.password,
    record.decrypted_password,
    record.decryptedPassword,
    record.autofill && record.autofill.password
  );

  if (!username || !password) return null;

  const rawId = firstNonEmptyString(record.id, record.credential_id, record.uuid);
  const id =
    rawId || `cred_${hashString(`${credentialDomain}|${username}|${password}`)}`;

  return {
    id,
    domain: credentialDomain,
    username,
    password
  };
}

function extractCredentialArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && typeof payload === "object") {
    if (Array.isArray(payload.credentials)) return payload.credentials;
    if (Array.isArray(payload.items)) return payload.items;
    if (payload.data && Array.isArray(payload.data.credentials)) {
      return payload.data.credentials;
    }
    if ("username" in payload || "password" in payload) return [payload];
  }
  return [];
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

function estimatePasswordStrength(password) {
  const value = normalizeString(password, 4096);
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

async function getAuthorizedToken(allowSync = false) {
  let token = await getToken();

  if (!token && allowSync) {
    const synced = await trySyncTokenFromAppTabs();
    if (synced.ok) {
      token = await getToken();
    }
  }

  if (!token) {
    return {
      ok: false,
      code: CODE.NO_TOKEN,
      message: "Please login to Cyber Hygiene."
    };
  }

  if (isJwtExpired(token)) {
    await clearToken();
    return {
      ok: false,
      code: CODE.UNAUTHORIZED,
      message: "Session expired. Please login again."
    };
  }

  return { ok: true, code: CODE.OK, token };
}

async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function fetchVaultCredentials(domain, token) {
  try {
    const endpoint = `${CONFIG.API_BASE_URL}/vault?domain=${encodeURIComponent(
      domain
    )}`;
    const response = await fetchWithTimeout(
      endpoint,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json"
        },
        cache: "no-store"
      },
      CONFIG.REQUEST_TIMEOUT_MS
    );

    if (response.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired."
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        code: CODE.API_ERROR,
        message: `Vault API error (${response.status}).`
      };
    }

    let payload;
    try {
      payload = await response.json();
    } catch {
      return {
        ok: false,
        code: CODE.INVALID_RESPONSE,
        message: "Invalid JSON response from vault API."
      };
    }

    const records = extractCredentialArray(payload);
    const credentials = records
      .map((record) => normalizeCredentialRecord(record, domain))
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
      message: "Network error while contacting backend."
    };
  }
}

async function fetchAllStoredCredentials(token) {
  try {
    const response = await fetchWithTimeout(
      `${CONFIG.API_BASE_URL}/credentials`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json"
        },
        cache: "no-store"
      },
      CONFIG.REQUEST_TIMEOUT_MS
    );

    if (response.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired."
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        code: CODE.API_ERROR,
        message: `Credentials API error (${response.status}).`
      };
    }

    let payload;
    try {
      payload = await response.json();
    } catch {
      return {
        ok: false,
        code: CODE.INVALID_RESPONSE,
        message: "Invalid JSON response from credentials API."
      };
    }

    if (!Array.isArray(payload)) {
      return {
        ok: false,
        code: CODE.INVALID_RESPONSE,
        message: "Invalid credentials response format."
      };
    }

    const credentials = payload
      .map((record) => {
        if (!record || typeof record !== "object") return null;

        const id = firstNonEmptyString(record.id, record.credential_id);
        const username = firstNonEmptyString(record.username, record.email);
        const domain = getBaseDomain(firstNonEmptyString(record.site, record.domain, record.url));

        if (!id || !username || !domain) return null;

        return {
          id,
          username,
          domain
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
      message: "Network error while contacting backend."
    };
  }
}

async function createStoredCredential(token, credential) {
  try {
    const response = await fetchWithTimeout(
      `${CONFIG.API_BASE_URL}/credentials`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify(credential),
        cache: "no-store"
      },
      CONFIG.REQUEST_TIMEOUT_MS
    );

    if (response.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired."
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        code: CODE.API_ERROR,
        message: `Credentials API error (${response.status}).`
      };
    }

    return {
      ok: true,
      code: CODE.OK
    };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while contacting backend."
    };
  }
}

async function updateStoredCredential(token, credId, credential) {
  const id = normalizeString(String(credId), 128);
  if (!id) {
    return {
      ok: false,
      code: CODE.INVALID_RESPONSE,
      message: "Invalid credential id."
    };
  }

  try {
    const response = await fetchWithTimeout(
      `${CONFIG.API_BASE_URL}/credentials/${encodeURIComponent(id)}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "application/json"
        },
        body: JSON.stringify(credential),
        cache: "no-store"
      },
      CONFIG.REQUEST_TIMEOUT_MS
    );

    if (response.status === 401) {
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Session expired."
      };
    }

    if (!response.ok) {
      return {
        ok: false,
        code: CODE.API_ERROR,
        message: `Credentials API error (${response.status}).`
      };
    }

    return {
      ok: true,
      code: CODE.OK
    };
  } catch {
    return {
      ok: false,
      code: CODE.NETWORK_ERROR,
      message: "Network error while contacting backend."
    };
  }
}

async function handleCaptureLoginCredential(message) {
  const username = normalizeString(message && message.username, 1024);
  const password = normalizeString(message && message.password, 4096);
  const domain = getBaseDomain(
    firstNonEmptyString(message && message.domain, message && message.site)
  );

  if (!domain || !username || !password) {
    return {
      ok: false,
      code: CODE.INVALID_RESPONSE,
      message: "Invalid captured login payload."
    };
  }

  const tokenState = await getAuthorizedToken(true);
  if (!tokenState.ok) return tokenState;

  const listResult = await fetchAllStoredCredentials(tokenState.token);
  if (!listResult.ok) {
    if (listResult.code === CODE.UNAUTHORIZED) {
      await clearToken();
    }
    return listResult;
  }

  const usernameLower = username.toLowerCase();
  const existing = listResult.credentials.find(
    (item) =>
      item.domain === domain &&
      normalizeString(item.username, 1024).toLowerCase() === usernameLower
  );

  const credentialPayload = {
    site: domain,
    username,
    password,
    strength: estimatePasswordStrength(password)
  };

  const saveResult = existing
    ? await updateStoredCredential(tokenState.token, existing.id, credentialPayload)
    : await createStoredCredential(tokenState.token, credentialPayload);

  if (!saveResult.ok) {
    if (saveResult.code === CODE.UNAUTHORIZED) {
      await clearToken();
    }
    return saveResult;
  }

  return {
    ok: true,
    code: CODE.OK,
    saved: true,
    action: existing ? "updated" : "created"
  };
}

function sendMessageToTab(tabId, message) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        reject(new Error(err.message));
        return;
      }
      resolve(response);
    });
  });
}

async function ensureContentScript(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["content.js"]
  });
}

async function autofillInTab(tabId, domain, credential) {
  const message = {
    type: "CYBERHYGIENE_AUTOFILL",
    payload: {
      domain,
      username: credential.username,
      password: credential.password
    }
  };

  try {
    const result = await sendMessageToTab(tabId, message);
    if (result && typeof result === "object") return result;
    return { ok: true, code: CODE.OK };
  } catch {
    try {
      await ensureContentScript(tabId);
      const result = await sendMessageToTab(tabId, message);
      if (result && typeof result === "object") return result;
      return { ok: true, code: CODE.OK };
    } catch {
      return {
        ok: false,
        code: CODE.INTERNAL_ERROR,
        message: "Unable to inject autofill content script."
      };
    }
  }
}

async function analyzePageRiskInTab(tabId) {
  const message = { type: "CYBERHYGIENE_ANALYZE_PAGE" };

  try {
    const result = await sendMessageToTab(tabId, message);
    if (result && typeof result === "object") return result;
  } catch {
    try {
      await ensureContentScript(tabId);
      const result = await sendMessageToTab(tabId, message);
      if (result && typeof result === "object") return result;
    } catch {
      return {
        ok: false,
        code: CODE.INTERNAL_ERROR,
        message: "Unable to analyze page risk."
      };
    }
  }

  return {
    ok: false,
    code: CODE.INVALID_RESPONSE,
    message: "Invalid phishing analysis response."
  };
}

async function handleGetPhishingRisk(message) {
  const context = await getContextForRequest(message);
  if (!context.ok) return context;

  const risk = await analyzePageRiskForContext(context);
  if (!risk.ok) return risk;

  return {
    ok: true,
    code: risk.blocked ? CODE.PHISHING_BLOCKED : risk.level === "medium" ? CODE.PHISHING_WARNING : CODE.OK,
    domain: context.domain,
    risk: {
      score: Number(risk.score) || 0,
      level: normalizeString(risk.level, 32) || "low",
      label: normalizeString(risk.label, 64) || "Safe",
      blocked: Boolean(risk.blocked),
      safe: Boolean(risk.safe),
      reasons: Array.isArray(risk.reasons) ? risk.reasons.slice(0, 4) : []
    }
  };
}

async function handleGetAuthStatus() {
  let token = await getToken();
  if (!token) {
    const synced = await trySyncTokenFromAppTabs();
    if (synced.ok) {
      token = await getToken();
    } else {
      return {
        ok: true,
        code: CODE.OK,
        authorized: false
      };
    }
  }

  if (isJwtExpired(token)) {
    await clearToken();
    return {
      ok: true,
      code: CODE.UNAUTHORIZED,
      authorized: false,
      expired: true
    };
  }

  return {
    ok: true,
    code: CODE.OK,
    authorized: true
  };
}

async function handleFetchVaultForActiveTab() {
  const token = await getToken();
  if (!token) {
    return {
      ok: false,
      code: CODE.NO_TOKEN,
      message: "Please login to Cyber Hygiene."
    };
  }

  if (isJwtExpired(token)) {
    await clearToken();
    return {
      ok: false,
      code: CODE.UNAUTHORIZED,
      message: "Session expired. Please login again."
    };
  }

  const context = await getContextForRequest({});
  if (!context.ok) return context;

  if (context.blocked) {
    return {
      ok: false,
      code: CODE.SITE_BLOCKED,
      domain: context.domain,
      message: "Autofill is disabled for this site."
    };
  }

  const risk = await analyzePageRiskForContext(context);
  if (risk.ok && risk.blocked) {
    return {
      ok: false,
      code: CODE.PHISHING_BLOCKED,
      domain: context.domain,
      message: "This login page looks like phishing. Autofill is blocked.",
      risk
    };
  }

  const activeToken = await getToken();
  const vault = await fetchVaultCredentials(context.domain, activeToken || token);
  if (!vault.ok) {
    if (vault.code === CODE.UNAUTHORIZED) {
      await clearToken();
    }
    return vault;
  }

  const metadata = vault.credentials.map((item) => ({
    id: item.id,
    label: maskUsername(item.username)
  }));

  return {
    ok: true,
    code: CODE.OK,
    domain: context.domain,
    credentials: metadata
  };
}

async function handlePerformAutofill(message) {
  const credentialId = normalizeString(message && message.credentialId, 512);
  if (!credentialId) {
    return {
      ok: false,
      code: CODE.CREDENTIAL_NOT_FOUND,
      message: "Credential not selected."
    };
  }

  const context = await getContextForRequest(message);
  if (!context.ok) return context;

  if (context.blocked) {
    return {
      ok: false,
      code: CODE.SITE_BLOCKED,
      message: "Autofill is disabled for this site."
    };
  }

  const risk = await analyzePageRiskForContext(context);
  if (!risk.ok) {
    return risk;
  }

  if (risk.blocked) {
    clearBiometricUnlock();
    return {
      ok: false,
      code: CODE.PHISHING_BLOCKED,
      message: "This page looks like phishing. Autofill has been blocked.",
      risk
    };
  }

  if (!hasValidBiometricUnlock(context)) {
    const biometric = await requestBiometricGateViaAppTab({
      tabId: context.tabId,
      domain: context.domain
    });
    if (!biometric.ok) {
      return biometric;
    }
  }

  if (!hasValidBiometricUnlock(context)) {
    return {
      ok: false,
      code: CODE.BIOMETRIC_FAILED,
      message: "Fingerprint verification required before autofill."
    };
  }

  const activeToken = await getToken();
  if (!activeToken) {
    clearBiometricUnlock();
    return {
      ok: false,
      code: CODE.NO_TOKEN,
      message: "Please login to Cyber Hygiene."
    };
  }

  if (isJwtExpired(activeToken)) {
    await clearToken();
    clearBiometricUnlock();
    return {
      ok: false,
      code: CODE.UNAUTHORIZED,
      message: "Session expired. Please login again."
    };
  }

  const vault = await fetchVaultCredentials(context.domain, activeToken);
  if (!vault.ok) {
    if (vault.code === CODE.UNAUTHORIZED) {
      await clearToken();
      clearBiometricUnlock();
    }
    return vault;
  }

  const selected = vault.credentials.find((c) => c.id === credentialId);
  if (!selected) {
    return {
      ok: false,
      code: CODE.CREDENTIAL_NOT_FOUND,
      message: "Selected credential is no longer available."
    };
  }

  if (selected.domain !== context.domain) {
    return {
      ok: false,
      code: CODE.PHISHING_BLOCKED,
      message: "Domain mismatch detected. Autofill blocked."
    };
  }

  const fillResult = await autofillInTab(context.tabId, context.domain, selected);
  if (fillResult && fillResult.ok) {
    clearBiometricUnlock();
  }
  return fillResult;
}

async function handleGrantBiometricUnlock(message) {
  const context = await getContextForRequest(message);
  if (!context.ok) return context;

  const token = normalizeString(message && message.token, 4096);
  if (token) {
    if (!looksLikeJwt(token) || isJwtExpired(token)) {
      clearBiometricUnlock();
      return {
        ok: false,
        code: CODE.UNAUTHORIZED,
        message: "Biometric session expired. Please verify again."
      };
    }
    await setToken(token);
  }

  setBiometricUnlock(context.tabId, context.domain);
  return {
    ok: true,
    code: CODE.OK,
    domain: context.domain,
    tabId: context.tabId
  };
}

async function handleMessage(message) {
  const type = message && message.type;

  switch (type) {
    case MESSAGE.GET_ACTIVE_CONTEXT: {
      return getActiveContext();
    }

    case MESSAGE.GET_PHISHING_RISK: {
      return handleGetPhishingRisk(message);
    }

    case MESSAGE.GET_AUTH_STATUS: {
      return handleGetAuthStatus();
    }

    case MESSAGE.OPEN_LOGIN: {
      await chrome.tabs.create({ url: CONFIG.LOGIN_URL });
      return { ok: true, code: CODE.OK };
    }

    case MESSAGE.SYNC_TOKEN_FROM_APP: {
      const synced = await trySyncTokenFromAppTabs();
      if (!synced.ok) {
        return synced;
      }
      return { ok: true, code: CODE.OK, authorized: true };
    }

    case MESSAGE.REQUEST_BIOMETRIC_GATE: {
      return requestBiometricGateViaAppTab(message);
    }

    case MESSAGE.GRANT_BIOMETRIC_UNLOCK: {
      return handleGrantBiometricUnlock(message);
    }

    case MESSAGE.FETCH_VAULT_FOR_ACTIVE_TAB: {
      return handleFetchVaultForActiveTab();
    }

    case MESSAGE.PERFORM_AUTOFILL: {
      return handlePerformAutofill(message);
    }

    case MESSAGE.CAPTURE_LOGIN_CREDENTIAL: {
      return handleCaptureLoginCredential(message);
    }
    case "SAVE_CREDENTIAL":
    case "ADD_CREDENTIAL":
    case "UPSERT_CREDENTIAL": {
      return handleCaptureLoginCredential(message);
    }

    case MESSAGE.SET_NEVER_AUTOFILL: {
      const enabled = Boolean(message && message.enabled);
      let domain = getBaseDomain(message && message.domain);

      if (!domain) {
        const context = await getActiveContext();
        if (!context.ok) return context;
        domain = context.domain;
      }

      const blocked = await setNeverAutofill(domain, enabled);
      return {
        ok: true,
        code: CODE.OK,
        domain,
        blocked
      };
    }

    case MESSAGE.GET_NEVER_AUTOFILL_STATUS: {
      let domain = getBaseDomain(message && message.domain);

      if (!domain) {
        const context = await getActiveContext();
        if (!context.ok) return context;
        domain = context.domain;
      }

      const blocked = await isNeverAutofill(domain);
      return {
        ok: true,
        code: CODE.OK,
        domain,
        blocked
      };
    }

    case MESSAGE.SET_TOKEN: {
      const token = normalizeString(message && message.token, 4096);
      if (!token) {
        return {
          ok: false,
          code: CODE.INVALID_RESPONSE,
          message: "Invalid token."
        };
      }
      await setToken(token);
      return { ok: true, code: CODE.OK };
    }

    case MESSAGE.CLEAR_TOKEN: {
      await clearToken();
      clearBiometricUnlock();
      return { ok: true, code: CODE.OK };
    }

    default:
      return {
        ok: false,
        code: CODE.INVALID_RESPONSE,
        message: "Unknown message type."
      };
  }
}

chrome.runtime.onInstalled.addListener(async () => {
  await initializeSidePanelBehavior();
  const data = await storageGet([CONFIG.NEVER_AUTOFILL_KEY]);
  if (!Array.isArray(data[CONFIG.NEVER_AUTOFILL_KEY])) {
    await storageSet({ [CONFIG.NEVER_AUTOFILL_KEY]: [] });
  }
});

chrome.runtime.onStartup.addListener(() => {
  initializeSidePanelBehavior();
});

initializeSidePanelBehavior();

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then(sendResponse)
    .catch(() => {
      sendResponse({
        ok: false,
        code: CODE.INTERNAL_ERROR,
        message: "Internal extension error."
      });
    });
  return true;
});
