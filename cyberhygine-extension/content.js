(() => {
  if (window.__CYBERHYGIENE_CONTENT_READY__) return;
  window.__CYBERHYGIENE_CONTENT_READY__ = true;

  const CAPTURE_DEBOUNCE_MS = 8000;
  let lastCaptureKey = "";
  let lastCaptureAt = 0;

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

  function normalizeString(value, maxLen = 4096) {
    if (typeof value !== "string") return "";
    const trimmed = value.trim();
    return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed;
  }

  function getBaseDomainFromHostname(hostnameInput) {
    let hostname = normalizeString(hostnameInput).toLowerCase();
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
    const last3 = parts.slice(-3).join(".");
    if (SECOND_LEVEL_SUFFIXES.has(last2) && parts.length >= 3) {
      return last3;
    }
    return last2;
  }

  function getCurrentBaseDomain() {
    try {
      return getBaseDomainFromHostname(window.location.hostname);
    } catch {
      return "";
    }
  }

  function isVisibleInput(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.disabled || el.readOnly) return false;

    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return false;
    if (style.opacity === "0") return false;
    if (el.offsetWidth === 0 && el.offsetHeight === 0) return false;
    return true;
  }

  function setInputValue(input, value) {
    const prototype = Object.getPrototypeOf(input);
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "value");

    if (descriptor && typeof descriptor.set === "function") {
      descriptor.set.call(input, value);
    } else {
      input.value = value;
    }

    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    input.dispatchEvent(new Event("blur", { bubbles: true }));
  }

  function findPasswordInput(root) {
    const candidates = Array.from(
      root.querySelectorAll('input[type="password"]')
    ).filter(isVisibleInput);

    if (candidates.length === 0) return null;

    const scored = candidates.map((el) => {
      const autocomplete = normalizeString(el.autocomplete).toLowerCase();
      let score = 0;
      if (autocomplete.includes("current-password")) score += 120;
      if (autocomplete.includes("password")) score += 80;
      if (autocomplete.includes("new-password")) score -= 80;
      if (el.form) score += 10;
      return { el, score };
    });

    scored.sort((a, b) => b.score - a.score);
    return scored[0].el;
  }

  function scoreUsernameInput(input, allInputs, passwordInput) {
    const type = normalizeString(input.type).toLowerCase();
    const name = normalizeString(input.name).toLowerCase();
    const id = normalizeString(input.id).toLowerCase();
    const auto = normalizeString(input.autocomplete).toLowerCase();
    const placeholder = normalizeString(input.placeholder).toLowerCase();

    let score = 0;
    if (type === "email") score += 140;
    if (type === "text" || type === "" || type === "search") score += 50;
    if (type === "tel" || type === "url") score += 20;

    if (auto.includes("username")) score += 130;
    if (auto.includes("email")) score += 120;

    if (/user|login|email|identifier|account/.test(name)) score += 100;
    if (/user|login|email|identifier|account/.test(id)) score += 90;
    if (/user|login|email/.test(placeholder)) score += 70;

    if (
      type === "password" ||
      type === "hidden" ||
      type === "checkbox" ||
      type === "radio" ||
      type === "submit" ||
      type === "button"
    ) {
      score -= 300;
    }

    const pIndex = allInputs.indexOf(passwordInput);
    const iIndex = allInputs.indexOf(input);
    if (pIndex >= 0 && iIndex >= 0) {
      const distance = Math.abs(pIndex - iIndex);
      score += Math.max(0, 60 - distance);
    }

    return score;
  }

  function findUsernameInput(passwordInput) {
    const scope = passwordInput.form || document;
    const allInputs = Array.from(scope.querySelectorAll("input")).filter(
      isVisibleInput
    );

    const candidates = allInputs
      .filter((el) => el !== passwordInput)
      .map((el) => ({
        el,
        score: scoreUsernameInput(el, allInputs, passwordInput)
      }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score);

    return candidates.length > 0 ? candidates[0].el : null;
  }

  function getHostnameTokens(hostname) {
    return normalizeString(hostname)
      .toLowerCase()
      .split(".")
      .filter(Boolean);
  }

  function getPageTextSample(maxLen = 5000) {
    const text = normalizeString(
      (document.body && document.body.innerText) || document.documentElement.innerText || "",
      maxLen
    );
    return text.toLowerCase();
  }

  function getBrandSignals() {
    const title = normalizeString(document.title, 256).toLowerCase();
    const headings = Array.from(document.querySelectorAll("h1, h2, h3, [role='heading']"))
      .map((el) => normalizeString(el.textContent, 120).toLowerCase())
      .filter(Boolean)
      .join(" ");
    const text = `${title} ${headings} ${getPageTextSample(2500)}`;

    return [
      { name: "facebook", tokens: ["facebook", "fb"], domains: ["facebook", "fb"] },
      { name: "google", tokens: ["google", "gmail"], domains: ["google", "gmail"] },
      { name: "microsoft", tokens: ["microsoft", "outlook", "office", "live"], domains: ["microsoft", "outlook", "office", "live"] },
      { name: "apple", tokens: ["apple", "icloud"], domains: ["apple", "icloud"] },
      { name: "amazon", tokens: ["amazon", "aws"], domains: ["amazon", "aws"] },
      { name: "paypal", tokens: ["paypal"], domains: ["paypal"] },
      { name: "instagram", tokens: ["instagram"], domains: ["instagram"] },
      { name: "linkedin", tokens: ["linkedin"], domains: ["linkedin"] },
      { name: "github", tokens: ["github"], domains: ["github"] },
      { name: "netflix", tokens: ["netflix"], domains: ["netflix"] },
      { name: "x", tokens: ["twitter", "x.com"], domains: ["twitter", "x"] },
      { name: "dropbox", tokens: ["dropbox"], domains: ["dropbox"] }
    ].filter((brand) => brand.tokens.some((token) => text.includes(token)));
  }

  function analyzePageForPhishing() {
    const hostname = normalizeString(window.location.hostname, 512).toLowerCase();
    const protocol = normalizeString(window.location.protocol, 32).toLowerCase();
    const baseDomain = getCurrentBaseDomain();
    const hostnameTokens = getHostnameTokens(hostname);
    const title = normalizeString(document.title, 256);
    const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')).filter(isVisibleInput);
    const allForms = Array.from(document.forms || []);
    const visibleIframes = Array.from(document.querySelectorAll("iframe")).filter((frame) => {
      const style = window.getComputedStyle(frame);
      return style.display !== "none" && style.visibility !== "hidden";
    });

    let score = 0;
    const reasons = [];

    if (protocol === "http:" && baseDomain !== "localhost" && !/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 35;
      reasons.push("This page is not using HTTPS, which is unusual for a real login page.");
    }

    if (hostname.startsWith("xn--")) {
      score += 35;
      reasons.push("The domain uses punycode characters, which can be used for lookalike phishing domains.");
    }

    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      score += 12;
      reasons.push("The domain contains many hyphens, which is common on fake login domains.");
    }

    if (hostnameTokens.length >= 4) {
      score += 10;
      reasons.push("The site uses an unusually deep subdomain structure.");
    }

    if (hostname.length >= 35) {
      score += 8;
      reasons.push("The hostname is unusually long for a login page.");
    }

    const suspiciousKeywords = ["verify", "secure", "account", "wallet", "billing", "support", "unlock", "recovery"];
    const keywordMatches = suspiciousKeywords.filter((word) => hostname.includes(word));
    if (keywordMatches.length >= 2) {
      score += 14;
      reasons.push("The domain mixes urgency or account-related keywords often seen in phishing URLs.");
    }

    const urgentPhrases = ["verify your account", "confirm your identity", "suspended", "unusual activity", "act now", "limited time"];
    const pageText = getPageTextSample();
    const urgentMatches = urgentPhrases.filter((phrase) => pageText.includes(phrase));
    if (urgentMatches.length > 0) {
      score += 12;
      reasons.push("The page uses urgency language that is common in phishing lures.");
    }

    const externalForms = allForms.filter((form) => {
      const action = normalizeString(form.getAttribute("action"), 2048);
      if (!action) return false;
      try {
        const actionUrl = new URL(action, window.location.href);
        const actionDomain = getBaseDomainFromHostname(actionUrl.hostname);
        return actionDomain && actionDomain !== baseDomain;
      } catch {
        return false;
      }
    });
    if (externalForms.length > 0) {
      score += 24;
      reasons.push("The login form submits to a different domain than the page you are viewing.");
    }

    if (visibleIframes.length >= 3 && passwordInputs.length > 0) {
      score += 10;
      reasons.push("This login page uses several visible iframes, which can hide deceptive forms.");
    }

    const detectedBrands = getBrandSignals();
    const matchedBrands = detectedBrands.filter((brand) =>
      brand.domains.some((token) => hostname.includes(token))
    );
    const mismatchedBrands = detectedBrands.filter((brand) =>
      !brand.domains.some((token) => hostname.includes(token))
    );

    // If the page text references several brands but one of them clearly matches
    // the current domain, treat that as a legitimate brand match instead of phishing.
    if (matchedBrands.length === 0 && mismatchedBrands.length > 0) {
      score += 40;
      reasons.push(`The page looks like ${mismatchedBrands[0].name}, but the domain does not match that brand.`);
    }

    const hasLoginUi = passwordInputs.length > 0;
    const level = score >= 60 ? "high" : score >= 30 ? "medium" : "low";

    return {
      ok: true,
      code: "OK",
      domain: baseDomain,
      hostname,
      hasLoginUi,
      score,
      level,
      safe: level === "low",
      blocked: level === "high",
      label: level === "high" ? "Likely phishing" : level === "medium" ? "Suspicious" : "Safe",
      reasons: reasons.slice(0, 4)
    };
  }

  function isHttpPage() {
    return window.location.protocol === "http:" || window.location.protocol === "https:";
  }

  function isLikelyNewPasswordField(input) {
    const auto = normalizeString(input.autocomplete).toLowerCase();
    const name = normalizeString(input.name).toLowerCase();
    const id = normalizeString(input.id).toLowerCase();
    const placeholder = normalizeString(input.placeholder).toLowerCase();
    const hint = `${auto} ${name} ${id} ${placeholder}`;
    return /new-password|confirm|repeat|otp|one.?time|verification|reset|create|signup|register/.test(
      hint
    );
  }

  function extractSubmittedLoginCredential(form) {
    const scope = form instanceof HTMLFormElement ? form : document;
    const passwordInput = findPasswordInput(scope);
    if (!passwordInput) return null;

    if (isLikelyNewPasswordField(passwordInput)) return null;

    const allPasswordInputs = Array.from(
      scope.querySelectorAll('input[type="password"]')
    ).filter(isVisibleInput);
    if (allPasswordInputs.length > 1 && allPasswordInputs.some(isLikelyNewPasswordField)) {
      return null;
    }

    const usernameInput = findUsernameInput(passwordInput);
    const username = normalizeString(usernameInput && usernameInput.value, 1024);
    const password = normalizeString(passwordInput.value, 4096);

    if (!username || !password) return null;

    return {
      username,
      password
    };
  }

  function shouldSkipRecentCapture(domain, username, password) {
    const key = `${domain}|${username}|${password}`;
    const now = Date.now();
    if (lastCaptureKey === key && now - lastCaptureAt < CAPTURE_DEBOUNCE_MS) {
      return true;
    }
    lastCaptureKey = key;
    lastCaptureAt = now;
    return false;
  }

  function sendCapturedCredential(payload) {
    try {
      chrome.runtime.sendMessage(
        {
          type: "CAPTURE_LOGIN_CREDENTIAL",
          domain: payload.domain,
          site: payload.site,
          username: payload.username,
          password: payload.password
        },
        () => {
          void chrome.runtime.lastError;
        }
      );
    } catch {
      // no-op
    }
  }

  function onFormSubmit(event) {
    if (!isHttpPage()) return;
    if (isTrustedAppOrigin()) return;

    const form = event.target instanceof HTMLFormElement ? event.target : null;
    if (!form) return;

    const credential = extractSubmittedLoginCredential(form);
    if (!credential) return;

    const domain = getCurrentBaseDomain();
    if (!domain) return;

    if (shouldSkipRecentCapture(domain, credential.username, credential.password)) {
      return;
    }

    sendCapturedCredential({
      domain,
      site: window.location.hostname || domain,
      username: credential.username,
      password: credential.password
    });
  }

  function isTrustedAppOrigin() {
    try {
      const protocol = window.location.protocol.toLowerCase();
      const hostname = window.location.hostname.toLowerCase();
      const port = window.location.port || (protocol === "https:" ? "443" : protocol === "http:" ? "80" : "");

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

  function readAppTokenFromLocalStorage() {
    if (!isTrustedAppOrigin()) {
      return { ok: false, code: "FORBIDDEN_ORIGIN", message: "Not a trusted app origin." };
    }

    try {
      const token = normalizeString(window.localStorage.getItem("token") || "", 4096);
      if (!token) {
        return { ok: false, code: "TOKEN_NOT_FOUND", message: "No login token found in app." };
      }
      return { ok: true, code: "OK", token };
    } catch {
      return { ok: false, code: "TOKEN_READ_ERROR", message: "Could not read app token." };
    }
  }

  let lastSyncedAppToken = "";

  function syncAppTokenToExtension(force = false) {
    if (!isTrustedAppOrigin()) return;

    let token = "";
    try {
      token = normalizeString(window.localStorage.getItem("token") || "", 4096);
    } catch {
      token = "";
    }

    if (!force && token === lastSyncedAppToken) {
      return;
    }

    lastSyncedAppToken = token;
    const message = token
      ? { type: "SET_TOKEN", token }
      : { type: "CLEAR_TOKEN" };

    try {
      chrome.runtime.sendMessage(message, () => {
        void chrome.runtime.lastError;
      });
    } catch {
      // non-fatal
    }
  }

  function base64UrlToArrayBuffer(base64url) {
    const value = normalizeString(base64url, 8192).replace(/-/g, "+").replace(/_/g, "/");
    const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
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
    return {
      ...optionsJSON,
      challenge: base64UrlToArrayBuffer(optionsJSON.challenge),
      allowCredentials: (optionsJSON.allowCredentials || []).map((cred) => ({
        ...cred,
        id: base64UrlToArrayBuffer(cred.id)
      }))
    };
  }

  function serializeAuthenticationCredential(credential) {
    const response = credential.response;
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

  async function performBiometricGate() {
    if (!isTrustedAppOrigin()) {
      return { ok: false, code: "FORBIDDEN_ORIGIN", message: "Biometric check is allowed only on Cyber Hygiene app." };
    }

    if (!window.PublicKeyCredential || !navigator.credentials) {
      return { ok: false, code: "WEBAUTHN_UNSUPPORTED", message: "This browser does not support biometric verification." };
    }

    const authEndpoints = [
      {
        options: "http://localhost:9000/api/fingerprints/login/options",
        verify: "http://localhost:9000/api/fingerprints/login/verify"
      },
      {
        options: "http://localhost:9000/api/passkeys/login/options",
        verify: "http://localhost:9000/api/passkeys/login/verify"
      }
    ];

    let lastError = "Biometric verification failed.";

    for (const endpoint of authEndpoints) {
      try {
        const optionsRes = await fetch(endpoint.options, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store"
        });

        if (!optionsRes.ok) {
          if (optionsRes.status === 404) {
            continue;
          }
          lastError = "Could not start biometric verification.";
          continue;
        }

        const optionsData = await optionsRes.json();
        const requestOptions = toRequestOptions(optionsData.options || {});
        requestOptions.userVerification = "required";

        if (navigator.credentials && typeof navigator.credentials.preventSilentAccess === "function") {
          try {
            await navigator.credentials.preventSilentAccess();
          } catch {
            // no-op
          }
        }

        const credential = await navigator.credentials.get({
          publicKey: requestOptions,
          mediation: "required"
        });

        if (!credential) {
          return { ok: false, code: "BIOMETRIC_CANCELLED", message: "Biometric verification cancelled." };
        }

        const verifyRes = await fetch(endpoint.verify, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store",
          body: JSON.stringify({
            attempt_id: optionsData.attempt_id,
            credential: serializeAuthenticationCredential(credential)
          })
        });

        if (!verifyRes.ok) {
          if (verifyRes.status === 404) {
            continue;
          }

          let detail = "Biometric verification failed.";
          try {
            const err = await verifyRes.json();
            if (err && typeof err.detail === "string" && err.detail.trim()) {
              detail = err.detail.trim();
            }
          } catch {
            // no-op
          }
          return { ok: false, code: "VERIFY_FAILED", message: detail };
        }

        const verifyData = await verifyRes.json();
        if (!verifyData || !verifyData.success) {
          lastError = "Biometric verification failed.";
          continue;
        }

        const token = normalizeString(verifyData.token || "", 4096);
        return { ok: true, code: "OK", token };
      } catch {
        lastError = "Biometric verification failed.";
      }
    }

    return { ok: false, code: "BIOMETRIC_ERROR", message: lastError };
  }

  function autofill(payload) {
    const domain = normalizeString(payload && payload.domain, 512);
    const username = normalizeString(payload && payload.username, 2048);
    const password = normalizeString(payload && payload.password, 2048);

    if (!domain || !username || !password) {
      return {
        ok: false,
        code: "INVALID_PAYLOAD",
        message: "Invalid autofill payload."
      };
    }

    const currentDomain = getCurrentBaseDomain();
    if (!currentDomain || currentDomain !== domain) {
      return {
        ok: false,
        code: "DOMAIN_MISMATCH",
        message: "Domain mismatch. Autofill blocked."
      };
    }

    const passwordInput = findPasswordInput(document);
    if (!passwordInput) {
      return {
        ok: false,
        code: "NO_PASSWORD_FIELD",
        message: "Password field not found."
      };
    }

    const usernameInput = findUsernameInput(passwordInput);

    if (usernameInput) {
      setInputValue(usernameInput, username);
    }

    setInputValue(passwordInput, password);
    passwordInput.focus();

    if (!usernameInput) {
      return {
        ok: true,
        code: "PASSWORD_ONLY_FILLED",
        message: "Password filled. Username/email field not found."
      };
    }

    return {
      ok: true,
      code: "AUTOFILL_SUCCESS",
      message: "Credentials autofilled successfully."
    };
  }

  document.addEventListener("submit", onFormSubmit, true);

  if (isTrustedAppOrigin()) {
    syncAppTokenToExtension(true);
    window.setInterval(() => syncAppTokenToExtension(false), 2000);
    window.addEventListener("focus", () => syncAppTokenToExtension(false));
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        syncAppTokenToExtension(false);
      }
    });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || !message.type) return;

    if (message.type === "CYBERHYGIENE_READ_APP_TOKEN") {
      sendResponse(readAppTokenFromLocalStorage());
      return true;
    }

    if (message.type === "CYBERHYGIENE_BIOMETRIC_GATE") {
      performBiometricGate().then(sendResponse).catch(() => {
        sendResponse({ ok: false, code: "BIOMETRIC_ERROR", message: "Biometric verification failed." });
      });
      return true;
    }

    if (message.type === "CYBERHYGIENE_ANALYZE_PAGE") {
      try {
        sendResponse(analyzePageForPhishing());
      } catch {
        sendResponse({
          ok: false,
          code: "PHISHING_ANALYSIS_ERROR",
          message: "Could not analyze this page."
        });
      }
      return true;
    }

    if (message.type !== "CYBERHYGIENE_AUTOFILL") return;

    try {
      const result = autofill(message.payload);
      sendResponse(result);
    } catch {
      sendResponse({
        ok: false,
        code: "AUTOFILL_ERROR",
        message: "Failed to autofill this page."
      });
    }

    return true;
  });
})();
