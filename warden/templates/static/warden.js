/* Warden shared UI + WebAuthn helpers. No dependencies, no tracking. */
(() => {
  "use strict";

  const W = (window.Warden = window.Warden || {});

  W.$ = (selector, root = document) => root.querySelector(selector);
  W.$$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  class WardenError extends Error {
    constructor(message, status = 0, data = null) {
      super(message);
      this.name = "WardenError";
      this.status = status;
      this.data = data;
    }
  }
  W.WardenError = WardenError;

  W.fetchJSON = async (url, options = {}) => {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    let body = options.body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== "string") {
      headers.set("Content-Type", "application/json");
      body = JSON.stringify(body);
    }
    if ((options.method || "GET").toUpperCase() !== "GET") {
      headers.set("X-Warden-Request", "1");
    }
    const response = await fetch(url, {
      credentials: "same-origin",
      cache: "no-store",
      ...options,
      headers,
      body,
    });
    let data = null;
    const text = await response.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = { detail: text };
      }
    }
    if (!response.ok) {
      let message = "Something went wrong.";
      if (data) {
        if (typeof data.detail === "string") message = data.detail;
        else if (Array.isArray(data.detail) && data.detail[0]?.msg) message = data.detail[0].msg;
        else if (data.detail?.message) message = data.detail.message;
        else if (data.message) message = data.message;
      }
      throw new WardenError(message, response.status, data);
    }
    return data;
  };

  W.toast = (message, { title = "", type = "ok", timeout = 4200 } = {}) => {
    const root = W.$("#toast-root");
    if (!root) return;
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const mark = document.createElement("span");
    mark.className = "toast-mark";
    const body = document.createElement("div");
    if (title) {
      const heading = document.createElement("strong");
      heading.textContent = title;
      body.appendChild(heading);
    }
    const copy = document.createElement("p");
    copy.textContent = message;
    body.appendChild(copy);
    toast.append(mark, body);
    root.appendChild(toast);
    const dismiss = () => {
      if (!toast.isConnected) return;
      toast.classList.add("is-leaving");
      window.setTimeout(() => toast.remove(), 180);
    };
    window.setTimeout(dismiss, timeout);
    toast.addEventListener("click", dismiss);
  };

  W.showError = (element, message) => {
    if (!element) return;
    element.textContent = message;
    element.hidden = false;
  };

  W.hide = (element) => {
    if (element) element.hidden = true;
  };

  W.setBusy = (button, busy, busyLabel = null) => {
    if (!button) return;
    if (!button.dataset.originalLabel) {
      const label = button.querySelector("span:not(.btn-spinner)");
      button.dataset.originalLabel = label ? label.textContent : button.textContent.trim();
      button.dataset.labelTarget = label ? "span" : "self";
    }
    button.classList.toggle("is-busy", Boolean(busy));
    button.disabled = Boolean(busy);
    if (busyLabel) {
      const label = button.dataset.labelTarget === "span"
        ? button.querySelector("span:not(.btn-spinner)")
        : button;
      if (label) label.textContent = busyLabel;
    } else if (!busy) {
      const label = button.dataset.labelTarget === "span"
        ? button.querySelector("span:not(.btn-spinner)")
        : button;
      if (label) label.textContent = button.dataset.originalLabel;
    }
  };

  W.formatRelative = (timestamp) => {
    if (!timestamp) return "never";
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - Number(timestamp)));
    if (seconds < 10) return "just now";
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)}d ago`;
    return new Date(Number(timestamp) * 1000).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  };

  W.refreshTimes = (root = document) => {
    W.$$("time[data-ts]", root).forEach((node) => {
      node.textContent = W.formatRelative(node.dataset.ts);
    });
  };

  W.copy = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      W.toast("Copied to clipboard.");
      return true;
    } catch {
      W.toast("Couldn't access the clipboard. Select and copy manually.", { type: "error" });
      return false;
    }
  };

  W.download = (filename, text, type = "text/plain") => {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1500);
  };

  W.confirm = (message, { confirmLabel = "Continue", danger = true } = {}) =>
    window.confirm(`${message}\n\n${confirmLabel}`) && (!danger || true);

  // ---------------------------------------------------------------- base64url
  W.b64urlToBuffer = (value) => {
    const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  };

  W.bufferToB64url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  };

  // ------------------------------------------------------------------ WebAuthn
  W.passkeysSupported = () =>
    Boolean(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);

  W.passkeySupportMessage = () => {
    if (!window.isSecureContext) {
      return "Passkeys need HTTPS (or localhost). Open this address over a secure connection.";
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      return "This browser doesn't support passkeys. Try a recent Safari, Chrome, Edge, or Firefox.";
    }
    return "";
  };

  W.prepareCreationOptions = (options) => {
    const publicKey = { ...options };
    publicKey.challenge = W.b64urlToBuffer(options.challenge);
    publicKey.user = { ...options.user, id: W.b64urlToBuffer(options.user.id) };
    if (options.excludeCredentials) {
      publicKey.excludeCredentials = options.excludeCredentials.map((credential) => ({
        ...credential,
        id: W.b64urlToBuffer(credential.id),
      }));
    }
    return publicKey;
  };

  W.prepareRequestOptions = (options) => {
    const publicKey = { ...options };
    publicKey.challenge = W.b64urlToBuffer(options.challenge);
    if (options.allowCredentials) {
      publicKey.allowCredentials = options.allowCredentials.map((credential) => ({
        ...credential,
        id: W.b64urlToBuffer(credential.id),
      }));
    }
    return publicKey;
  };

  W.serializeRegistration = (credential) => ({
    id: credential.id,
    rawId: W.bufferToB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
    response: {
      clientDataJSON: W.bufferToB64url(credential.response.clientDataJSON),
      attestationObject: W.bufferToB64url(credential.response.attestationObject),
      transports: credential.response.getTransports ? credential.response.getTransports() : [],
    },
  });

  W.serializeAssertion = (credential) => ({
    id: credential.id,
    rawId: W.bufferToB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || undefined,
    clientExtensionResults: credential.getClientExtensionResults
      ? credential.getClientExtensionResults()
      : {},
    response: {
      clientDataJSON: W.bufferToB64url(credential.response.clientDataJSON),
      authenticatorData: W.bufferToB64url(credential.response.authenticatorData),
      signature: W.bufferToB64url(credential.response.signature),
      userHandle: credential.response.userHandle
        ? W.bufferToB64url(credential.response.userHandle)
        : null,
    },
  });

  W.friendlyPasskeyError = (error) => {
    if (!error) return "The passkey request failed.";
    if (error.name === "NotAllowedError") {
      return "The passkey prompt was dismissed or timed out. Try again.";
    }
    if (error.name === "SecurityError") {
      return "This domain isn't allowed to use passkeys. Check the WebAuthn RP ID configuration.";
    }
    if (error.name === "InvalidStateError") {
      return "This passkey is already registered with Warden.";
    }
    if (error.name === "AbortError") {
      return "The passkey request was cancelled.";
    }
    return error.message || "The passkey request failed.";
  };

  W.beginLogin = async ({ username = null, next = "/" } = {}) => {
    if (!W.passkeysSupported()) throw new WardenError(W.passkeySupportMessage());
    let begin;
    try {
      begin = await W.fetchJSON("/_warden/auth/login/begin", {
        method: "POST",
        body: { username: username || null, next: next || "/" },
      });
    } catch (error) {
      if (error.status === 404) {
        throw new WardenError("No passkey found for that username. Leave it blank to use a discoverable passkey.");
      }
      throw error;
    }
    let credential;
    try {
      credential = await navigator.credentials.get({
        publicKey: W.prepareRequestOptions(begin.publicKey),
      });
    } catch (error) {
      throw new WardenError(W.friendlyPasskeyError(error));
    }
    return W.fetchJSON("/_warden/auth/login/complete", {
      method: "POST",
      body: { credential: W.serializeAssertion(credential) },
    });
  };

  W.registerPasskey = async ({ mode = "add", name = "", username = "", displayName = "", setupCode = "", next = "/" } = {}) => {
    if (!W.passkeysSupported()) throw new WardenError(W.passkeySupportMessage());
    const beginBody = mode === "setup"
      ? { username, display_name: displayName, setup_code: setupCode, next }
      : { name };
    const begin = await W.fetchJSON(
      mode === "setup" ? "/_warden/auth/setup/begin" : "/_warden/auth/register/begin",
      { method: "POST", body: beginBody },
    );
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: W.prepareCreationOptions(begin.publicKey),
      });
    } catch (error) {
      throw new WardenError(W.friendlyPasskeyError(error));
    }
    return W.fetchJSON(
      mode === "setup" ? "/_warden/auth/setup/complete" : "/_warden/auth/register/complete",
      { method: "POST", body: { credential: W.serializeRegistration(credential) } },
    );
  };

  // ------------------------------------------------------------------ modals
  W.openModal = (dialog) => {
    if (!dialog) return;
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
    const focusable = dialog.querySelector("input:not([type=hidden]), button, select, textarea");
    if (focusable) window.setTimeout(() => focusable.focus(), 30);
  };

  W.closeModal = (dialog) => {
    if (!dialog) return;
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  };

  W.openOverlay = (overlay) => {
    if (!overlay) return;
    overlay._trigger = document.activeElement;
    overlay.hidden = false;
    overlay.classList.add("open");
    const focusable = overlay.querySelector("input:not([type=hidden]), button, select, textarea");
    if (focusable) window.setTimeout(() => focusable.focus(), 30);
  };

  W.closeOverlay = (overlay) => {
    if (!overlay) return;
    overlay.classList.remove("open");
    const trigger = overlay._trigger;
    window.setTimeout(() => {
      overlay.hidden = true;
      if (trigger && typeof trigger.focus === "function") trigger.focus();
    }, 180);
  };

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const openOverlay = document.querySelector(".modal-overlay.open:not([hidden])");
    if (openOverlay) { W.closeOverlay(openOverlay); return; }
    const openDialog = document.querySelector("dialog.modal[open]");
    if (openDialog) W.closeModal(openDialog);
  });

  W.wireModalDismiss = () => {
    W.$$("dialog.modal").forEach((dialog) => {
      dialog.addEventListener("click", (event) => {
        if (event.target === dialog) W.closeModal(dialog);
      });
      W.$$("[data-close-modal]", dialog).forEach((button) => {
        button.addEventListener("click", () => W.closeModal(dialog));
      });
    });

    W.$$(".modal-overlay").forEach((overlay) => {
      overlay.addEventListener("click", (event) => {
        if (event.target === overlay) W.closeOverlay(overlay);
      });
      W.$$("[data-close-modal]", overlay).forEach((button) => {
        button.addEventListener("click", () => W.closeOverlay(overlay));
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    W.refreshTimes();
    W.wireModalDismiss();
    const logout = W.$("#logout-button");
    if (logout) {
      logout.addEventListener("click", async () => {
        try {
          const result = await W.fetchJSON("/_warden/auth/logout", { method: "POST", body: {} });
          window.location.assign(result.redirect || "/_warden/login");
        } catch {
          window.location.assign("/_warden/login");
        }
      });
    }
  });
})();
