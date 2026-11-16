/* First-login invite registration page. */
(() => {
  "use strict";

  const form = document.getElementById("invite-form");
  if (!form) {
    return;
  }

  const token = form.dataset.token || "";
  const tokenInput = document.getElementById("invite-token");
  const nameInput = document.getElementById("passkey-name");
  const errorBox = document.getElementById("invite-error");
  const registerBtn = document.getElementById("register-btn");
  const copyBtn = document.getElementById("copy-btn");

  if (token) {
    tokenInput.value = token;
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const text = tokenInput.value.trim();
      if (text && window.Warden && window.Warden.copy) {
        window.Warden.copy(text);
      }
    });
  }

  const showError = (message) => {
    errorBox.querySelector(".panel-body").textContent = message;
    errorBox.hidden = false;
    registerBtn.disabled = false;
    registerBtn.querySelector("span:first-child").textContent = "Register passkey";
  };

  const postJSON = async (url, payload) => {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify(payload),
    });
    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }
    if (!response.ok) {
      throw new Error(data.detail || "Registration failed.");
    }
    return data;
  };

  const startRegistration = async (inviteToken, name) => {
    const W = window.Warden;
    if (!W || !W.prepareCreationOptions || !W.serializeRegistration) {
      showError("Warden's client helpers did not load. Reload the page and try again.");
      return;
    }
    if (!W.passkeysSupported()) {
      showError(W.passkeySupportMessage());
      return;
    }

    registerBtn.disabled = true;
    registerBtn.querySelector("span:first-child").textContent = "Setting up…";

    try {
      const data = await postJSON("/_warden/auth/invite/begin", {
        token: inviteToken,
        name,
      });
      let cred;
      try {
        cred = await navigator.credentials.create({
          publicKey: W.prepareCreationOptions(data.publicKey),
        });
      } catch (err) {
        throw new Error(W.friendlyPasskeyError(err));
      }
      const credential = W.serializeRegistration(cred);
      credential.invite_token = inviteToken;
      const result = await postJSON("/_warden/auth/invite/complete", {
        token: inviteToken,
        credential,
      });
      window.location.href = result.redirect || "/";
    } catch (err) {
      showError(err.message || "Registration failed.");
    }
  };

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    errorBox.hidden = true;
    const tokenValue = tokenInput.value.trim();
    const nameValue = nameInput.value.trim();
    if (!tokenValue) {
      showError("Please enter your invite token.");
      tokenInput.focus();
      return;
    }
    if (!nameValue) {
      showError("Please give this passkey a name.");
      nameInput.focus();
      return;
    }
    startRegistration(tokenValue, nameValue);
  });
})();
