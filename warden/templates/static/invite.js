/* First-login invite registration page. */
(() => {
  "use strict";

  const form = document.getElementById("invite-form");
  if (!form) {
    return;
  }

  const token = form.dataset.token || "";
  const display = form.dataset.tokenDisplay || "";
  const tokenInput = document.getElementById("invite-token");
  const nameInput = document.getElementById("passkey-name");
  const tokenDisplay = document.getElementById("invite-token-display");
  const errorBox = document.getElementById("invite-error");
  const registerBtn = document.getElementById("register-btn");
  const copyBtn = document.getElementById("copy-btn");

  if (display) {
    tokenDisplay.value = display;
  }
  if (token) {
    tokenInput.value = token;
    tokenDisplay.value = token;
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const text = tokenDisplay.value.trim();
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
    registerBtn.disabled = true;
    registerBtn.querySelector("span:first-child").textContent = "Setting up…";

    try {
      const data = await postJSON("/_warden/auth/invite/begin", {
        token: inviteToken,
        name,
      });
      const cred = await navigator.credentials.create({ publicKey: data.publicKey });
      const credential = {
        id: cred.id,
        type: cred.type,
        rawId: cred.rawId,
        response: {
          clientDataJSON: cred.response.clientDataJSON,
          attestationObject: cred.response.attestationObject,
          transports: cred.response.transports,
          authenticatorData: cred.response.authenticatorData,
          signature: cred.response.signature,
          userHandle: cred.response.userHandle,
          publicKeyAlgorithm: cred.response.publicKeyAlgorithm,
          publicKey: cred.response.publicKey,
        },
        getClientExtensionResults: () => cred.getClientExtensionResults(),
        invite_token: inviteToken,
      };
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
