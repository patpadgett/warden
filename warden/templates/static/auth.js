/* Login and first-run setup ceremonies. */
(() => {
  "use strict";
  const W = window.Warden;
  const page = document.body.dataset.page;
  const errorBox = W.$("#auth-error");
  const warningBox = W.$("#auth-warning");

  const showSupport = () => {
    const message = W.passkeySupportMessage();
    if (!message) return true;
    W.showError(warningBox, message);
    return false;
  };

  const fail = (error) => {
    W.showError(errorBox, error?.message || "Something went wrong. Please try again.");
  };

  if (page === "login") {
    const button = W.$("#passkey-login");
    const username = W.$("#login-username");
    const next = document.body.dataset.next || "/";

    if (!showSupport()) {
      button.disabled = true;
      button.title = W.passkeySupportMessage();
    }

    const signIn = async () => {
      W.hide(errorBox);
      W.setBusy(button, true, "Waiting for your passkey…");
      try {
        const result = await W.beginLogin({
          username: username?.value?.trim() || null,
          next,
        });
        window.location.assign(result.redirect || "/");
      } catch (error) {
        fail(error);
        W.setBusy(button, false);
      }
    };

    button.addEventListener("click", signIn);
    username?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        signIn();
      }
    });
  }

  if (page === "setup") {
    const form = W.$("#setup-form");
    const button = W.$("#setup-submit");
    const username = W.$("#setup-username");
    const displayName = W.$("#setup-display-name");
    const code = W.$("#setup-code");
    const next = document.body.dataset.next || "/";

    if (!showSupport()) {
      button.disabled = true;
      button.title = W.passkeySupportMessage();
    }

    code?.addEventListener("input", () => {
      const raw = code.value.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 12);
      code.value = raw.replace(/(.{4})/g, "$1-").replace(/-$/, "");
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      W.hide(errorBox);
      if (!form.reportValidity()) return;
      if (!W.passkeysSupported()) {
        showSupport();
        return;
      }
      W.setBusy(button, true, "Creating your passkey…");
      try {
        const result = await W.registerPasskey({
          mode: "setup",
          username: username.value.trim(),
          displayName: displayName.value.trim(),
          setupCode: code.value.trim(),
          next,
        });
        window.location.assign(result.redirect || "/");
      } catch (error) {
        fail(error);
        W.setBusy(button, false);
      }
    });
  }
})();
