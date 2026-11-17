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

    const otpStep = W.$("#otp-step");
    const otpCode = W.$("#otp-login-code");
    const otpSubmit = W.$("#otp-login-submit");
    let otpChallenge = null;

    const finish = (result) => window.location.assign(result.redirect || "/");

    const signIn = async () => {
      W.hide(errorBox);
      W.setBusy(button, true, "Waiting for your passkey…");
      try {
        const result = await W.beginLogin({
          username: username?.value?.trim() || null,
          next,
        });
        if (result && result.otp_required) {
          otpChallenge = result.login_challenge || result.challenge;
          if (otpStep) otpStep.hidden = false;
          W.setBusy(button, false);
          otpCode?.focus();
          return;
        }
        finish(result);
      } catch (error) {
        fail(error);
        W.setBusy(button, false);
      }
    };

    const submitOtp = async () => {
      if (!otpChallenge) return;
      W.hide(errorBox);
      W.setBusy(otpSubmit, true, "Checking…");
      try {
        finish(await W.completeLoginOtp(otpChallenge, otpCode?.value || ""));
      } catch (error) {
        fail(error);
        W.setBusy(otpSubmit, false);
        otpCode?.select();
      }
    };

    otpSubmit?.addEventListener("click", submitOtp);
    otpCode?.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        submitOtp();
      }
    });

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
