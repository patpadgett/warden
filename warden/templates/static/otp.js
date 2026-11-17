(() => {
  "use strict";
  const setupBtn = document.getElementById("otp-setup");
  const verifyBtn = document.getElementById("otp-verify");
  const disableBtn = document.getElementById("otp-disable");
  const codeInput = document.getElementById("otp-code");
  const statusEl = document.getElementById("otp-status");
  const secretBox = document.getElementById("otp-secret");
  const secretText = document.getElementById("otp-secret-text");
  const urlText = document.getElementById("otp-url");
  const messageEl = document.getElementById("otp-message");

  const show = (el) => { if (el) el.hidden = false; };
  const hide = (el) => { if (el) el.hidden = true; };
  const msg = (text, kind) => {
    if (!messageEl) return;
    messageEl.textContent = text;
    messageEl.className = kind === "error" ? "otp-message otp-error" : "otp-message otp-ok";
    show(messageEl);
  };

  if (setupBtn) {
    setupBtn.addEventListener("click", async () => {
      setupBtn.disabled = true;
      try {
        const data = await window.Warden.fetchJSON("/_warden/auth/otp/setup", { method: "POST", body: {} });
        secretText.textContent = data.secret;
        urlText.textContent = data.otpauth_url;
        show(secretBox);
        msg("Scan the secret into your authenticator, then enter a code to confirm.", "ok");
      } catch (error) {
        msg(error.message || "Could not start enrolment.", "error");
      } finally {
        setupBtn.disabled = false;
      }
    });
  }

  if (verifyBtn) {
    verifyBtn.addEventListener("click", async () => {
      const code = (codeInput?.value || "").trim();
      if (!code) { msg("Enter the 6-digit code first.", "error"); return; }
      verifyBtn.disabled = true;
      try {
        const data = await window.Warden.fetchJSON("/_warden/auth/otp/verify", {
          method: "POST",
          body: { code },
        });
        if (data.ok) {
          msg("Two-factor authentication is now enabled.", "ok");
          if (statusEl) statusEl.textContent = "Enabled";
          hide(secretBox);
        } else {
          msg(data.detail || "Invalid code.", "error");
        }
      } catch (error) {
        msg(error.message || "Verification failed.", "error");
      } finally {
        verifyBtn.disabled = false;
      }
    });
  }

  if (disableBtn) {
    disableBtn.addEventListener("click", async () => {
      const code = window.prompt("Enter a current authenticator code to disable 2FA:");
      if (!code) return;
      disableBtn.disabled = true;
      try {
        await window.Warden.fetchJSON("/_warden/auth/otp/disable", {
          method: "POST",
          body: { code: code.trim() },
        });
        msg("Two-factor authentication disabled.", "ok");
        if (statusEl) statusEl.textContent = "Disabled";
      } catch (error) {
        msg(error.message || "Could not disable 2FA.", "error");
      } finally {
        disableBtn.disabled = false;
      }
    });
  }
})();