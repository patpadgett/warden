/* Copy-to-clipboard for a freshly generated backup code. */
(() => {
  "use strict";

  const code = document.getElementById("new-backup-code");
  const button = document.getElementById("copy-backup-code");
  if (!code || !button) {
    return;
  }

  button.addEventListener("click", () => {
    const text = code.textContent.trim();
    if (text && window.Warden && window.Warden.copy) {
      window.Warden.copy(text);
    }
  });
})();
