/* Warden admin interactions: status, services, passkeys, sessions, config, mesh. */
(() => {
  "use strict";
  const W = window.Warden;
  const page = document.body.dataset.page;

  const setText = (selector, value) => {
    const node = W.$(selector);
    if (node) node.textContent = value;
  };

  const showFailure = (box, error) => {
    const data = error?.data;
    let message = error?.message || "Something went wrong.";
    if (data && Array.isArray(data.errors) && data.errors.length) {
      message += `\n${data.errors.join("\n")}`;
    }
    W.showError(box, message);
  };

  const handleExpiredSession = (error) => {
    if (error?.status === 401) {
      window.location.assign("/_warden/login");
      return true;
    }
    return false;
  };

  const formatBytes = (value) => {
    let size = Number(value) || 0;
    if (size < 1024) return `${Math.round(size)} B`;
    const units = ["KB", "MB", "GB", "TB"];
    for (const unit of units) {
      size /= 1024;
      if (size < 1024 || unit === "TB") return `${size.toFixed(1)} ${unit}`;
    }
    return `${size.toFixed(1)} TB`;
  };

  // ------------------------------------------------------------------ dashboard
  const initDashboard = () => {
    const grid = W.$("#service-grid");
    const modal = W.$("#service-modal-overlay");
    const form = W.$("#service-form");
    const errorBox = W.$("#service-error");
    const submit = W.$("#service-submit");
    const title = W.$("#service-modal-title");
    const copy = W.$("#service-modal-copy");
    const refresh = W.$("#refresh-status");
    let editingHost = "";

    const resetForm = () => {
      form.reset();
      editingHost = "";
      W.hide(errorBox);
      W.closeOverlay(modal);
      const advanced = W.$("details.advanced", modal);
      if (advanced) advanced.open = false;
    };

    const openAdd = () => {
      form.reset();
      editingHost = "";
      title.textContent = "Add a service";
      copy.textContent = "Point a hostname at something running on your network.";
      W.hide(errorBox);
      W.openOverlay(modal);
    };

    const fill = (data) => {
      form.elements.host.value = data.host || "";
      form.elements.upstream.value = data.upstream || "";
      form.elements.name.value = data.name || "";
      form.elements.icon.value = data.icon || "";
      form.elements.health_path.value = data.health_path || "/";
      form.elements.public_paths.value = data.public_paths || "";
      W.$("#service-auth").checked = Boolean(data.auth);
      W.$("#service-enabled").checked = Boolean(data.enabled);
      W.$("#service-websocket").checked = Boolean(data.websocket);
      W.$("#service-preserve-host").checked = Boolean(data.preserve_host);
      W.$("#service-verify-tls").checked = Boolean(data.verify_tls);
    };

    const openEdit = (card) => {
      let data;
      try {
        data = JSON.parse(card.dataset.service || "{}");
      } catch {
        W.toast("That service card is unreadable. Reload the page.", { type: "error" });
        return;
      }
      fill(data);
      editingHost = card.dataset.host;
      title.textContent = `Edit ${data.name || editingHost}`;
      copy.textContent = "Changes are applied without dropping the listener.";
      W.hide(errorBox);
      W.openOverlay(modal);
    };

    W.$("#add-service")?.addEventListener("click", openAdd);
    W.$("[data-open-service]")?.addEventListener("click", openAdd);

    grid?.addEventListener("click", async (event) => {
      const card = event.target.closest(".service-card");
      if (!card) return;
      if (event.target.closest("[data-edit-service]")) {
        openEdit(card);
        return;
      }
      const remove = event.target.closest("[data-delete-service]");
      if (!remove) return;
      const host = card.dataset.host;
      if (!window.confirm(`Remove the route for ${host}?\n\nRequests will stop reaching this service immediately.`)) {
        return;
      }
      remove.disabled = true;
      try {
        await W.fetchJSON(`/_warden/api/services/${encodeURIComponent(host)}`, { method: "DELETE" });
        card.remove();
        W.toast(`${host} removed.`);
        window.setTimeout(() => window.location.reload(), 500);
      } catch (error) {
        remove.disabled = false;
        if (handleExpiredSession(error)) return;
        W.toast(error.message, { title: "Could not remove service", type: "error" });
      }
    });

    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      W.hide(errorBox);
      if (!form.reportValidity()) return;
      const publicPaths = form.elements.public_paths.value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
      const payload = {
        host: form.elements.host.value.trim(),
        upstream: form.elements.upstream.value.trim(),
        name: form.elements.name.value.trim() || null,
        icon: form.elements.icon.value.trim() || null,
        auth: W.$("#service-auth").checked,
        enabled: W.$("#service-enabled").checked,
        websocket: W.$("#service-websocket").checked,
        preserve_host: W.$("#service-preserve-host").checked,
        verify_tls: W.$("#service-verify-tls").checked,
        health_path: form.elements.health_path.value.trim() || "/",
        public_paths: publicPaths,
      };
      W.setBusy(submit, true, editingHost ? "Saving…" : "Adding…");
      try {
        if (editingHost) {
          await W.fetchJSON(`/_warden/api/services/${encodeURIComponent(editingHost)}`, {
            method: "PUT",
            body: payload,
          });
        } else {
          await W.fetchJSON("/_warden/api/services", { method: "POST", body: payload });
        }
        W.closeOverlay(modal);
        W.toast(editingHost ? "Service updated." : "Service added. It is live now.", {
          title: payload.host,
        });
        window.setTimeout(() => window.location.reload(), 520);
      } catch (error) {
        if (handleExpiredSession(error)) return;
        showFailure(errorBox, error);
        W.setBusy(submit, false);
      }
    });

    // -------------------------------------------------------------- live status
    const stateLabels = {
      online: "Live",
      offline: "Down",
      checking: "Checking",
      disabled: "Paused",
    };

    const renderTraffic = (events) => {
      const feed = W.$("#traffic-feed");
      if (!feed) return;
      if (!events || !events.length) {
        feed.replaceChildren();
        const empty = document.createElement("div");
        empty.className = "feed-empty";
        empty.textContent = "Requests will appear here as they pass through.";
        feed.appendChild(empty);
        return;
      }
      feed.replaceChildren();
      events.slice(0, 12).forEach((item) => {
        const row = document.createElement("div");
        row.className = "feed-row";
        const method = document.createElement("span");
        method.className = "feed-method";
        method.textContent = String(item.method || "").slice(0, 6);
        const main = document.createElement("span");
        main.className = "feed-main";
        const host = document.createElement("span");
        host.className = "feed-host";
        host.textContent = item.host;
        const path = document.createElement("span");
        path.className = "feed-path";
        path.textContent = item.path;
        main.append(host, path);
        const status = document.createElement("span");
        status.className = `feed-status${Number(item.status) >= 500 ? " error" : ""}`;
        status.textContent = String(item.status);
        const when = document.createElement("time");
        when.className = "feed-time";
        when.dataset.ts = item.timestamp;
        when.textContent = W.formatRelative(item.timestamp);
        row.append(method, main, status, when);
        feed.appendChild(row);
      });
    };

    const applyStatus = (snapshot) => {
      const totals = snapshot.totals || {};
      setText("#stat-online", String(totals.online ?? 0));
      setText("#stat-requests", Number(totals.requests || 0).toLocaleString());
      setText("#stat-errors", Number(totals.errors || 0).toLocaleString());
      const cards = W.$$(".service-card", grid);
      cards.forEach((card) => {
        const data = snapshot.services?.[card.dataset.host];
        if (!data) return;
        const pill = W.$("[data-status-pill]", card);
        if (pill) {
          pill.className = `status-pill ${data.state}`;
          const label = W.$("[data-status-label]", pill);
          if (label) label.textContent = stateLabels[data.state] || "Unknown";
        }
        card.classList.toggle("is-offline", data.state === "offline" || data.state === "disabled");
        const latency = W.$("[data-latency]", card);
        if (latency) latency.textContent = data.latency_ms == null ? "—" : `${data.latency_ms} ms`;
        const requests = W.$("[data-requests]", card);
        if (requests) requests.textContent = `${data.requests || 0} req`;
        const pillNode = W.$("[data-status-pill]", card);
        if (pillNode) {
          pillNode.title = data.health_error
            ? `${data.health_error} · checked ${W.formatRelative(data.health_checked_at)}`
            : `checked ${W.formatRelative(data.health_checked_at)}`;
        }
      });
      renderTraffic(snapshot.traffic || []);
    };

    const refreshStatus = async ({ manual = false } = {}) => {
      if (manual && refresh) W.setBusy(refresh, true, "Checking…");
      try {
        const snapshot = await W.fetchJSON("/_warden/api/status");
        applyStatus(snapshot);
      } catch (error) {
        if (handleExpiredSession(error)) return;
        if (manual) W.toast(error.message, { title: "Status unavailable", type: "error" });
      } finally {
        if (manual) W.setBusy(refresh, false);
      }
    };

    refresh?.addEventListener("click", () => refreshStatus({ manual: true }));
    refreshStatus();
    window.setInterval(() => {
      if (document.visibilityState === "visible") refreshStatus();
    }, 12000);
    window.setInterval(() => W.refreshTimes(), 30000);
  };

  // ------------------------------------------------------------------- passkeys
  const initPasskeys = () => {
    const add = W.$("#add-passkey");
    const modal = W.$("#passkey-modal-overlay");
    const form = W.$("#passkey-form");
    const submit = W.$("#passkey-submit");
    const errorBox = W.$("#passkey-error");
    const nameInput = W.$("#passkey-name");
    const renameModal = W.$("#rename-modal-overlay");
    const renameForm = W.$("#rename-form");
    const renameInput = W.$("#rename-name");
    const renameSubmit = W.$("#rename-submit");
    const renameError = W.$("#rename-error");
    let renameRow = null;

    if (new URLSearchParams(window.location.search).has("added")) {
      window.history.replaceState({}, "", window.location.pathname);
    }

    add?.addEventListener("click", () => {
      if (!W.passkeysSupported()) {
        W.toast(W.passkeySupportMessage(), { title: "Passkeys unavailable", type: "error" });
        return;
      }
      form.reset();
      W.hide(errorBox);
      W.openOverlay(modal);
    });

    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      W.hide(errorBox);
      if (!form.reportValidity()) return;
      W.setBusy(submit, true, "Waiting for your passkey…");
      try {
        const result = await W.registerPasskey({
          mode: "add",
          name: nameInput.value.trim(),
        });
        window.location.assign(result.redirect || "/passkeys?added=1");
      } catch (error) {
        showFailure(errorBox, error);
        W.setBusy(submit, false);
      }
    });

    W.$("#passkey-list")?.addEventListener("click", (event) => {
      const row = event.target.closest("[data-credential-id]");
      if (!row) return;
      if (event.target.closest("[data-rename-passkey]")) {
        renameRow = row;
        renameInput.value = row.dataset.name || "";
        W.hide(renameError);
        W.openOverlay(renameModal);
        return;
      }
      if (event.target.closest("[data-delete-passkey]")) {
        const name = row.dataset.name || "this passkey";
        if (!window.confirm(`Remove "${name}"?\n\nYou will need another passkey to sign in.`)) return;
        const button = event.target.closest("button");
        button.disabled = true;
        W.fetchJSON(`/_warden/api/passkeys/${row.dataset.credentialId}`, { method: "DELETE" })
          .then(() => {
            W.toast("Passkey removed.");
            window.setTimeout(() => window.location.reload(), 450);
          })
          .catch((error) => {
            button.disabled = false;
            if (handleExpiredSession(error)) return;
            W.toast(error.message, { title: "Could not remove passkey", type: "error" });
          });
      }
    });

    renameForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (!renameRow) return;
      W.hide(renameError);
      if (!renameForm.reportValidity()) return;
      W.setBusy(renameSubmit, true, "Saving…");
      try {
        await W.fetchJSON(`/_warden/api/passkeys/${renameRow.dataset.credentialId}`, {
          method: "PATCH",
          body: { name: renameInput.value.trim() },
        });
        const name = renameInput.value.trim();
        renameRow.dataset.name = name;
        const label = W.$("[data-passkey-name]", renameRow);
        if (label) label.textContent = name;
        W.closeOverlay(renameModal);
        W.toast("Passkey renamed.");
      } catch (error) {
        if (handleExpiredSession(error)) return;
        showFailure(renameError, error);
      } finally {
        W.setBusy(renameSubmit, false);
      }
    });

    W.$("#session-list")?.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-revoke-session]");
      if (!button) return;
      const row = button.closest("[data-session-id]");
      if (!row) return;
      if (!window.confirm("Revoke this session? That device will need to sign in again.")) return;
      button.disabled = true;
      try {
        const result = await W.fetchJSON(`/_warden/api/sessions/${row.dataset.sessionId}`, {
          method: "DELETE",
        });
        if (result.redirect) {
          window.location.assign(result.redirect);
          return;
        }
        row.remove();
        W.toast("Session revoked.");
      } catch (error) {
        button.disabled = false;
        if (handleExpiredSession(error)) return;
        W.toast(error.message, { title: "Could not revoke session", type: "error" });
      }
    });

    W.$("#revoke-others")?.addEventListener("click", async (event) => {
      if (!window.confirm("Sign out every other browser and device?")) return;
      const button = event.currentTarget;
      W.setBusy(button, true, "Revoking…");
      try {
        const result = await W.fetchJSON("/_warden/api/sessions/revoke-others", {
          method: "POST",
          body: {},
        });
        W.toast(`${result.count} other session${result.count === 1 ? "" : "s"} revoked.`);
        window.setTimeout(() => window.location.reload(), 550);
      } catch (error) {
        W.setBusy(button, false);
        if (handleExpiredSession(error)) return;
        W.toast(error.message, { title: "Could not revoke sessions", type: "error" });
      }
    });
  };

  // ------------------------------------------------------------------- activity
  const initActivity = () => {
    const filter = W.$("#activity-filter");
    const empty = W.$("#activity-empty");
    if (!filter) return;
    const rows = W.$$("[data-event-row]");
    filter.addEventListener("input", () => {
      const query = filter.value.trim().toLowerCase();
      let visible = 0;
      rows.forEach((row) => {
        const match = !query || row.textContent.toLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible += 1;
      });
      if (empty) empty.hidden = visible !== 0 || !query;
    });
    W.$("#activity-refresh")?.addEventListener("click", () => window.location.reload());
  };

  // --------------------------------------------------------------------- config
  const initConfig = () => {
    const editor = W.$("#config-editor");
    if (!editor) return;
    let original = editor.value;
    const status = W.$("#editor-status");
    const statusText = W.$("#editor-status-text");
    const errors = W.$("#config-errors");
    const restartNote = W.$("#restart-note");
    const validateButton = W.$("#config-validate");
    const saveButton = W.$("#config-save");
    const reloadButton = W.$("#config-reload");

    const setStatus = (text, dirty = false) => {
      if (statusText) statusText.textContent = text;
      if (status) status.classList.toggle("dirty", dirty);
    };

    const setError = (message) => {
      if (!errors) return;
      errors.textContent = message || "";
    };

    const showRestart = (fields) => {
      if (!restartNote) return;
      if (fields && fields.length) {
        restartNote.hidden = false;
        restartNote.textContent = `Saved. Restart Warden to apply: ${fields.join(", ")}.`;
      } else {
        restartNote.hidden = true;
      }
    };

    const validate = async ({ quiet = false } = {}) => {
      setError("");
      W.setBusy(validateButton, true, "Validating…");
      try {
        const result = await W.fetchJSON("/_warden/api/config/validate", {
          method: "POST",
          body: { yaml: editor.value },
        });
        setStatus("valid", editor.value !== original);
        if (!quiet) {
          W.toast(`${result.routes} route${result.routes === 1 ? "" : "s"} · configuration is valid.`, {
            title: "Looks good",
          });
        }
        showRestart(result.restart_required || []);
        return true;
      } catch (error) {
        if (handleExpiredSession(error)) return false;
        const data = error.data || {};
        const detail = data.detail || error.message;
        const list = Array.isArray(data.errors) ? data.errors : [];
        setError([detail, ...list].filter(Boolean).join("\n"));
        W.toast("The configuration has errors. See the editor.", { type: "error" });
        return false;
      } finally {
        W.setBusy(validateButton, false);
      }
    };

    const save = async () => {
      if (editor.value === original) {
        W.toast("No changes to save.");
        return;
      }
      setError("");
      W.setBusy(saveButton, true, "Saving…");
      try {
        const result = await W.fetchJSON("/_warden/api/config", {
          method: "POST",
          body: { yaml: editor.value },
        });
        original = editor.value;
        window.__wardenConfigDirty = false;
        setStatus("saved", false);
        W.toast("Configuration saved to disk.", { title: "Saved" });
        showRestart(result.restart_required || []);
        // The live config object is replaced in place; reloading reflects every
        // derived number (route count, TLS state) without risking stale UI.
        if (!result.restart_required || !result.restart_required.length) {
          window.setTimeout(() => window.location.reload(), 700);
        }
      } catch (error) {
        if (handleExpiredSession(error)) return;
        const data = error.data || {};
        const detail = data.detail || error.message;
        const list = Array.isArray(data.errors) ? data.errors : [];
        setError([detail, ...list].filter(Boolean).join("\n"));
        W.toast("Nothing was written. Fix the errors and try again.", { type: "error" });
      } finally {
        W.setBusy(saveButton, false);
      }
    };

    editor.addEventListener("input", () => {
      const dirty = editor.value !== original;
      window.__wardenConfigDirty = dirty;
      setStatus(dirty ? "unsaved changes" : "unchanged", dirty);
    });

    editor.addEventListener("keydown", (event) => {
      if (event.key === "Tab") {
        event.preventDefault();
        const start = editor.selectionStart;
        const end = editor.selectionEnd;
        editor.setRangeText("  ", start, end, "end");
        editor.dispatchEvent(new Event("input"));
      }
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        save();
      }
    });

    validateButton?.addEventListener("click", () => validate());
    saveButton?.addEventListener("click", save);
    reloadButton?.addEventListener("click", () => {
      if (editor.value !== original && !window.confirm("Discard your unsaved changes?")) return;
      editor.value = original;
      window.__wardenConfigDirty = false;
      setError("");
      setStatus("unchanged", false);
      W.toast("Draft discarded.");
    });

    window.addEventListener("beforeunload", (event) => {
      if (editor.value === original) return;
      event.preventDefault();
      event.returnValue = "";
    });
  };

  // ----------------------------------------------------------------------- mesh
  const initMesh = () => {
    const add = W.$("#add-peer");
    if (!add) return;
    const modal = W.$("#peer-modal-overlay");
    const form = W.$("#peer-form");
    const submit = W.$("#peer-submit");
    const errorBox = W.$("#peer-error");
    const configModal = W.$("#peer-config-modal-overlay");
    const configText = W.$("#peer-config-text");
    const configCopy = W.$("#peer-config-copy");
    const configDownload = W.$("#peer-config-download");
    const copyButton = W.$("#peer-config-copy-btn");
    const list = W.$("#peer-list");
    let configFilename = "warden-peer.conf";

    const showConfig = (name, text, filename) => {
      configText.textContent = text;
      configCopy.textContent = `Import this file into the WireGuard app on ${name}.`;
      configFilename = filename;
      W.openOverlay(configModal);
    };

    add.addEventListener("click", () => {
      form.reset();
      W.$("#peer-keepalive").value = "25";
      W.hide(errorBox);
      W.openOverlay(modal);
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      W.hide(errorBox);
      if (!form.reportValidity()) return;
      const payload = {
        name: W.$("#peer-name").value.trim(),
        address: W.$("#peer-address").value.trim() || null,
        endpoint: W.$("#peer-endpoint").value.trim() || null,
        keepalive: Number.parseInt(W.$("#peer-keepalive").value, 10) || 0,
      };
      W.setBusy(submit, true, "Creating…");
      try {
        const result = await W.fetchJSON("/_warden/api/mesh/peers", {
          method: "POST",
          body: payload,
        });
        W.closeOverlay(modal);
        W.toast(`${result.peer.name} added at ${result.peer.address}.`, { title: "Peer created" });
        appendPeer(result.peer, payload.endpoint);
        showConfig(result.peer.name, result.config, result.filename);
      } catch (error) {
        if (handleExpiredSession(error)) return;
        showFailure(errorBox, error);
      } finally {
        W.setBusy(submit, false);
      }
    });

    const appendPeer = (peer, endpoint) => {
      const empty = list.querySelector(".empty-list");
      if (empty) empty.closest("tr")?.remove();
      const row = document.createElement("tr");
      row.dataset.peerId = String(peer.id);
      row.dataset.publicKey = peer.public_key;
      const nameCell = document.createElement("td");
      const name = document.createElement("span");
      name.className = "primary";
      name.textContent = peer.name;
      const key = document.createElement("span");
      key.className = "mono-cell";
      key.style.display = "block";
      key.style.color = "var(--faint)";
      key.title = peer.public_key;
      key.textContent = `${peer.public_key.slice(0, 12)}…`;
      nameCell.append(name, key);
      const addressCell = document.createElement("td");
      addressCell.className = "mono-cell";
      addressCell.textContent = peer.address;
      const endpointCell = document.createElement("td");
      endpointCell.className = "mono-cell";
      endpointCell.dataset.peerEndpoint = "";
      endpointCell.textContent = endpoint || "—";
      const handshakeCell = document.createElement("td");
      const handshake = document.createElement("time");
      handshake.dataset.peerHandshake = "";
      handshake.textContent = "never";
      handshakeCell.appendChild(handshake);
      const transferCell = document.createElement("td");
      transferCell.className = "mono-cell";
      transferCell.dataset.peerTransfer = "";
      transferCell.textContent = "0 B ↓ · 0 B ↑";
      const actionsCell = document.createElement("td");
      actionsCell.className = "row-actions";
      const configButton = document.createElement("button");
      configButton.type = "button";
      configButton.className = "btn btn-ghost btn-sm";
      configButton.dataset.peerConfig = "";
      configButton.textContent = "Config";
      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className = "btn btn-danger btn-sm";
      deleteButton.dataset.deletePeer = "";
      deleteButton.textContent = "Remove";
      actionsCell.append(configButton, deleteButton);
      row.append(nameCell, addressCell, endpointCell, handshakeCell, transferCell, actionsCell);
      list.appendChild(row);
      const count = W.$(".hub-grid .hub-stat:last-child .value");
      if (count) count.textContent = String(list.querySelectorAll("[data-peer-id]").length);
    };

    list?.addEventListener("click", async (event) => {
      const row = event.target.closest("[data-peer-id]");
      if (!row) return;
      if (event.target.closest("[data-peer-config]")) {
        const button = event.target.closest("button");
        button.disabled = true;
        try {
          const result = await W.fetchJSON(`/_warden/api/mesh/peers/${row.dataset.peerId}/config`);
          const name = W.$(".primary", row)?.textContent || "peer";
          showConfig(name, result.config, result.filename);
        } catch (error) {
          if (handleExpiredSession(error)) return;
          W.toast(error.message, { title: "Could not render config", type: "error" });
        } finally {
          button.disabled = false;
        }
        return;
      }
      if (event.target.closest("[data-delete-peer]")) {
        const name = W.$(".primary", row)?.textContent || "this peer";
        if (!window.confirm(`Remove ${name}?\n\nIts keys are deleted from Warden. Apply again to drop the live session.`)) {
          return;
        }
        const button = event.target.closest("button");
        button.disabled = true;
        try {
          await W.fetchJSON(`/_warden/api/mesh/peers/${row.dataset.peerId}`, { method: "DELETE" });
          row.remove();
          W.toast(`${name} removed.`);
        } catch (error) {
          button.disabled = false;
          if (handleExpiredSession(error)) return;
          W.toast(error.message, { title: "Could not remove peer", type: "error" });
        }
      }
    });

    configDownload?.addEventListener("click", () => {
      W.download(configFilename, configText.textContent, "text/plain");
    });
    copyButton?.addEventListener("click", () => W.copy(configText.textContent));

    W.$("[data-copy-hub]")?.addEventListener("click", () => {
      const key = W.$("#hub-public-key");
      if (key) W.copy(key.textContent.trim());
    });

    W.$("#mesh-apply")?.addEventListener("click", async (event) => {
      if (!window.confirm("Write the WireGuard config and apply it to the host interface now?")) return;
      const button = event.currentTarget;
      W.setBusy(button, true, "Applying…");
      try {
        const result = await W.fetchJSON("/_warden/api/mesh/apply", {
          method: "POST",
          body: {},
        });
        W.toast(result.output || `Interface ${result.interface} is up.`, {
          title: "Mesh applied",
        });
        window.setTimeout(() => window.location.reload(), 800);
      } catch (error) {
        W.setBusy(button, false);
        if (handleExpiredSession(error)) return;
        W.toast(error.message, { title: "Could not apply mesh", type: "error" });
      }
    });

    const refreshMesh = async () => {
      try {
        const status = await W.fetchJSON("/_warden/api/mesh/status");
        const peers = status.peer_status || {};
        W.$$("[data-peer-id]").forEach((row) => {
          const info = peers[row.dataset.publicKey];
          if (!info) return;
          const endpoint = W.$("[data-peer-endpoint]", row);
          if (endpoint) endpoint.textContent = info.endpoint || "—";
          const handshake = W.$("[data-peer-handshake]", row);
          if (handshake) {
            handshake.dataset.ts = info.last_handshake || "";
            handshake.textContent = info.last_handshake
              ? W.formatRelative(info.last_handshake)
              : "never";
          }
          const transfer = W.$("[data-peer-transfer]", row);
          if (transfer) {
            transfer.textContent = `${formatBytes(info.rx_bytes)} ↓ · ${formatBytes(info.tx_bytes)} ↑`;
          }
        });
      } catch {
        /* Status is informative; keep the page usable if wg is unavailable. */
      }
    };
    refreshMesh();
    window.setInterval(() => {
      if (document.visibilityState === "visible") refreshMesh();
    }, 15000);
    window.setInterval(() => W.refreshTimes(), 30000);
  };

  const initUsers = () => {
    const addButton = W.$("#add-user");
    const addModal = W.$("#user-modal-overlay");
    const addForm = W.$("#user-form");
    const addError = W.$("#user-error");
    const addSubmit = W.$("#user-submit");

    const editModal = W.$("#edit-user-modal-overlay");
    const editForm = W.$("#edit-user-form");
    const editError = W.$("#edit-user-error");
    const editSubmit = W.$("#edit-user-submit");

    const inviteModal = W.$("#invite-modal-overlay");
    const inviteToken = W.$("#invite-token");
    const inviteCopy = W.$("#invite-copy");

    const hide = (el) => { if (el) { el.hidden = true; el.textContent = ""; } };

    const openAdd = () => {
      addForm.reset();
      hide(addError);
      W.openOverlay(addModal);
      addForm.elements.username.focus();
    };

    addButton?.addEventListener("click", openAdd);

    addForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      hide(addError);
      if (!addForm.reportValidity()) return;
      const payload = {
        username: addForm.elements.username.value.trim(),
        display_name: addForm.elements.display_name.value.trim(),
        email: addForm.elements.email.value.trim() || null,
        is_admin: addForm.elements.is_admin.checked,
      };
      W.setBusy(addSubmit, true, "Creating…");
      try {
        const user = await W.fetchJSON("/_warden/api/users", {
          method: "POST",
          body: payload,
        });
        const invite = await W.fetchJSON("/_warden/api/invites", {
          method: "POST",
          body: { user_id: user.user_id, expires_in: 3600 },
        });
        W.closeOverlay(addModal);
        W.toast("User created.", { title: payload.username });
        const row = W.$(`[data-user-id="${user.user_id}"]`);
        if (row) {
          row.querySelector(".user-name").textContent = payload.display_name || payload.username;
          row.querySelector(".user-handle").textContent = `@${payload.username}`;
          const badge = row.querySelector(".badge");
          if (badge) {
            badge.className = `badge ${payload.is_admin ? 'badge-accent' : 'badge-indigo'}`;
            badge.textContent = payload.is_admin ? 'Administrator' : 'User';
          }
          const promoteBtn = row.querySelector(".toggle-admin");
          if (promoteBtn) promoteBtn.textContent = payload.is_admin ? 'Demote' : 'Promote';
        }
        if (inviteToken) inviteToken.value = invite.token || "";
        W.openOverlay(inviteModal);
        inviteToken?.select();
      } catch (error) {
        if (handleExpiredSession(error)) return;
        showFailure(addError, error);
      } finally {
        W.setBusy(addSubmit, false);
      }
    });

    inviteCopy?.addEventListener("click", async () => {
      if (!inviteToken?.value) return;
      const ok = await W.copy(inviteToken.value);
      if (ok) inviteCopy.textContent = "Copied";
      window.setTimeout(() => { if (inviteCopy) inviteCopy.textContent = "Copy"; }, 1200);
    });

    const openEdit = (row) => {
      const userId = row.dataset.userId;
      const name = row.querySelector(".user-name")?.textContent || "";
      const email = row.querySelector(".user-email")?.textContent || "";
      const badge = row.querySelector(".badge");
      const isAdmin = badge?.classList.contains("badge-accent");
      editForm.elements.user_id.value = userId;
      editForm.elements.display_name.value = name;
      editForm.elements.email.value = email;
      editForm.elements.is_admin.checked = isAdmin;
      hide(editError);
      W.openOverlay(editModal);
      editForm.elements.display_name.focus();
    };

    W.$$(".user-row").forEach((row) => {
      row.addEventListener("click", (event) => {
        if (event.target.closest("button")) return;
        openEdit(row);
      });
    });

    editForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      hide(editError);
      if (!editForm.reportValidity()) return;
      const userId = editForm.elements.user_id.value;
      const payload = {
        display_name: editForm.elements.display_name.value.trim(),
        email: editForm.elements.email.value.trim() || null,
        is_admin: editForm.elements.is_admin.checked,
      };
      W.setBusy(editSubmit, true, "Saving…");
      try {
        await W.fetchJSON(`/_warden/api/users/${encodeURIComponent(userId)}`, {
          method: "PATCH",
          body: payload,
        });
        const row = W.$(`[data-user-id="${userId}"]`);
        if (row) {
          row.querySelector(".user-name").textContent = payload.display_name;
          const emailEl = row.querySelector(".user-email");
          if (emailEl) {
            emailEl.textContent = payload.email || "";
            emailEl.hidden = !payload.email;
          }
          const badge = row.querySelector(".badge");
          if (badge) {
            badge.className = `badge ${payload.is_admin ? 'badge-accent' : 'badge-indigo'}`;
            badge.textContent = payload.is_admin ? 'Administrator' : 'User';
          }
          const promoteBtn = row.querySelector(".toggle-admin");
          if (promoteBtn) promoteBtn.textContent = payload.is_admin ? 'Demote' : 'Promote';
        }
        W.closeOverlay(editModal);
        W.toast("User updated.");
      } catch (error) {
        if (handleExpiredSession(error)) return;
        showFailure(editError, error);
      } finally {
        W.setBusy(editSubmit, false);
      }
    });

    W.$$(".toggle-admin").forEach((button) => {
      button.addEventListener("click", async () => {
        const row = button.closest("tr[data-user-id]");
        if (!row) return;
        const userId = row.dataset.userId;
        const badge = row.querySelector(".badge");
        const isAdmin = badge?.classList.contains("badge-accent");
        button.disabled = true;
        try {
          await W.fetchJSON(`/_warden/api/users/${encodeURIComponent(userId)}`, {
            method: "PATCH",
            body: { is_admin: !isAdmin },
          });
          if (badge) {
            badge.className = `badge ${!isAdmin ? 'badge-accent' : 'badge-indigo'}`;
            badge.textContent = !isAdmin ? 'Administrator' : 'User';
          }
          button.textContent = !isAdmin ? 'Demote' : 'Promote';
        } catch (error) {
          if (handleExpiredSession(error)) return;
          W.toast(error.message, { title: "Could not update role", type: "error" });
        } finally {
          button.disabled = false;
        }
      });
    });

    W.$$(".delete-user").forEach((button) => {
      button.addEventListener("click", async () => {
        const row = button.closest("tr[data-user-id]");
        if (!row) return;
        const userId = row.dataset.userId;
        const name = row.querySelector(".user-name")?.textContent || "this user";
        if (!window.confirm(`Remove ${name}?\n\nThey will lose access immediately.`)) return;
        button.disabled = true;
        try {
          await W.fetchJSON(`/_warden/api/users/${encodeURIComponent(userId)}`, {
            method: "DELETE",
          });
          row.remove();
          W.toast(`${name} removed.`);
        } catch (error) {
          if (handleExpiredSession(error)) return;
          W.toast(error.message, { title: "Could not remove user", type: "error" });
        } finally {
          button.disabled = false;
        }
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    if (page === "dashboard") initDashboard();
    if (page === "passkeys") initPasskeys();
    if (page === "activity") initActivity();
    if (page === "config") initConfig();
    if (page === "mesh") initMesh();
    if (page === "users") initUsers();
  });
})();
