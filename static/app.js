(() => {
  "use strict";

  const byId = (id) => document.getElementById(id);

  function focusErrorSummary() {
    const summary = document.querySelector("[data-error-summary]");
    if (summary instanceof HTMLElement) summary.focus();
  }

  function setPasskeyMessage(element, value, isError = false) {
    element.textContent = value;
    element.setAttribute("role", isError ? "alert" : "status");
    element.setAttribute("aria-live", isError ? "assertive" : "polite");
  }

  function showDriverFields() {
    const driver = byId("driver");
    if (!driver) return;
    const visible = {
      additional_ip: "additional",
      socks5: "socks",
      provider_tunnel: "provider",
    }[driver.value];
    ["additional", "socks", "provider"].forEach((name) => {
      const field = byId(`${name}-fields`);
      if (!field) return;
      const isVisible = name === visible;
      field.classList.toggle("hidden", !isVisible);
      field.setAttribute("aria-hidden", String(!isVisible));
      field.querySelectorAll("input, select, textarea").forEach((control) => {
        control.disabled = !isVisible;
        if (control.hasAttribute("data-driver-required")) {
          control.required = isVisible;
        }
      });
    });
  }

  function updateFloatingProviderHelp() {
    const provider = byId("floating-provider");
    const help = byId("floating-provider-help");
    if (!provider || !help) return;
    const messages = {
      cloudzy: "In Cloudzy, open Networking → Floating IPs and copy the address, netmask, and gateway shown for the IP attached to this server.",
      digitalocean: "In DigitalOcean, assign the Reserved IP to this Droplet first. Use the network details shown by the Droplet or provider guide.",
      other: "Use the address, prefix or netmask, gateway, and interface supplied by your server provider.",
    };
    help.textContent = messages[provider.value] || messages.other;
  }

  function toggleFixedRoute() {
    const mode = byId("route-mode");
    if (!mode) return;
    const fixed = mode.value === "fixed";
    const exit = byId("fixed-exit-field");
    const pool = byId("fixed-pool-field");
    if (exit) exit.classList.toggle("hidden", !fixed);
    if (pool) pool.classList.toggle("hidden", !fixed);
  }

  function attachConfirmations() {
    document.querySelectorAll("form[data-confirm]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        if (!window.confirm(form.dataset.confirm || "Continue?")) {
          event.preventDefault();
        }
      });
    });
  }

  function attachRouteSwitches() {
    document.querySelectorAll("form[data-route-switch]").forEach((form) => {
      const profile = form.querySelector("[data-route-profile]");
      const pool = form.querySelector("[data-route-pool]");
      profile?.addEventListener("change", () => {
        if (pool) pool.value = "";
        form.requestSubmit();
      });
      pool?.addEventListener("change", () => {
        if (profile) profile.value = "";
        form.requestSubmit();
      });
    });
  }

  function attachUniquePoolBackups() {
    const selects = [...document.querySelectorAll("select[data-pool-backup]")];
    if (!selects.length) return;
    const refresh = () => {
      const chosen = new Set(selects.map((select) => select.value).filter(Boolean));
      selects.forEach((select) => {
        select.querySelectorAll("option[value]").forEach((option) => {
          option.disabled = Boolean(option.value && option.value !== select.value && chosen.has(option.value));
        });
      });
    };
    selects.forEach((select) => select.addEventListener("change", refresh));
    refresh();
  }

  function attachRequiredChoices() {
    document.querySelectorAll("[data-required-choice]").forEach((group) => {
      const form = group.closest("form");
      const submit = form?.querySelector("[data-choice-submit]");
      const choices = [...group.querySelectorAll('input[type="radio"]')];
      if (!submit || !choices.length) return;
      const refresh = () => {
        const ready = choices.some((choice) => choice.checked);
        submit.disabled = !ready;
        submit.textContent = ready
          ? (submit.dataset.readyLabel || "Continue")
          : (submit.dataset.waitingLabel || "Choose an option");
      };
      choices.forEach((choice) => choice.addEventListener("change", refresh));
      refresh();
    });
  }

  function attachLocationPickers() {
    document.querySelectorAll("[data-location-picker]").forEach((form) => {
      const choices = [...form.querySelectorAll('input[name="route_choice"]')];
      const fields = [...form.querySelectorAll("[data-location-fields]")];
      const profileSelect = form.querySelector('select[name="profile_id"]');
      const message = form.querySelector("[data-automatic-ipv6-message]");
      if (!choices.length) return;

      const refresh = () => {
        const selected = choices.find((choice) => choice.checked);
        const route = selected?.value || "direct";
        fields.forEach((field) => {
          const visible = field.dataset.locationFields === route;
          field.classList.toggle("hidden", !visible);
          field.setAttribute("aria-hidden", String(!visible));
          field.querySelectorAll("input, select, textarea").forEach((control) => {
            control.disabled = !visible;
          });
        });

        if (!message || !selected) return;
        let readiness = selected.dataset.ipv6Ready;
        if (route === "exit") {
          readiness = profileSelect?.selectedOptions[0]?.dataset.ipv6Ready;
        }
        if (readiness === "true") {
          message.textContent = "IPv6 protected: this Location passed live IPv6 TCP, DNS, and public-address checks.";
        } else if (readiness === "false") {
          message.textContent = "IPv6 blocked safely: IPv4 stays connected and IPv6 cannot leave outside CayVPN.";
        } else if (route === "pool") {
          message.textContent = "CayVPN protects IPv6 whenever the active Location in this backup group supports it; otherwise IPv6 is blocked safely.";
        } else {
          message.textContent = "Choose a Location to see how CayVPN will protect IPv6.";
        }
      };

      choices.forEach((choice) => choice.addEventListener("change", refresh));
      profileSelect?.addEventListener("change", refresh);
      refresh();
    });
  }

  function attachDeviceStepOneHistory() {
    const form = document.querySelector("[data-device-step-one-history]");
    const name = form?.querySelector('input[name="name"]');
    const protocols = form ? [...form.querySelectorAll('input[name="ingress_protocol"]')] : [];
    if (!form || !name || !protocols.length) return;

    const storageKey = `cayvpn-device-step-one:${window.location.pathname}`;
    const navigation = window.performance?.getEntriesByType?.("navigation")?.[0];
    let referrerPath = "";
    try {
      referrerPath = new URL(document.referrer).pathname;
    } catch (_error) {
      // An empty or restricted referrer is normal.
    }
    const arrivedThroughHistory =
      navigation?.type === "back_forward" ||
      window.history?.state?.cayvpnDeviceStepOne === true ||
      referrerPath.startsWith("/setup/client/");

    const restore = (allowed) => {
      if (!allowed) return;
      let saved;
      try {
        saved = JSON.parse(window.sessionStorage.getItem(storageKey) || "null");
      } catch (_error) {
        return;
      }
      if (!saved || typeof saved !== "object" || Array.isArray(saved)) return;
      if (!name.value && typeof saved.name === "string") {
        name.value = saved.name.slice(0, 120);
      }
      if (typeof saved.ingressProtocol === "string") {
        const protocol = protocols.find(
          (choice) => choice.value === saved.ingressProtocol && !choice.disabled,
        );
        if (protocol) protocol.checked = true;
      }
    };

    const save = () => {
      const selected = protocols.find((choice) => choice.checked && !choice.disabled);
      try {
        window.sessionStorage.setItem(
          storageKey,
          JSON.stringify({
            name: name.value.slice(0, 120),
            ingressProtocol: selected?.value || "wireguard",
          }),
        );
      } catch (_error) {
        // The server-side draft and Resume link remain available when a
        // browser blocks session storage.
      }
      try {
        window.history?.replaceState?.(
          { ...(window.history.state || {}), cayvpnDeviceStepOne: true },
          "",
        );
      } catch (_error) {
        // The saved server-side draft remains the fallback.
      }
    };

    name.addEventListener("input", save);
    protocols.forEach((choice) => choice.addEventListener("change", save));
    restore(arrivedThroughHistory);
    form.addEventListener("submit", save);
  }

  function monitorUpdate() {
    const monitor = document.querySelector('[data-update-monitor="true"]');
    const message = byId("update-progress");
    if (!monitor || !message) return;
    const initialState = monitor.dataset.updateState;
    const activeStates = new Set(["stage_queued", "staging", "install_queued", "installing"]);
    const terminalStates = new Set(["staged", "installed", "stage_failed", "install_failed", "install_interrupted"]);
    let attempts = 0;
    const poll = async () => {
      attempts += 1;
      try {
        const response = await fetch("/api/v1/updates", {
          credentials: "same-origin",
          cache: "no-store",
        });
        if (response.ok) {
          const body = await response.json();
          const state = body.status?.state;
          if (state === "stage_queued" || state === "staging") {
            message.textContent = "Downloading and verifying the update…";
          } else if (state === "install_queued" || state === "installing") {
            message.textContent = "Installing and checking the update…";
          } else if (terminalStates.has(state)) {
            window.location.reload();
            return;
          }
        }
      } catch (error) {
        message.textContent = initialState.startsWith("install")
          ? "CayVPN is restarting. Reconnecting to settings…"
          : "The download is continuing in the background…";
      }
      if (attempts < 240) window.setTimeout(poll, 3000);
    };
    window.setTimeout(poll, 1500);
  }

  function decode(value) {
    const pad = "=".repeat((4 - (value.length % 4)) % 4);
    return Uint8Array.from(
      atob((value + pad).replace(/-/g, "+").replace(/_/g, "/")),
      (character) => character.charCodeAt(0),
    );
  }

  function encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }

  function prepare(value) {
    if (value.challenge) value.challenge = decode(value.challenge);
    if (value.user?.id) value.user.id = decode(value.user.id);
    if (value.excludeCredentials) {
      value.excludeCredentials = value.excludeCredentials.map((item) => ({
        ...item,
        id: decode(item.id),
      }));
    }
    if (value.allowCredentials) {
      value.allowCredentials = value.allowCredentials.map((item) => ({
        ...item,
        id: decode(item.id),
      }));
    }
    return value;
  }

  async function postJson(url, csrfToken) {
    const response = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-CSRFToken": csrfToken },
    });
    const data = await response.json();
    if (!response.ok) {
      const error = new Error(data.error || "CayVPN could not start passkey setup.");
      error.name = "CayVPNError";
      throw error;
    }
    return data;
  }

  function preparePasskeyControls() {
    const controls = byId("passkey-controls");
    const message = byId("passkey-message");
    if (!controls || !message) return true;
    const warning = byId("passkey-secure-context-warning");
    const buttons = [byId("register-passkey"), byId("approve-passkey")].filter(Boolean);
    if (!window.isSecureContext) {
      warning?.classList.remove("hidden");
      buttons.forEach((button) => {
        button.disabled = true;
        button.setAttribute("aria-disabled", "true");
      });
      setPasskeyMessage(message, "Optional passkey setup is paused until this browser trusts CayVPN.");
      return false;
    }
    if (!window.PublicKeyCredential || !navigator.credentials) {
      buttons.forEach((button) => {
        button.disabled = true;
        button.setAttribute("aria-disabled", "true");
      });
      setPasskeyMessage(message, "This browser cannot create passkeys. Use a current browser or approve through server recovery below.");
      return false;
    }
    return true;
  }

  function passkeyFailureMessage(error, action) {
    if (error?.name === "CayVPNError") return error.message;
    if (!window.isSecureContext || error?.name === "SecurityError") {
      return "Trust the CayVPN certificate on this device, fully quit and reopen the browser, then try again.";
    }
    if (error?.name === "NotAllowedError") {
      return `Passkey ${action} was cancelled or timed out. Try again when you are ready.`;
    }
    return `Passkey ${action} could not start. Try again or use SSH recovery below.`;
  }

  async function registerPasskey() {
    const controls = byId("passkey-controls");
    const message = byId("passkey-message");
    if (!controls || !message) return;
    if (!preparePasskeyControls()) return;
    try {
      const options = prepare(
        await postJson(controls.dataset.registerOptionsUrl, controls.dataset.csrfToken),
      );
      const credential = await navigator.credentials.create({ publicKey: options });
      const body = {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          attestationObject: encode(credential.response.attestationObject),
        },
      };
      const result = await fetch(controls.dataset.registerUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": controls.dataset.csrfToken,
        },
        body: JSON.stringify(body),
      });
      const data = await result.json();
      setPasskeyMessage(
        message,
        data.ok
          ? "Passkey added. Use it when CayVPN asks you to confirm a change."
          : (data.error || "Passkey registration failed."),
        !data.ok,
      );
      if (data.ok) window.location.reload();
    } catch (error) {
      setPasskeyMessage(message, passkeyFailureMessage(error, "registration"), true);
    }
  }

  async function authenticatePasskey() {
    const controls = byId("passkey-controls");
    const message = byId("passkey-message");
    if (!controls || !message) return;
    if (!preparePasskeyControls()) return;
    try {
      const options = prepare(
        await postJson(controls.dataset.authOptionsUrl, controls.dataset.csrfToken),
      );
      const credential = await navigator.credentials.get({ publicKey: options });
      const body = {
        id: credential.id,
        rawId: encode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: encode(credential.response.clientDataJSON),
          authenticatorData: encode(credential.response.authenticatorData),
          signature: encode(credential.response.signature),
          userHandle: credential.response.userHandle
            ? encode(credential.response.userHandle)
            : null,
        },
      };
      const result = await fetch(controls.dataset.authUrl, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": controls.dataset.csrfToken,
        },
        body: JSON.stringify(body),
      });
      const data = await result.json();
      setPasskeyMessage(
        message,
        data.ok
          ? "Important changes are unlocked for five minutes."
          : (data.error || "Passkey confirmation failed."),
        !data.ok,
      );
      if (data.ok) window.location.reload();
    } catch (error) {
      setPasskeyMessage(message, passkeyFailureMessage(error, "authentication"), true);
    }
  }

  byId("driver")?.addEventListener("change", showDriverFields);
  byId("floating-provider")?.addEventListener("change", updateFloatingProviderHelp);
  byId("route-mode")?.addEventListener("change", toggleFixedRoute);
  byId("register-passkey")?.addEventListener("click", registerPasskey);
  byId("approve-passkey")?.addEventListener("click", authenticatePasskey);
  showDriverFields();
  updateFloatingProviderHelp();
  toggleFixedRoute();
  attachConfirmations();
  attachRouteSwitches();
  attachUniquePoolBackups();
  attachRequiredChoices();
  attachLocationPickers();
  attachDeviceStepOneHistory();
  focusErrorSummary();
  preparePasskeyControls();
  monitorUpdate();
})();
