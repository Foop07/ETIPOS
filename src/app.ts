(function () {
  "use strict";

  const $ = (id: string): any => document.getElementById(id);

  // --- Elements -------------------------------------------------------------

  const pwaInstallBanner = $("pwaInstallBanner");
  const btnPwaInstall = $("btnPwaInstall");
  const btnDismissInstall = $("btnDismissInstall");
  const biometricGate = $("biometricGate");
  const btnBiometricAuth = $("btnBiometricAuth");

  const tabSend = $("tabSend");
  const tabReceive = $("tabReceive");
  const panelSend = $("panelSend");
  const panelReceive = $("panelReceive");

  const healthPill = $("healthPill");
  const healthDot = $("healthDot");
  const healthText = $("healthText");
  const footUrl = $("footUrl");

  const dropzone = $("dropzone");
  const fileInput = $("fileInput");

  const filebar = $("filebar");
  const fileName = $("fileName");
  const fileSize = $("fileSize");
  const btnClear = $("btnClear");
  const btnScan = $("btnScan");

  const progress = $("progress");
  const progressTitle = $("progressTitle");
  const progressCount = $("progressCount");
  const bar = $("bar");
  const barFill = $("barFill");
  const steps = $("steps");

  const result = $("result");
  const verdictBadge = $("verdictBadge");
  const resultReason = $("resultReason");
  const facts = $("facts");
  const credential = $("credential");
  const qrImage = $("qrImage");
  const pinDisplay = $("pinDisplay");
  const credTimer = $("credTimer");
  const btnCopyLink = $("btnCopyLink");
  const btnNewFile = $("btnNewFile");
  const btnRetry = $("btnRetry");

  const pinDigits = [$("d1"), $("d2"), $("d3"), $("d4"), $("d5"), $("d6")];
  const btnDownload = $("btnDownload");
  const receiveAlert = $("receiveAlert");

  // --- Domain OTP Verification Elements ---
  const panelOtpAuth = $("panelOtpAuth");
  const otpDigits = [$("o1"), $("o2"), $("o3"), $("o4"), $("o5"), $("o6")];
  const btnVerifyOtp = $("btnVerifyOtp");
  const otpAlert = $("otpAlert");

  const distanceLinkInput = $("distanceLinkInput");
  const btnCopyDistanceLink = $("btnCopyDistanceLink");
  const recipientEmail = $("recipientEmail");
  const btnSendEmail = $("btnSendEmail");
  const emailNotice = $("emailNotice");

  // --- State ----------------------------------------------------------------
  let currentToken = "";
  let currentDownloadUrl = "";

  let mode = "send";
  let selectedFile = null;
  let activeStream = null;
  let copyUrl = "";
  let countdown = null;
  let expiryAt = 0;
  let downloading = false;

  const STATUS_GLYPH = {
    running: "",
    done: "✓",
    failed: "!",
    skipped: "–"
  };

  // --- Helpers --------------------------------------------------------------

  function formatBytes(bytes) {
    if (!bytes) return "0 Bytes";
    const units = ["Bytes", "KB", "MB", "GB"];
    const i = Math.min(
      Math.floor(Math.log(bytes) / Math.log(1024)),
      units.length - 1
    );
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(1)) + " " + units[i];
  }

  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }

  function resetPanels() {
    hide(progress);
    hide(result);
    hide(credential);
    hide(facts);
    hide(btnRetry);
    stopCountdown();
  }

  // --- Mode switching -------------------------------------------------------

  function setMode(next) {
    mode = next;
    const sending = next === "send";

    tabSend.classList.toggle("active", sending);
    tabReceive.classList.toggle("active", !sending);
    tabSend.setAttribute("aria-selected", String(sending));
    tabReceive.setAttribute("aria-selected", String(!sending));

    if (sending) {
      show(panelSend);
      hide(panelReceive);
    } else {
      hide(panelSend);
      show(panelReceive);
    }

    if (!sending) {
      const empty = pinDigits.find((d) => !d.value);
      if (empty) empty.focus();
    }
  }

  tabSend.addEventListener("click", () => setMode("send"));
  tabReceive.addEventListener("click", () => setMode("receive"));

  // --- Health ---------------------------------------------------------------

  function setHealth(state, label) {
    healthDot.className = "status-dot" + (state ? " " + state : "");
    healthText.textContent = label;
  }

  async function fetchHealth() {
    try {
      const res = await fetch("/health", { cache: "no-store" });
      if (!res.ok) throw new Error("health check failed");
      const data = await res.json();

      const c = data.components || {};
      const online = [c.tier1_magika, c.tier2_clamav, c.tier3_ollama_qwen]
        .filter((v) => v === "ONLINE").length;

      if (online === 3) setHealth("ok", "all online");
      else if (online > 0) setHealth("warn", online + "/3 online");
      else setHealth("bad", "degraded");

      healthPill.title =
        `Magika: ${c.tier1_magika}\n` +
        `ClamAV: ${c.tier2_clamav}\n` +
        `Qwen 2.5: ${c.tier3_ollama_qwen}\n` +
        `Vault: ${data.vault_active_transfers} active transfer(s)`;
    } catch (e) {
      setHealth("bad", "offline");
      healthPill.title = "Gateway is not responding.";
    }
  }

  healthPill.addEventListener("click", fetchHealth);

  async function fetchNetworkInfo() {
    try {
      const res = await fetch("/network-info", { cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      footUrl.textContent = data.https_url;
    } catch (e) {
      footUrl.textContent = "local gateway";
    }
  }

  fetchHealth();
  fetchNetworkInfo();
  setInterval(fetchHealth, 30000);

  // --- File selection -------------------------------------------------------

  function handleFile(file) {
    if (!file) return;
    selectedFile = file;
    fileName.textContent = file.name;
    fileSize.textContent = formatBytes(file.size);
    show(filebar);
    resetPanels();
    dropzone.classList.remove("hidden");
  }

  function clearFile() {
    if (activeStream) {
      activeStream.abort();
      activeStream = null;
    }
    selectedFile = null;
    fileInput.value = "";
    hide(filebar);
    resetPanels();
    dropzone.classList.remove("hidden");
    setBar(0, "");
    progressTitle.textContent = "Analysing";
    progressCount.textContent = "0 / 6";
    steps.innerHTML = "";
  }

  function openPicker() {
    if (mode === "receive") {
      const empty = pinDigits.find((d) => !d.value);
      if (empty) empty.focus();
      return;
    }
    if (selectedFile) startScan();
    else fileInput.click();
  }

  dropzone.addEventListener("click", openPicker);
  dropzone.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openPicker();
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) handleFile(e.target.files[0]);
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("drag");
  });

  dropzone.addEventListener("dragleave", () => {
    dropzone.classList.remove("drag");
  });

  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
    setMode("send");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  btnClear.addEventListener("click", clearFile);
  btnScan.addEventListener("click", startScan);

  // --- Progress rendering ---------------------------------------------------

  function setBar(percent, tone) {
    barFill.style.width = percent + "%";
    barFill.className = "bar-fill" + (tone ? " " + tone : "");
    bar.setAttribute("aria-valuenow", String(percent));
  }

  function buildSteps(catalog) {
    steps.innerHTML = "";
    catalog.forEach((stage) => {
      const li = document.createElement("li");
      li.className = "step pending";
      li.dataset.key = stage.key;

      const icon = document.createElement("span");
      icon.className = "step-icon";

      const text = document.createElement("div");
      text.className = "step-text";

      const label = document.createElement("p");
      label.className = "step-label";
      label.textContent = stage.label;

      const detail = document.createElement("p");
      detail.className = "step-detail";

      text.appendChild(label);
      text.appendChild(detail);

      const engine = document.createElement("span");
      engine.className = "step-engine";
      engine.textContent = stage.engine;

      li.appendChild(icon);
      li.appendChild(text);
      li.appendChild(engine);
      steps.appendChild(li);
    });
  }

  function updateStep(update) {
    const li = steps.querySelector(`[data-key="${update.key}"]`);
    if (!li) return;

    li.className = "step " + update.status;
    const icon = li.querySelector(".step-icon");
    icon.textContent = STATUS_GLYPH[update.status] || "";

    const detail = li.querySelector(".step-detail");
    detail.textContent = update.detail || "";

    const doneCount = steps.querySelectorAll(
      ".step.done, .step.failed, .step.skipped"
    ).length;

    progressCount.textContent = doneCount + " / " + update.total;

    // Advance only as stages complete, so the bar never jumps backwards.
    const percent = Math.min(
      Math.round((doneCount / update.total) * 100),
      100
    );
    const tone = li.classList.contains("failed") ? "bad"
      : doneCount === update.total ? "ok" : "";
    setBar(percent, tone);
  }

  // --- Streaming scan -------------------------------------------------------

  async function startScan() {
    if (!selectedFile || activeStream) return;

    resetPanels();
    setBar(0, "");
    buildSteps([]);
    show(progress);
    progressTitle.textContent = "Analysing " + selectedFile.name;

    const body = new FormData();
    body.append("file", selectedFile);

    activeStream = new AbortController();

    let receivedResult = false;

    try {
      const res = await fetch("/transfer/stream", {
        method: "POST",
        body: body,
        signal: activeStream.signal
      });

      if (!res.ok || !res.body) {
        throw new Error("Scan failed to start (HTTP " + res.status + ")");
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        // SSE frames are separated by a blank line.
        const frames = buffer.split(/\r?\n\r?\n/);
        buffer = frames.pop() || "";

        for (const frame of frames) {
          const handled = handleFrame(frame);
          if (handled) receivedResult = true;
        }
      }

      if (!receivedResult) {
        throw new Error("The scan ended before returning a verdict.");
      }
    } catch (err) {
      if (err.name === "AbortError") return;
      setBar(100, "bad");
      progressTitle.textContent = "Scan interrupted";
      showResult({
        verdict: "ERROR",
        tone: "bad",
        reason: err.message || "Could not reach the gateway.",
        details: []
      });
    } finally {
      activeStream = null;
    }
  }

  function handleFrame(frame) {
    let event = "message";
    const dataLines = [];

    frame.split(/\r?\n/).forEach((line) => {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
    });

    if (!dataLines.length) return false;

    let payload;
    try {
      payload = JSON.parse(dataLines.join("\n"));
    } catch (e) {
      return false;
    }

    if (event === "stages") {
      buildSteps(payload.stages || []);
    } else if (event === "stage") {
      updateStep(payload);
    } else if (event === "result") {
      finishApproved(payload);
      return true;
    } else if (event === "rejected") {
      finishRejected(payload);
      return true;
    } else if (event === "error") {
      setBar(100, "bad");
      progressTitle.textContent = "Scan failed";
      showResult({
        verdict: "ERROR",
        tone: "bad",
        reason: payload.message || "Triage crashed.",
        details: []
      });
      return true;
    }

    return false;
  }

  // --- Result rendering -----------------------------------------------------

  function showResult({ verdict, tone, reason, details }) {
    verdictBadge.textContent = verdict;
    verdictBadge.className = "verdict" + (tone ? " " + tone : "");
    resultReason.textContent = reason;

    if (details && details.length) {
      facts.innerHTML = "";
      details.forEach(([key, value]) => {
        const dt = document.createElement("dt");
        dt.textContent = key;
        const dd = document.createElement("dd");
        dd.textContent = value;
        facts.appendChild(dt);
        facts.appendChild(dd);
      });
      show(facts);
    } else {
      facts.innerHTML = "";
      hide(facts);
    }

    show(result);
  }

  function verdictTone(verdict) {
    if (verdict === "SAFE" || verdict === "APPROVED") return "ok";
    if (verdict === "SUSPICIOUS" || verdict === "QUARANTINE") return "warn";
    return "bad";
  }

  function describeTriage(triage) {
    if (!triage) return [];
    const fileInfo = triage.file_info || {};
    const rows = [];

    if (fileInfo.actual_type) {
      rows.push([
        "Detected",
        fileInfo.actual_type +
          (fileInfo.confidence ? " (" + fileInfo.confidence + "% confidence)" : "")
      ]);
    }
    if (fileInfo.claimed_extension) rows.push(["Extension", fileInfo.claimed_extension]);
    if (typeof triage.entropy === "number") rows.push(["Entropy", String(triage.entropy)]);

    const imports = (triage.interesting_imports || []).length;
    if (imports) rows.push(["Suspicious APIs", String(imports)]);

    const yara = (triage.yara_matches || []).length;
    if (yara) rows.push(["YARA matches", String(yara)]);

    const indicators = triage.indicators || [];
    if (indicators.length) rows.push(["Indicators", String(indicators.length)]);

    const ai = triage.ai_triage;
    if (ai && ai.verdict && ai.verdict !== "ANALYSIS_ERROR") {
      rows.push(["AI verdict", ai.verdict + " (" + ai.threat_score + "/100)"]);
    }

    return rows;
  }

  function finishApproved(payload) {
    const triage = payload.triage || {};
    progressTitle.textContent = "Scan complete";
    setBar(100, "ok");

    showResult({
      verdict: "APPROVED",
      tone: "ok",
      reason: "Passed every tier. The file is now waiting in the in-memory vault.",
      details: describeTriage(triage)
    });

    pinDisplay.textContent = payload.pin;
    qrImage.src = payload.qr_url;
    copyUrl = payload.receiver_url;
    btnCopyLink.style.display = "";
    btnNewFile.style.display = "";
    show(credential);

    expiryAt = Date.now() + (payload.expires_in_seconds || 300) * 1000;
    startCountdown();

    // Android exclusive badge & vibration feedback
    if ("vibrate" in navigator) {
      try { navigator.vibrate([80, 40, 80]); } catch (_) {}
    }
    if ("setAppBadge" in navigator) {
      try { (navigator as any).setAppBadge(1); } catch (_) {}
    }

    // Trigger persistent internet token generation alongside local relay
    if (distanceLinkInput) {
      distanceLinkInput.value = "Generating long distance link...";
    }
    if (selectedFile) {
      const internetFormData = new FormData();
      internetFormData.append("file", selectedFile);
      fetch("/transfer/internet", {
        method: "POST",
        body: internetFormData
      })
      .then(res => res.json())
      .then(async data => {
        if (data.token) {
          currentToken = data.token;
          // Check if there is an active cloudflare tunnel URL configured on the backend
          let preferredOrigin = window.location.origin;
          try {
            const tunResp = await fetch("/tunnel-url");
            if (tunResp.ok) {
              const tunData = await tunResp.json();
              if (tunData.url) {
                preferredOrigin = tunData.url;
              }
            }
          } catch (_) {}

          currentDownloadUrl = `${preferredOrigin}/download/token/${data.token}`;
          if (distanceLinkInput) {
            distanceLinkInput.value = currentDownloadUrl;
          }
        }
      })
      .catch(err => {
        console.log("Distance transfer token creation:", err);
        if (distanceLinkInput) {
          distanceLinkInput.value = "Unavailable (Check server logs)";
        }
      });
    }
  }

  function finishRejected(payload) {
    progressTitle.textContent = "Scan complete";

    const verdict = payload.verdict || "BLOCKED";
    const indicators = (payload.indicators || []).slice(0, 3);
    const details = [];
    if (payload.stage) details.push(["Blocked at", payload.stage]);
    if (indicators.length) {
      details.push(["Signals", indicators.join("; ")]);
    }

    showResult({
      verdict,
      tone: verdictTone(verdict),
      reason: payload.reason || "Blocked by the security pipeline.",
      details
    });

    show(btnRetry);
  }

  function startCountdown() {
    stopCountdown();
    const tick = () => {
      const left = Math.max(0, Math.floor((expiryAt - Date.now()) / 1000));
      const mins = Math.floor(left / 60);
      const secs = String(left % 60).padStart(2, "0");
      credTimer.textContent = "Expires in " + mins + ":" + secs;

      if (left === 0) {
        stopCountdown();
        credTimer.textContent = "Expired — request a new code";
        pinDisplay.textContent = "------";
      }
    };
    tick();
    countdown = setInterval(tick, 1000);
  }

  function stopCountdown() {
    if (countdown) {
      clearInterval(countdown);
      countdown = null;
    }
  }

  btnRetry.addEventListener("click", clearFile);
  btnNewFile.addEventListener("click", clearFile);

  btnCopyLink.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(copyUrl);
      const original = btnCopyLink.textContent;
      btnCopyLink.textContent = "Copied";
      setTimeout(() => { btnCopyLink.textContent = original; }, 1500);
    } catch (e) {
      window.prompt("Copy this link:", copyUrl);
    }
  });

  // --- Receive --------------------------------------------------------------

  function getEnteredPin() {
    return pinDigits.map((d) => d.value.trim()).join("");
  }

  function refreshDownloadState() {
    btnDownload.disabled = getEnteredPin().length !== 6;
    hide(receiveAlert);
  }

  async function triggerDownload() {
    const pin = getEnteredPin();
    if (pin.length !== 6 || downloading) return;

    downloading = true;
    hide(receiveAlert);
    btnDownload.disabled = true;
    btnDownload.textContent = "Checking code…";

    // Confirm the code is live before navigating away, so an expired PIN
    // produces an inline message instead of a raw JSON error page.
    let status = null;
    try {
      const res = await fetch("/transfer/status/" + pin, { cache: "no-store" });
      status = res.ok ? await res.json() : null;
    } catch (e) {
      status = null;
    }

    if (!status || !status.valid) {
      downloading = false;
      btnDownload.textContent = "Download file";
      refreshDownloadState();
      receiveAlert.textContent = "Invalid or expired code. Ask the sender for a new one.";
      show(receiveAlert);
      return;
    }

    btnDownload.textContent = "Downloading…";
    if ("clearAppBadge" in navigator) {
      try { (navigator as any).clearAppBadge(); } catch (_) {}
    }
    window.location.href = "/download/" + pin;

    setTimeout(() => {
      downloading = false;
      btnDownload.textContent = "Download file";
      refreshDownloadState();
    }, 2000);
  }

  btnDownload.addEventListener("click", triggerDownload);

  pinDigits.forEach((cell, idx) => {
    cell.addEventListener("input", (e) => {
      const digits = e.target.value.replace(/\D/g, "");
      cell.value = digits ? digits[digits.length - 1] : "";
      if (cell.value && idx < 5) pinDigits[idx + 1].focus();
      refreshDownloadState();
    });

    cell.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !cell.value && idx > 0) {
        pinDigits[idx - 1].focus();
      } else if (e.key === "Enter" && getEnteredPin().length === 6) {
        triggerDownload();
      }
    });

    cell.addEventListener("paste", (e: any) => {
      e.preventDefault();
      const clip = e.clipboardData || (window as any).clipboardData;
      const raw = clip
        ? clip.getData("text").replace(/\D/g, "").slice(0, 6)
        : "";
      if (!raw) return;
      for (let i = 0; i < raw.length; i++) {
        if (pinDigits[i]) pinDigits[i].value = raw[i];
      }
      pinDigits[Math.min(raw.length, 5)].focus();
      refreshDownloadState();
    });
  });

  // Copy long distance token link
  if (btnCopyDistanceLink && distanceLinkInput) {
    btnCopyDistanceLink.addEventListener("click", async () => {
      const urlToCopy = distanceLinkInput.value;
      if (!urlToCopy || urlToCopy.includes("...")) return;
      try {
        await navigator.clipboard.writeText(urlToCopy);
        const original = btnCopyDistanceLink.textContent;
        btnCopyDistanceLink.textContent = "Copied!";
        setTimeout(() => { btnCopyDistanceLink.textContent = original; }, 1500);
      } catch (e) {
        window.prompt("Copy long distance link:", urlToCopy);
      }
    });
  }

  // Email delivery button handler
  if (btnSendEmail && recipientEmail) {
    btnSendEmail.addEventListener("click", async () => {
      const email = recipientEmail.value.trim();
      if (!email || !email.includes("@")) {
        alert("Please enter a valid email address.");
        return;
      }

      if (!currentToken) {
        alert("Preparing transfer link... Please try again in a few seconds.");
        return;
      }

      btnSendEmail.textContent = "Sending...";
      btnSendEmail.disabled = true;

      try {
        const resp = await fetch("/transfer/notify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            token: currentToken,
            recipient_email: email,
            sender_name: "ETIPOS User"
          })
        });

        const data = await resp.json();
        if (resp.ok && data.status === "SENT") {
          if (emailNotice) {
            emailNotice.textContent = "✓ Download link sent to " + email;
            emailNotice.style.color = "#3fb950";
            emailNotice.classList.remove("hidden");
          }
          recipientEmail.value = "";
        } else {
          throw new Error(data.detail || "Failed to send email");
        }
      } catch (err) {
        if (emailNotice) {
          emailNotice.textContent = "✕ Error: " + (err.message || "Failed to send");
          emailNotice.style.color = "#f85149";
          emailNotice.classList.remove("hidden");
        }
      } finally {
        btnSendEmail.textContent = "Send Link";
        btnSendEmail.disabled = false;
      }
    });
  }

  // Deep link from the transfer QR: /?pin=123456 or /?token=xyz
  function applyUrlPin() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    if (token) {
      window.location.href = "/download/token/" + token;
      return;
    }

    const pin = (params.get("pin") || "").replace(/\D/g, "").slice(0, 6);
    if (pin.length !== 6) return;
    setMode("receive");
    for (let i = 0; i < 6; i++) {
      if (pinDigits[i]) pinDigits[i].value = pin[i];
    }
    refreshDownloadState();
  }

  applyUrlPin();

  // --- Android Exclusive Security & PWA Features ----------------------------

  // 1. App-Switcher & Privacy Shield (FLAG_SECURE PWA counter-measure)
  // Blurs sensitive credentials/PIN/QR when switched to recent tasks or backgrounded
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      document.body.classList.add("blurred");
    } else {
      document.body.classList.remove("blurred");
    }
  });

  window.addEventListener("blur", () => {
    document.body.classList.add("blurred");
  });
  window.addEventListener("focus", () => {
    document.body.classList.remove("blurred");
  });

  // 2. Android Chrome PWA Install Prompt Banner
  let deferredPrompt: any = null;
  window.addEventListener("beforeinstallprompt", (e: any) => {
    e.preventDefault();
    deferredPrompt = e;
    const dismissed = localStorage.getItem("etipos_pwa_dismissed");
    if (!dismissed && pwaInstallBanner) {
      show(pwaInstallBanner);
    }
  });

  if (btnPwaInstall) {
    btnPwaInstall.addEventListener("click", async () => {
      if (deferredPrompt) {
        deferredPrompt.prompt();
        const choice = await deferredPrompt.userChoice;
        if (choice.outcome === "accepted") {
          console.log("ETIPOS PWA installed");
        }
        deferredPrompt = null;
        if (pwaInstallBanner) hide(pwaInstallBanner);
      }
    });
  }

  if (btnDismissInstall) {
    btnDismissInstall.addEventListener("click", () => {
      if (pwaInstallBanner) hide(pwaInstallBanner);
      localStorage.setItem("etipos_pwa_dismissed", "1");
    });
  }

  // 3. Android WebAuthn Biometric Shield (Fingerprint/Face unlock)
  async function checkBiometricHardware(): Promise<boolean> {
    if (!(window as any).PublicKeyCredential) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (_) {
      return false;
    }
  }

  let biometricVerified = false;
  async function performBiometricGate(): Promise<boolean> {
    const hasBiometrics = await checkBiometricHardware();
    if (!hasBiometrics) {
      return true; // No biometric hardware on device; allow graceful fallback
    }

    try {
      const challenge = new Uint8Array(32);
      window.crypto.getRandomValues(challenge);

      // Request biometric platform verification (Android fingerprint / facial recognition)
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: "ETIPOS Fortress" },
          user: {
            id: new Uint8Array([1, 2, 3, 4]),
            name: "etipos-receiver",
            displayName: "ETIPOS Receiver"
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required"
          },
          timeout: 60000
        }
      });

      return !!credential;
    } catch (err: any) {
      console.warn("Biometric verification canceled or failed:", err);
      return false;
    }
  }

  // Hook into receive panel to show biometric shield if available
  // --- Domain Session OTP Gate ----------------------------------------------
  let portalLocked = false;

  function getEnteredOtp(): string {
    return otpDigits.map((d: any) => d ? d.value.trim() : "").join("");
  }

  function refreshOtpButtonState() {
    if (btnVerifyOtp) {
      btnVerifyOtp.disabled = getEnteredOtp().length !== 6;
    }
  }

  async function checkAuthStatus() {
    try {
      const res = await fetch("/auth/status");
      if (!res.ok) return;
      const data = await res.json();
      if (data.required && !data.authenticated) {
        lockPortal();
      } else {
        unlockPortal();
      }
    } catch (_) {
      // Offline fallback: don't block
    }
  }

  function lockPortal() {
    portalLocked = true;
    if (panelSend) hide(panelSend);
    if (panelReceive) hide(panelReceive);
    if (tabSend) hide(tabSend);
    if (tabReceive) hide(tabReceive);
    if (pwaInstallBanner) hide(pwaInstallBanner);
    if (panelOtpAuth) show(panelOtpAuth);

    const empty = otpDigits.find((d: any) => d && !d.value);
    if (empty) empty.focus();
  }

  function unlockPortal() {
    portalLocked = false;
    if (panelOtpAuth) hide(panelOtpAuth);
    if (tabSend) show(tabSend);
    if (tabReceive) show(tabReceive);
    setMode(mode || "send");
    applyUrlPin();
  }

  async function submitOtp() {
    const otp = getEnteredOtp();
    if (otp.length !== 6) return;
    if (otpAlert) hide(otpAlert);
    if (btnVerifyOtp) {
      btnVerifyOtp.disabled = true;
      btnVerifyOtp.textContent = "Verifying...";
    }

    try {
      const res = await fetch("/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otp })
      });
      if (res.ok) {
        if (btnVerifyOtp) btnVerifyOtp.textContent = "Unlocked ✓";
        setTimeout(() => {
          unlockPortal();
          if (btnVerifyOtp) {
            btnVerifyOtp.textContent = "Unlock Gateway";
            btnVerifyOtp.disabled = false;
          }
        }, 400);
      } else {
        const data = await res.json().catch(() => ({}));
        if (otpAlert) {
          otpAlert.textContent = data.detail || "Invalid OTP code. Please check server terminal.";
          otpAlert.className = "notice bad";
          show(otpAlert);
        }
        if (btnVerifyOtp) {
          btnVerifyOtp.textContent = "Unlock Gateway";
          btnVerifyOtp.disabled = false;
        }
        otpDigits.forEach((c: any) => { if (c) c.value = ""; });
        if (otpDigits[0]) otpDigits[0].focus();
      }
    } catch (e: any) {
      if (otpAlert) {
        otpAlert.textContent = "Connection error while verifying OTP.";
        otpAlert.className = "notice bad";
        show(otpAlert);
      }
      if (btnVerifyOtp) {
        btnVerifyOtp.textContent = "Unlock Gateway";
        btnVerifyOtp.disabled = false;
      }
    }
  }

  otpDigits.forEach((cell: any, idx: number) => {
    if (!cell) return;
    cell.addEventListener("input", (e: any) => {
      cell.value = (cell.value || "").replace(/\D/g, "");
      if (cell.value && idx < 5 && otpDigits[idx + 1]) {
        otpDigits[idx + 1].focus();
      }
      refreshOtpButtonState();
    });

    cell.addEventListener("keydown", (e: any) => {
      if (e.key === "Backspace" && !cell.value && idx > 0 && otpDigits[idx - 1]) {
        otpDigits[idx - 1].focus();
      } else if (e.key === "Enter" && getEnteredOtp().length === 6) {
        submitOtp();
      }
    });

    cell.addEventListener("paste", (e: any) => {
      e.preventDefault();
      const raw = ((e.clipboardData || (window as any).clipboardData).getData("text") || "")
        .replace(/\D/g, "")
        .slice(0, 6);
      for (let i = 0; i < 6; i++) {
        if (otpDigits[i]) otpDigits[i].value = raw[i] || "";
      }
      refreshOtpButtonState();
      if (otpDigits[Math.min(raw.length, 5)]) {
        otpDigits[Math.min(raw.length, 5)].focus();
      }
      if (raw.length === 6) {
        submitOtp();
      }
    });
  });

  if (btnVerifyOtp) {
    btnVerifyOtp.addEventListener("click", submitOtp);
  }

  checkAuthStatus();

  if (btnBiometricAuth) {
    btnBiometricAuth.addEventListener("click", async () => {
      btnBiometricAuth.textContent = "Scanning fingerprint / face...";
      const ok = await performBiometricGate();
      if (ok) {
        biometricVerified = true;
        btnBiometricAuth.textContent = "✓ Biometrics Verified";
        btnBiometricAuth.style.color = "#34d399";
        btnBiometricAuth.style.borderColor = "#34d399";
        (btnBiometricAuth as HTMLButtonElement).disabled = true;
        refreshDownloadState();
      } else {
        btnBiometricAuth.textContent = "Verification Failed — Try Again";
        btnBiometricAuth.style.color = "#f87171";
      }
    });
  }
})();
