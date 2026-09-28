(function () {
  "use strict";

  // Navigation & Mode Controls
  const navSend = document.getElementById("navSend");
  const navReceive = document.getElementById("navReceive");
  const modeIndicator = document.getElementById("modeIndicator");
  const modeAltIndicator = document.getElementById("modeAltIndicator");
  const cardToggleReceive = document.getElementById("cardToggleReceive");
  const cardToggleSend = document.getElementById("cardToggleSend");
  const heroActionBtn = document.getElementById("heroActionBtn");
  const heroActionText = document.getElementById("heroActionText");

  // Center Workbench Card Elements
  const centerWorkspaceCard = document.getElementById("centerWorkspaceCard");
  const centerCardLabel = document.getElementById("centerCardLabel");
  const centerCardTitle = document.getElementById("centerCardTitle");
  const centerCardDesc = document.getElementById("centerCardDesc");
  const btnSelectFile = document.getElementById("btnSelectFile");
  const btnSelectText = document.getElementById("btnSelectText");
  const btnCircleAction = document.getElementById("btnCircleAction");
  const fileInput = document.getElementById("fileInput");

  // Bento Inverted Card
  const bentoInvertedTitle = document.getElementById("bentoInvertedTitle");
  const bentoInvertedBody = document.getElementById("bentoInvertedBody");

  // Feature Card (Right Column: PIN & QR / Receive)
  const featureTitle = document.getElementById("featureTitle");
  const featureCaption = document.getElementById("featureCaption");
  const featureDefaultView = document.getElementById("featureDefaultView");
  const featureReceiveView = document.getElementById("featureReceiveView");
  const qrImage = document.getElementById("qrImage");
  const pinDisplay = document.getElementById("pinDisplay");
  const btnCopyCredential = document.getElementById("btnCopyCredential");

  // Receive PIN Digits
  const pinDigits = [
    document.getElementById("d1"),
    document.getElementById("d2"),
    document.getElementById("d3"),
    document.getElementById("d4"),
    document.getElementById("d5"),
    document.getElementById("d6"),
  ];
  const btnDownloadTrigger = document.getElementById("btnDownloadTrigger");
  const receiveAlert = document.getElementById("receiveAlert");

  // Health Dots
  const magikaTagDot = document.getElementById("magikaTagDot");
  const clamTagDot = document.getElementById("clamTagDot");
  const aiTagDot = document.getElementById("aiTagDot");

  let currentMode = "send"; // 'send' or 'receive'
  let selectedFile = null;
  let activeTransferData = null;

  // Format Bytes Utility
  function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
  }

  // Switch Mode Handler
  function setMode(mode) {
    currentMode = mode;
    if (mode === "send") {
      navSend.classList.add("active");
      navReceive.classList.remove("active");
      modeIndicator.className = "active";
      modeAltIndicator.className = "";
      heroActionText.textContent = "Send file";

      // Reset Center Card to Send state
      centerCardLabel.textContent = "EPHEMERAL GATEWAY";
      if (!selectedFile) {
        centerCardTitle.textContent = "The simplest transfer is Wi-Fi + etipos";
        centerCardDesc.textContent = "Drag & drop any document or binary to inspect byte signatures and stream safely across local devices.";
        btnSelectText.textContent = "Select file";
      }

      bentoInvertedTitle.textContent = "Multi-Tier Triage";
      bentoInvertedBody.textContent = "Deep content-type validation with Magika neural classifier / Multi-signature scanning with ClamAV / Local LLM analysis with Qwen 2.5 Coder";

      featureDefaultView.classList.remove("hidden");
      featureReceiveView.classList.add("hidden");
      featureTitle.textContent = activeTransferData ? "Transfer Approved" : "Ready to transfer";
    } else {
      navReceive.classList.add("active");
      navSend.classList.remove("active");
      modeIndicator.className = "";
      modeAltIndicator.className = "active";
      heroActionText.textContent = "Receive file";

      centerCardLabel.textContent = "EPHEMERAL RETRIEVAL";
      centerCardTitle.textContent = "Instant Local Download";
      centerCardDesc.textContent = "Input the 6-digit access code from Phone A to download the verified file directly into memory.";
      btnSelectText.textContent = "Enter PIN →";

      bentoInvertedTitle.textContent = "Memory Vault";
      bentoInvertedBody.textContent = "Payloads are retrieved directly from RAM and expunged automatically from the gateway as soon as download completes.";

      featureDefaultView.classList.add("hidden");
      featureReceiveView.classList.remove("hidden");
      featureTitle.textContent = "Enter PIN";

      // Focus first empty digit
      const empty = pinDigits.find((d) => !d.value);
      if (empty) empty.focus();
    }
  }

  navSend.addEventListener("click", () => setMode("send"));
  navReceive.addEventListener("click", () => setMode("receive"));
  cardToggleReceive.addEventListener("click", () => setMode("receive"));
  cardToggleSend.addEventListener("click", () => setMode("send"));
  heroActionBtn.addEventListener("click", () => {
    if (currentMode === "send") {
      fileInput.click();
    } else {
      const empty = pinDigits.find((d) => !d.value);
      if (empty) empty.focus();
    }
  });

  // Check Health on Startup
  async function fetchHealth() {
    try {
      const res = await fetch("/health");
      if (!res.ok) return;
      const data = await res.json();
      if (data.components) {
        if (magikaTagDot) {
          magikaTagDot.style.background = data.components.tier1_magika === "ONLINE" ? "#34d399" : "#f59e0b";
        }
        if (clamTagDot) {
          clamTagDot.style.background = data.components.tier2_clamav === "ONLINE" ? "#34d399" : "#f59e0b";
        }
        if (aiTagDot) {
          aiTagDot.style.background = data.components.tier3_ollama_qwen === "ONLINE" ? "#34d399" : "#f59e0b";
        }
      }
    } catch (e) {
      // Offline fallback
    }
  }
  fetchHealth();

  // File Selection
  function handleFileSelected(file) {
    if (!file) return;
    selectedFile = file;
    centerCardLabel.textContent = "PAYLOAD READY FOR TRIAGE";
    centerCardTitle.textContent = file.name;
    centerCardDesc.textContent = `Size: ${formatBytes(file.size)} • Click below to execute 3-tier inspection and generate transfer credential.`;
    btnSelectText.textContent = "Inspect & Transfer";
  }

  btnSelectFile.addEventListener("click", () => {
    if (currentMode === "receive") {
      const empty = pinDigits.find((d) => !d.value);
      if (empty) empty.focus();
      return;
    }
    if (!selectedFile) {
      fileInput.click();
    } else {
      executeTransfer();
    }
  });

  btnCircleAction.addEventListener("click", () => {
    if (currentMode === "send") fileInput.click();
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelected(e.target.files[0]);
    }
  });

  // Drag & Drop on Center Card
  centerWorkspaceCard.addEventListener("dragover", (e) => {
    e.preventDefault();
    centerWorkspaceCard.style.borderColor = "rgba(255, 255, 255, 0.4)";
  });

  centerWorkspaceCard.addEventListener("dragleave", (e) => {
    e.preventDefault();
    centerWorkspaceCard.style.borderColor = "";
  });

  centerWorkspaceCard.addEventListener("drop", (e) => {
    e.preventDefault();
    centerWorkspaceCard.style.borderColor = "";
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setMode("send");
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  // Execute Transfer
  async function executeTransfer() {
    if (!selectedFile) return;

    btnSelectFile.disabled = true;
    btnSelectText.textContent = "Inspecting...";
    centerCardDesc.textContent = "Running Tier 1 (Magika) → Tier 2 (ClamAV) → Tier 3 (Qwen AI Triage)...";

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const res = await fetch("/transfer", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();

      if (res.ok && data.status === "APPROVED") {
        activeTransferData = data;
        centerCardTitle.textContent = "Transfer Approved";
        centerCardDesc.textContent = `File passed all security checks. Transfer PIN: ${data.pin}. Ephemeral TTL: 5 minutes.`;
        btnSelectText.textContent = "Transfer Another";
        selectedFile = null;

        // Update Right Feature Box
        featureTitle.textContent = "Transfer Approved";
        pinDisplay.textContent = data.pin;
        qrImage.src = data.qr_url;
        featureCaption.textContent = "Scan with phone camera or enter PIN on receiver";

        btnCopyCredential.style.display = "inline-flex";
        btnCopyCredential.onclick = () => {
          navigator.clipboard.writeText(data.receiver_url).then(() => {
            btnCopyCredential.innerHTML = "<span>Copied!</span><span>✓</span>";
            setTimeout(() => {
              btnCopyCredential.innerHTML = "<span>Copy Link</span><span>↗</span>";
            }, 1500);
          });
        };
      } else {
        const reason = (data.detail && (data.detail.reason || data.detail.message)) || "File rejected by security engine.";
        centerCardTitle.textContent = "Transfer Blocked";
        centerCardDesc.textContent = reason;
        btnSelectText.textContent = "Choose Different File";
        selectedFile = null;
      }
    } catch (err) {
      centerCardTitle.textContent = "Transfer Error";
      centerCardDesc.textContent = err.message || "Failed to reach gateway.";
      btnSelectText.textContent = "Retry";
    } finally {
      btnSelectFile.disabled = false;
    }
  }

  // Receive PIN Digits Handler
  function getEnteredPin() {
    return pinDigits.map((d) => d.value.trim()).join("");
  }

  function updateDownloadState() {
    const pin = getEnteredPin();
    btnDownloadTrigger.disabled = pin.length !== 6;
  }

  pinDigits.forEach((digit, idx) => {
    digit.addEventListener("input", (e) => {
      const val = e.target.value.replace(/\D/g, "");
      digit.value = val ? val[val.length - 1] : "";
      if (val && idx < 5) {
        pinDigits[idx + 1].focus();
      }
      updateDownloadState();
    });

    digit.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !digit.value && idx > 0) {
        pinDigits[idx - 1].focus();
      } else if (e.key === "Enter" && getEnteredPin().length === 6) {
        triggerDownload();
      }
    });

    digit.addEventListener("paste", (e) => {
      e.preventDefault();
      const pasteText = (e.clipboardData || window.clipboardData)
        .getData("text")
        .replace(/\D/g, "")
        .slice(0, 6);
      if (pasteText) {
        for (let i = 0; i < pasteText.length; i++) {
          if (pinDigits[i]) pinDigits[i].value = pasteText[i];
        }
        const next = Math.min(pasteText.length, 5);
        pinDigits[next].focus();
        updateDownloadState();
      }
    });
  });

  // Trigger Download
  function triggerDownload() {
    const pin = getEnteredPin();
    if (pin.length !== 6) return;

    receiveAlert.classList.add("hidden");
    btnDownloadTrigger.disabled = true;
    btnDownloadTrigger.innerHTML = "<span>Retrieving...</span><span>↓</span>";

    window.location.href = `/download/${pin}`;

    setTimeout(() => {
      btnDownloadTrigger.disabled = false;
      btnDownloadTrigger.innerHTML = "<span>Download file</span><span>↓</span>";
    }, 2500);
  }

  btnDownloadTrigger.addEventListener("click", triggerDownload);

  // Check URL query parameters (e.g., ?pin=123456 from QR code)
  function handleUrlParams() {
    const params = new URLSearchParams(window.location.search);
    const pin = params.get("pin");
    if (pin && pin.length === 6) {
      setMode("receive");
      for (let i = 0; i < 6; i++) {
        if (pinDigits[i]) pinDigits[i].value = pin[i];
      }
      updateDownloadState();
    }
  }
  handleUrlParams();
})();