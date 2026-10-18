const list = document.getElementById("list");

function renderUrls() {
  chrome.storage.local.get({ __monitoredUrls: [] }, ({ __monitoredUrls }) => {
    const el = document.getElementById("urls");
    if (!el) return;
    if (__monitoredUrls.length) {
      const cleanList = __monitoredUrls
        .map((p) => p.replace(/^https?:\/\//, "").replace(/\/\*$/, ""))
        .filter((v, i, a) => a.indexOf(v) === i);
      const display = cleanList.slice(0, 3).join(", ");
      const extra = cleanList.length > 3 ? ` +${cleanList.length - 3} more` : "";
      el.innerHTML = `<strong>Monitoring:</strong> ${display}${extra}`;
    } else {
      el.innerHTML = `<strong>Monitoring:</strong> <em>Connecting to console…</em>`;
    }
  });
}

function renderIdentity() {
  const el = document.getElementById("identity");
  if (!el) return;
  chrome.storage.managed.get(["deviceLabel", "employeeId"]).catch(() => ({})).then((managed) => {
    const parts = [];
    if (managed?.employeeId) parts.push(`ID: ${managed.employeeId}`);
    if (managed?.deviceLabel) parts.push(`Device: ${managed.deviceLabel}`);
    el.innerHTML = parts.length
      ? `<strong>Assigned to:</strong> ${parts.join(" · ")}`
      : `<strong>Identity:</strong> Client IP captured automatically by relay server.`;
  });
}

function render() {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    if (!logs || !logs.length) {
      list.innerHTML = `
        <div class="empty-state">
          <div class="empty-title">Protection Active</div>
          <div class="empty-desc">No sensitive PII incidents recorded on this device.</div>
        </div>`;
      return;
    }
    list.innerHTML = "";
    for (const l of logs) {
      const d = document.createElement("div");
      d.className = "row";
      
      const tags = (l.findings || []).map((f) => 
        `<span class="tag">${f.type}</span><span class="masked">${f.masked}</span>`
      ).join(" ");
      
      const time = new Date(l.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const action = l.action || "BLOCKED";
      const badgeClass = action === "PASTE_BLOCKED" ? "badge-paste" : (action === "DROP_BLOCKED" ? "badge-drop" : (action === "MONITORED" ? "badge-monitored" : "badge-blocked"));

      d.innerHTML = `
        <div class="row-header">
          <span class="row-site">${l.site || "unknown site"}</span>
          <span class="badge ${badgeClass}">${action}</span>
          <span class="row-time">${time}</span>
        </div>
        <div class="tags-row">${tags}</div>
      `;
      list.appendChild(d);
    }
  });
}

// document.getElementById("clear")?.addEventListener("click", () => {
//   chrome.storage.local.set({ logs: [] }, render);
// });

// document.getElementById("export")?.addEventListener("click", () => {
//   chrome.storage.local.get({ logs: [] }, ({ logs }) => {
//     const url = URL.createObjectURL(new Blob([JSON.stringify(logs, null, 2)], { type: "application/json" }));
//     const a = Object.assign(document.createElement("a"), { href: url, download: `aipii-guard-logs-${Date.now()}.json` });
//     a.click();
//   });
// });

// render();
// renderUrls();
// renderIdentity();

document.getElementById("clear").onclick = () => chrome.storage.local.set({ logs: [] }, render);
document.getElementById("export").onclick = () => {
  chrome.storage.local.get({ logs: [] }, ({ logs }) => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(logs, null, 2)], { type: "application/json" }));
    const a = Object.assign(document.createElement("a"), { href: url, download: `aipii-guard-logs-${Date.now()}.json` });
    a.click();
  });
};

render();
renderUrls();
renderIdentity();
