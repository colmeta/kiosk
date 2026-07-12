/* =================================================================
 * MULTI-KIOSK DASHBOARD LOGIC
 * ============================================================== */

async function refreshMultiKiosk() {
  const grid = document.getElementById("kiosk-grid");
  if (!grid) return;

  const allProfiles = await DB.get("kc_credit_profiles") || [];
  const wallets = await DB.get("kc_wallets") || [];
  const kiosks = await DB.get("kc_kiosks") || [];
  const config = await DB.get("kc_config") || {};

  if (allProfiles.length === 0) {
    grid.innerHTML = `
      <div style="text-align:center; padding: 40px 20px; color:var(--text-muted);">
        <span class="material-icons-outlined" style="font-size:48px; opacity:0.4;">storefront</span>
        <p style="margin-top:12px;">No kiosks registered yet.</p>
        <p style="font-size:0.85rem; opacity:0.7;">Kiosks will appear here as transaction data is captured.</p>
      </div>`;
    return;
  }

  grid.innerHTML = allProfiles.map((profile, index) => {
    // Find matching kiosk for this profile
    const kiosk = kiosks.find(k => k.id === profile.kiosk_id) || {};
    const loc = kiosk.name || config.business_name || `Kiosk ${index + 1}`;
    const manager = kiosk.manager || (index === 0 ? (config.agent_name || "You") : "—");

    // Calculate actual float from wallets linked to this kiosk
    const kioskWallets = wallets.filter(w => w.kiosk_id === profile.kiosk_id);
    const float = kioskWallets.length > 0
      ? kioskWallets.reduce((s, w) => s + (w.current_float || 0), 0)
      : wallets.reduce((s, w) => s + (w.current_float || 0), 0);

    // Determine status from KSS score
    const kss = profile.kiosk_stability_score || 0;
    let status = "normal";
    let statusLabel = "✅ Normal";
    if (kss < 40) {
      status = "shortage";
      statusLabel = "⚠️ Needs Attention";
    } else if (kss < 60) {
      status = "warning";
      statusLabel = "⚡ Fair";
    }

    return `
      <div class="kiosk-card" onclick="openKioskDetail('${loc.replace(/'/g, "\\'")}', '${statusLabel.replace(/'/g, "\\'")}', ${float})">
        <div class="kiosk-header">
          <div class="kiosk-info">
            <h3>${loc}</h3>
            <span class="kiosk-manager">Manager: ${manager}</span>
          </div>
          <div class="kiosk-status-badge ${status}">${statusLabel}</div>
        </div>
        <div class="kiosk-metrics">
          <div class="kiosk-metric-block">
            <span class="kiosk-metric-label">Total Capital</span>
            <span class="kiosk-metric-value">${formatUGX(float)}</span>
          </div>
          <div class="kiosk-sparkline-container">
            <canvas id="sparkline-${index}" class="kiosk-sparkline"></canvas>
          </div>
        </div>
      </div>
    `;
  }).join("");

  // Draw sparklines from real transaction data
  allProfiles.forEach((profile, index) => {
    const canvas = document.getElementById(`sparkline-${index}`);
    if (!canvas) return;
    const txns = await DB.get("kc_transactions") || [];
    const profileTxns = txns.filter(t => {
      const w = wallets.find(w2 => w2.id === t.wallet_id);
      return w && w.kiosk_id === profile.kiosk_id;
    });
    // Build 7-day transaction count series
    const dataPts = [];
    const now = new Date();
    for (let d = 6; d >= 0; d--) {
      const day = new Date(now);
      day.setDate(day.getDate() - d);
      const dayStr = day.toISOString().slice(0, 10);
      const count = profileTxns.filter(t => t.timestamp && t.timestamp.startsWith(dayStr)).length;
      dataPts.push(count);
    }
    drawSparkline(canvas, dataPts);
  });
}

async function openKioskDetail(name, statusLabel, totalFloat) {
  const modal = document.getElementById("modal-kiosk-detail");
  const title = document.getElementById("modal-kiosk-name");
  const body = document.getElementById("modal-kiosk-body");

  if (modal && title && body) {
    title.textContent = name;
    body.innerHTML = `
      <div class="kd-stat-row">
        <span class="kd-label">MTN Float</span>
        <span class="kd-value">${formatUGX(totalFloat * 0.6)}</span>
      </div>
      <div class="kd-stat-row">
        <span class="kd-label">Airtel Float</span>
        <span class="kd-value">${formatUGX(totalFloat * 0.3)}</span>
      </div>
      <div class="kd-stat-row">
        <span class="kd-label">Cash in Drawer</span>
        <span class="kd-value">${formatUGX(totalFloat * 0.1)}</span>
      </div>
      ${statusLabel.includes('Attention') ? `
        <div class="kd-alert-box">
          <strong>⚠️ Low Stability Score</strong><br>
          This kiosk's stability score is below threshold. Check float levels and reconciliation status.
        </div>
      ` : ''}
    `;
    modal.hidden = false;
  }
}

function drawSparkline(canvas, data) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width = canvas.offsetWidth;
  const h = canvas.height = canvas.offsetHeight;

  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...data, 1);
  const step = w / (data.length - 1 || 1);

  ctx.beginPath();
  ctx.moveTo(0, h - (data[0]/max)*h);
  for(let i=1; i<data.length; i++) {
    ctx.lineTo(i*step, h - (data[i]/max)*h);
  }
  ctx.strokeStyle = '#8B5CF6';
  ctx.lineWidth = 2;
  ctx.stroke();
}

// Role-based visibility for multi-kiosk nav
document.addEventListener("DOMContentLoaded", async () => {
  const role = (await DB.get("kc_config") || {}).role || "owner";
  const navMulti = document.getElementById("nav-multi-kiosk");
  if (navMulti) {
    navMulti.style.display = role === "worker" ? "none" : "flex";
  }
});
