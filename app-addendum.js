/* =================================================================
 * MULTI-KIOSK DASHBOARD LOGIC
 * ============================================================== */

function refreshMultiKiosk() {
  const grid = document.getElementById("kiosk-grid");
  if (!grid) return;

  const allProfiles = DB.get("kc_credit_profiles") || [];
  if (allProfiles.length === 0) {
    grid.innerHTML = `<p style="color:var(--text-muted); text-align:center; padding: 20px;">No kiosks found.</p>`;
    return;
  }

  grid.innerHTML = allProfiles.map((p, index) => {
    let loc = "Nansana Main";
    let float = DB.get("kc_wallets").reduce((s, w) => s + (w.current_float || 0), 0);
    let manager = "Collin (You)";
    let status = "normal";
    let statusLabel = "✅ Normal";
    let dataPts = [4, 6, 5, 8, 7, 10, 9];
    
    if (index === 1) {
      loc = "Kyebando Branch";
      float = 850000;
      manager = "Sarah";
      status = "shortage";
      statusLabel = "⚠️ UGX 150K Shortage";
      dataPts = [8, 7, 5, 4, 3, 2, 4];
    } else if (index === 2) {
      loc = "Makindye Branch";
      float = 3200000;
      manager = "John";
      status = "normal";
      statusLabel = "✅ Normal";
      dataPts = [2, 3, 5, 8, 9, 12, 14];
    }

    return `
      <div class="kiosk-card" onclick="openKioskDetail('${loc}', '${statusLabel}', ${float})">
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

  allProfiles.forEach((p, index) => {
    const canvas = document.getElementById(`sparkline-${index}`);
    let dataPts = [4, 6, 5, 8, 7, 10, 9];
    if (index === 1) dataPts = [8, 7, 5, 4, 3, 2, 4];
    if (index === 2) dataPts = [2, 3, 5, 8, 9, 12, 14];
    if (canvas) drawSparkline(canvas, dataPts);
  });
}

function openKioskDetail(name, statusLabel, totalFloat) {
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
      ${statusLabel.includes('Shortage') ? `
        <div class="kd-alert-box">
          <strong>⚠️ Shortage Detected</strong><br>
          System expected UGX 1,000,000 in Capital based on End of Day audit, but agent reported UGX 850,000.
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
  const max = Math.max(...data);
  const step = w / (data.length - 1);
  
  ctx.beginPath();
  ctx.moveTo(0, h - (data[0]/max)*h);
  for(let i=1; i<data.length; i++) {
    ctx.lineTo(i*step, h - (data[i]/max)*h);
  }
  ctx.strokeStyle = '#8B5CF6';
  ctx.lineWidth = 2;
  ctx.stroke();
}

// Hook up the Control Panel button and Role restrictions
document.addEventListener("DOMContentLoaded", () => {
  const btnSeed = document.getElementById("btn-seed-kiosks");
  if (btnSeed) {
    btnSeed.addEventListener("click", () => {
      const profiles = DB.get("kc_credit_profiles") || [];
      if (profiles.length === 1) {
        profiles.push({ id: DB.generateUUID(), kiosk_id: "kyebando-1", kiosk_stability_score: 45 });
        profiles.push({ id: DB.generateUUID(), kiosk_id: "makindye-1", kiosk_stability_score: 95 });
        DB.set("kc_credit_profiles", profiles);
        showToast("Seeded 2 remote kiosks for demo", "success");
        if (Nav.getCurrent() === "multi-kiosk") refreshMultiKiosk();
      }
    });
  }

  // Handle worker role restrictions dynamically
  const origRoleSwitch = document.getElementById("role-worker");
  if (origRoleSwitch) {
    origRoleSwitch.addEventListener("change", () => {
      const navMulti = document.getElementById("nav-multi-kiosk");
      if (navMulti) navMulti.style.display = "none";
    });
  }
  const origRoleOwner = document.getElementById("role-owner");
  if (origRoleOwner) {
    origRoleOwner.addEventListener("change", () => {
      const navMulti = document.getElementById("nav-multi-kiosk");
      if (navMulti) navMulti.style.display = "flex";
    });
  }

  // Initial hiding if already worker
  const role = (DB.get("kc_config") || {}).role || "owner";
  const navMulti = document.getElementById("nav-multi-kiosk");
  if (navMulti) {
    navMulti.style.display = role === "worker" ? "none" : "flex";
  }
});
