/* ============================================================================
 * KioskControl UG — Mobile Money Business Operating System v2.0
 * Complete Offline-First PWA Logic Engine
 * ============================================================================
 * Modules:
 *   1. DB           – localStorage wrapper with JSON serialisation
 *   2. Parser       – Regex-based MTN / Airtel SMS parser
 *   3. Security     – Three-layer fraud detection
 *   4. Tariff       – Fee / commission calculator
 *   5. KSS          – Kiosk Stability Score engine
 *   6. AIReconciler – Smart discrepancy diagnosis
 *   7. Nav          – Screen navigation controller
 *   8. App          – Initialisation & lifecycle
 *   9. Handlers     – All UI event handlers
 *  10. Utilities    – Formatting, toasts, status-bar clock
 *  11. Seeder       – 30-day historical data generator
 *  12. Analytics    – Canvas chart rendering engine
 * ========================================================================= */

"use strict";

/* ──────────────────────────────────────────────────────────────────────────────
 * 1. DATABASE MODULE
 * ────────────────────────────────────────────────────────────────────────── */

const DB = (() => {
  const KEYS = [
    "kc_kiosks",
    "kc_wallets",
    "kc_transactions",
    "kc_money_outside",
    "kc_credit_profiles",
    "kc_config",
    "kc_consent_log",
  ];

  /** Retrieve a parsed value from localStorage. Returns [] for missing arrays. */
  function get(key) {
    try {
      const raw = localStorage.getItem(key);
      if (raw === null) return key === "kc_config" ? null : [];
      return JSON.parse(raw);
    } catch (_) {
      return key === "kc_config" ? null : [];
    }
  }

  /** Persist a value (object or array) under the given key. */
  function set(key, data) {
    localStorage.setItem(key, JSON.stringify(data));
  }

  /** RFC-4122 v4 UUID generator (crypto-safe when available). */
  function generateUUID() {
    if (
      typeof crypto !== "undefined" &&
      typeof crypto.randomUUID === "function"
    ) {
      return crypto.randomUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        const r = (Math.random() * 16) | 0;
        const v = c === "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }
    );
  }

  /** Nuke every kc_ key from localStorage. */
  function reset() {
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && k.startsWith("kc_")) toRemove.push(k);
    }
    toRemove.forEach((k) => localStorage.removeItem(k));
  }

  /** Export the complete dataset as a Base-64 encoded JSON string. */
  function exportData() {
    const payload = {};
    KEYS.forEach((k) => {
      const v = localStorage.getItem(k);
      if (v !== null) payload[k] = JSON.parse(v);
    });
    return btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
  }

  /** Restore a Base-64 encoded backup. */
  function importData(b64) {
    try {
      const json = decodeURIComponent(escape(atob(b64)));
      const payload = JSON.parse(json);
      Object.keys(payload).forEach((k) => {
        localStorage.setItem(k, JSON.stringify(payload[k]));
      });
      return true;
    } catch (_) {
      return false;
    }
  }

  return {
    get,
    set,
    generateUUID,
    reset,
    export: exportData,
    import: importData,
  };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 2. SMS PARSER MODULE
 * ────────────────────────────────────────────────────────────────────────── */

const Parser = (() => {
  /**
   * Helper: strip commas from amount strings and return a number.
   * e.g. "1,500,000" → 1500000
   */
  function parseAmt(s) {
    return Number(String(s).replace(/,/g, ""));
  }

  /* ---------- regex patterns ---------- */

  // MTN Deposit
  const MTN_DEP =
    /You have received UGX ([\d,]+) from ([\d+]+)\.\s*New balance:\s*UGX ([\d,]+)\./i;

  // MTN Withdrawal (commission variant)
  const MTN_WD_COMM =
    /Withdrawn UGX ([\d,]+) from ([\d+]+)\.\s*Commission earned:\s*UGX ([\d,]+)\.\s*New balance:\s*UGX ([\d,]+)\./i;

  // MTN Withdrawal alt (fee/sent variant)
  const MTN_WD_FEE =
    /You have sent UGX ([\d,]+) to ([\d+]+)\.\s*Fee charged:\s*UGX ([\d,]+)\.\s*New balance:\s*UGX ([\d,]+)\./i;

  // Airtel Deposit
  const AIR_DEP =
    /You have received UGX ([\d,]+) from ([\d+]+)\.\s*Your Airtel Money balance is UGX ([\d,]+)\./i;

  // Airtel Withdrawal
  const AIR_WD =
    /Cash Out of UGX ([\d,]+) to ([\d+]+) completed\.\s*Charge:\s*UGX ([\d,]+)\.\s*Balance:\s*UGX ([\d,]+)\./i;

  // Commission notification
  const COMMISSION =
    /Commission of UGX ([\d,]+) earned on transaction ([A-Za-z0-9]+)\.\s*Total commission:\s*UGX ([\d,]+)\./i;

  /**
   * Parse a raw SMS text and return a structured result.
   * @param {string} text   - The SMS body
   * @param {string} sender - The sender ID or phone number
   */
  function parse(text, sender) {
    let m;

    // 1. MTN Deposit
    if ((m = MTN_DEP.exec(text))) {
      return {
        success: true,
        type: "Deposit",
        network: "MTN",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        balance: parseAmt(m[3]),
        commission: 0,
        fee: 0,
        raw: text,
      };
    }

    // 2. MTN Withdrawal (commission)
    if ((m = MTN_WD_COMM.exec(text))) {
      return {
        success: true,
        type: "Withdrawal",
        network: "MTN",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        commission: parseAmt(m[3]),
        balance: parseAmt(m[4]),
        fee: 0,
        raw: text,
      };
    }

    // 3. MTN Withdrawal alt (fee)
    if ((m = MTN_WD_FEE.exec(text))) {
      return {
        success: true,
        type: "Withdrawal",
        network: "MTN",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        fee: parseAmt(m[3]),
        balance: parseAmt(m[4]),
        commission: 0,
        raw: text,
      };
    }

    // 4. Airtel Deposit
    if ((m = AIR_DEP.exec(text))) {
      return {
        success: true,
        type: "Deposit",
        network: "Airtel",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        balance: parseAmt(m[3]),
        commission: 0,
        fee: 0,
        raw: text,
      };
    }

    // 5. Airtel Withdrawal
    if ((m = AIR_WD.exec(text))) {
      return {
        success: true,
        type: "Withdrawal",
        network: "Airtel",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        fee: parseAmt(m[3]),
        balance: parseAmt(m[4]),
        commission: 0,
        raw: text,
      };
    }

    // 6. Commission notification
    if ((m = COMMISSION.exec(text))) {
      return {
        success: true,
        type: "Commission",
        network: sender === "AirtelMoney" ? "Airtel" : "MTN",
        amount: parseAmt(m[1]),
        balance: parseAmt(m[3]),
        counterparty: m[2],
        commission: parseAmt(m[1]),
        fee: 0,
        raw: text,
      };
    }

    // No pattern matched
    return { success: false, raw: text };
  }

  /** Expose all compiled regex patterns for Security module. */
  const ALL_PATTERNS = [
    MTN_DEP,
    MTN_WD_COMM,
    MTN_WD_FEE,
    AIR_DEP,
    AIR_WD,
    COMMISSION,
  ];

  return { parse, ALL_PATTERNS };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 3. SECURITY MODULE — Three-Layer Fraud Detection
 * ────────────────────────────────────────────────────────────────────────── */

const Security = (() => {
  const VALID_SENDERS = [
    "mobilemoney",
    "mtn",
    "airtel",
    "airtelmoney",
    "momo",
  ];
  const SPAM_WORDS = ["promo", "win", "free", "congratulations", "prize", "claim"];

  /**
   * Layer 1 — Sender ID validation.
   * A phone-number sender or one containing spam keywords is rejected.
   */
  function checkSender(sender) {
    const lower = (sender || "").toLowerCase().trim();
    if (/^[+0]\d{9,}$/.test(lower.replace(/[\s-]/g, ""))) {
      return {
        valid: false,
        reason: "Sender is a phone number — likely spoofed",
      };
    }
    for (const w of SPAM_WORDS) {
      if (lower.includes(w))
        return { valid: false, reason: `Sender contains suspicious word "${w}"` };
    }
    if (!VALID_SENDERS.includes(lower)) {
      return {
        valid: false,
        reason: `Unknown sender "${sender}". Expected a carrier ID.`,
      };
    }
    return { valid: true, reason: "Sender recognised" };
  }

  /**
   * Layer 2 — Balance math verification.
   * Deposits should add, withdrawals should subtract.
   */
  function checkBalance(parsedAmount, parsedNewBalance, currentKnownBalance, transactionType) {
    if (currentKnownBalance === null || currentKnownBalance === undefined) {
      return { valid: true, reason: "No prior balance to compare" };
    }
    let expected;
    if (transactionType === "Deposit") {
      expected = currentKnownBalance + parsedAmount;
    } else if (transactionType === "Withdrawal") {
      expected = currentKnownBalance - parsedAmount;
    } else {
      return { valid: true, reason: "Non-float transaction type" };
    }
    if (Math.abs(expected - parsedNewBalance) > 500) {
      return {
        valid: false,
        reason: `Balance mismatch — expected ${expected}, got ${parsedNewBalance}`,
        expected,
        got: parsedNewBalance,
      };
    }
    return { valid: true, reason: "Balance math checks out" };
  }

  /**
   * Layer 3 — Message structure validation.
   * If the text contains financial keywords but matches no known pattern, flag it.
   */
  function checkStructure(text) {
    const hasFinancialKeyword =
      /UGX|balance|received|withdrawn|cash out|commission/i.test(text);
    const matchesKnownPattern = Parser.ALL_PATTERNS.some((rx) => rx.test(text));

    if (hasFinancialKeyword && !matchesKnownPattern) {
      return {
        valid: false,
        reason: "Message contains financial keywords but format is unrecognised",
      };
    }
    return { valid: true, reason: "Structure OK" };
  }

  /**
   * Master validation: runs all three layers.
   */
  function validate(text, sender, currentBalance) {
    const flags = [];
    let severity = "safe";
    let safe = true;

    // Layer 1
    const s1 = checkSender(sender);
    if (!s1.valid) {
      flags.push({ layer: "sender", ...s1 });
      severity = "critical";
      safe = false;
    }

    // Layer 3 (run before Layer 2 because we need a parse to get amount/balance)
    const s3 = checkStructure(text);
    if (!s3.valid) {
      flags.push({ layer: "structure", ...s3 });
      if (severity !== "critical") severity = "warning";
      safe = false;
    }

    // Attempt parse for Layer 2
    const parsed = Parser.parse(text, sender);
    if (parsed.success && currentBalance !== null && currentBalance !== undefined) {
      const s2 = checkBalance(
        parsed.amount,
        parsed.balance,
        currentBalance,
        parsed.type
      );
      if (!s2.valid) {
        flags.push({ layer: "balance", ...s2 });
        if (severity !== "critical") severity = "warning";
        safe = false;
      }
    }

    return { safe, flags, severity };
  }

  return { checkSender, checkBalance, checkStructure, validate };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 4. TARIFF CALCULATOR MODULE
 * ────────────────────────────────────────────────────────────────────────── */

const DEFAULT_TARIFFS = {
  MTN: {
    Withdrawal: [
      { min: 500,     max: 2500,    fee: 330  },
      { min: 2501,    max: 5000,    fee: 440  },
      { min: 5001,    max: 15000,   fee: 700  },
      { min: 15001,   max: 30000,   fee: 880  },
      { min: 30001,   max: 45000,   fee: 1050 },
      { min: 45001,   max: 60000,   fee: 1300 },
      { min: 60001,   max: 125000,  fee: 1700 },
      { min: 125001,  max: 250000,  fee: 2500 },
      { min: 250001,  max: 500000,  fee: 3500 },
      { min: 500001,  max: 1000000, fee: 5500 },
      { min: 1000001, max: 3000000, fee: 9000 },
      { min: 3000001, max: 5000000, fee: 13500 },
      { min: 5000001, max: 7000000, fee: 16500 },
    ],
    Deposit: [{ min: 500, max: 5000000, fee: 0 }],
  },
  Airtel: {
    Withdrawal: [
      { min: 500,     max: 2500,    fee: 300  },
      { min: 2501,    max: 5000,    fee: 400  },
      { min: 5001,    max: 15000,   fee: 650  },
      { min: 15001,   max: 30000,   fee: 850  },
      { min: 30001,   max: 45000,   fee: 1000 },
      { min: 45001,   max: 60000,   fee: 1250 },
      { min: 60001,   max: 125000,  fee: 1600 },
      { min: 125001,  max: 250000,  fee: 2400 },
      { min: 250001,  max: 500000,  fee: 3400 },
      { min: 500001,  max: 1000000, fee: 5300 },
      { min: 1000001, max: 3000000, fee: 8500 },
      { min: 3000001, max: 5000000, fee: 13000 },
    ],
    Deposit: [{ min: 500, max: 5000000, fee: 0 }],
  },
};

const Tariff = (() => {
  /**
   * Look up the tariff fee for a given amount, network and transaction type.
   */
  function calculate(amount, network, type) {
    const config = DB.get("kc_config") || {};
    const taxRate = config.tax_rate !== undefined ? config.tax_rate : 0.5;
    const tariffs = (config.tariff_rates && config.tariff_rates[network])
      ? config.tariff_rates
      : DEFAULT_TARIFFS;

    const bands = (tariffs[network] && tariffs[network][type]) || [];
    let fee = 0;

    for (const band of bands) {
      if (amount >= band.min && amount <= band.max) {
        fee = band.fee;
        break;
      }
    }

    const tax = Math.round((amount * taxRate) / 100);
    const commission = Math.round(fee * 0.5); // agent's share ≈ 50%
    const customerPays = amount + fee + tax;

    return { amount, fee, tax, commission, customerPays };
  }

  return { calculate };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 5. KSS ENGINE — Kiosk Stability Score
 * ────────────────────────────────────────────────────────────────────────── */

const KSS = (() => {
  /**
   * Compute the Kiosk Stability Score from transaction history.
   *
   * KSS = w1·V + w2·C − w3·S − w4·D + w5·R   (clamped 0-100)
   *
   * V = rolling 90-day volume  → normalised to 0-30 pts
   * C = consistency (active days / 90 × 20)   → max 20 pts
   * S = float stockout events × 5             → penalty
   * D = overdue loans × 3                     → penalty
   * R = successful reconciliations × 2        → max 20 pts
   */
  function calculate() {
    const txns = DB.get("kc_transactions");
    const moneyOut = DB.get("kc_money_outside");
    const profiles = DB.get("kc_credit_profiles");

    const now = Date.now();
    const ninetyDays = 90 * 24 * 60 * 60 * 1000;
    const cutoff = now - ninetyDays;

    // V: volume
    const recentTxns = txns.filter((t) => new Date(t.timestamp).getTime() >= cutoff);
    const totalVolume = recentTxns.reduce((s, t) => s + (t.amount || 0), 0);
    const V = Math.min(30, (totalVolume / 100000000) * 30);

    // C: consistency (unique active days)
    const daySet = new Set();
    recentTxns.forEach((t) => {
      daySet.add(new Date(t.timestamp).toISOString().slice(0, 10));
    });
    const C = Math.min(20, (daySet.size / 90) * 20);

    // S: stockout count
    const stockoutCount =
      profiles.length > 0 ? profiles[0].float_stockout_count || 0 : 0;
    const S = stockoutCount * 5;

    // D: overdue loans
    const overdueCount = moneyOut.filter(
      (m) =>
        m.status === "Overdue" ||
        (m.status === "Active" && new Date(m.repayment_target_date) < new Date())
    ).length;
    const D = overdueCount * 3;

    // R: reconciliations (capped)
    const reconCount =
      profiles.length > 0 ? profiles[0].last_reconciled_count || 0 : 0;
    const R = Math.min(20, reconCount * 2);

    let score = Math.round(V + C - S - D + R);
    score = Math.max(0, Math.min(100, score));

    let grade;
    if (score >= 80) grade = "Excellent";
    else if (score >= 60) grade = "Good";
    else if (score >= 40) grade = "Fair";
    else grade = "Poor";

    return { score, grade, breakdown: { V, C, S, D, R } };
  }

  return { calculate };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 6. AI RECONCILIATION MODULE
 * ────────────────────────────────────────────────────────────────────────── */

const AIReconciler = (() => {
  /**
   * Diagnose a float discrepancy by inspecting transactions and loans.
   */
  function diagnose(expectedBalance, actualBalance) {
    const discrepancy = expectedBalance - actualBalance;

    if (discrepancy === 0) {
      return "Perfect match! No issues detected. 🎉";
    }

    const findings = [];

    // a) Outstanding loans
    const loans = DB.get("kc_money_outside").filter(
      (m) => m.transaction_direction === "Lent_Out" && m.status === "Active"
    );
    if (loans.length > 0) {
      loans.forEach((l) => {
        findings.push({
          icon: "🤝",
          text: `You have ${formatUGX(l.principal_amount - (l.repaid_amount || 0))} lent to ${l.party_name} since ${formatDate(new Date(l.created_at))} that hasn't been fully repaid.`,
          amount: l.principal_amount - (l.repaid_amount || 0),
        });
      });
    }

    // b) Commission withdrawals today
    const today = new Date().toISOString().slice(0, 10);
    const todayTxns = DB.get("kc_transactions").filter(
      (t) => t.timestamp && t.timestamp.startsWith(today)
    );
    const commissions = todayTxns.filter((t) => t.type === "Commission");
    if (commissions.length > 0) {
      const commTotal = commissions.reduce((s, c) => s + c.amount, 0);
      findings.push({
        icon: "💰",
        text: `Commission withdrawals totalling ${formatUGX(commTotal)} were detected today.`,
        amount: commTotal,
      });
    }

    // c) Transaction gaps (>2 hrs during 8am-8pm)
    const businessTxns = todayTxns
      .map((t) => new Date(t.timestamp))
      .filter((d) => d.getHours() >= 8 && d.getHours() <= 20)
      .sort((a, b) => a - b);

    for (let i = 1; i < businessTxns.length; i++) {
      const gap = businessTxns[i] - businessTxns[i - 1];
      if (gap > 2 * 60 * 60 * 1000) {
        const hrs = Math.round((gap / (60 * 60 * 1000)) * 10) / 10;
        findings.push({
          icon: "⏳",
          text: `There is an unexplained ${hrs}-hour gap in transactions between ${formatTime(businessTxns[i - 1])} and ${formatTime(businessTxns[i])}.`,
          amount: 0,
        });
      }
    }

    // d) Remaining unexplained
    const explainedTotal = findings.reduce((s, f) => s + f.amount, 0);
    const remaining = Math.abs(discrepancy) - explainedTotal;
    if (remaining > 500) {
      findings.push({
        icon: "❓",
        text: `${formatUGX(remaining)} remains unaccounted for. Verify cash drawer and check for unrecorded expenses.`,
        amount: remaining,
      });
    }

    if (findings.length === 0) {
      findings.push({
        icon: "⚠️",
        text: `Discrepancy of ${formatUGX(Math.abs(discrepancy))} detected but no specific cause found. Manual verification needed.`,
        amount: Math.abs(discrepancy),
      });
    }

    return findings;
  }

  return { diagnose };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 7. SCREEN NAVIGATION MODULE
 * ────────────────────────────────────────────────────────────────────────── */

const Nav = (() => {
  const ONBOARDING = ["consent", "setup", "pin-setup", "scan"];
  let currentScreen = null;

  function goto(screenId) {
    // Hide all screens
    document.querySelectorAll(".screen").forEach((el) => {
      el.classList.remove("active");
      el.style.display = "none";
    });

    // Show target
    const target =
      document.getElementById(`screen-${screenId}`) ||
      document.querySelector(`[data-screen="${screenId}"]`);
    if (target) {
      target.classList.add("active");
      target.style.display = "flex";
    }

    // Bottom nav visibility
    const bottomNav = document.querySelector(".bottom-nav");
    if (bottomNav) {
      bottomNav.style.display = ONBOARDING.includes(screenId) ? "none" : "flex";
    }

    // Update active tab
    document.querySelectorAll(".nav-item").forEach((el) => {
      el.classList.toggle(
        "active",
        el.getAttribute("data-screen") === screenId
      );
    });

    currentScreen = screenId;

    // Fire screen-specific hooks
    if (screenId === "dashboard")    refreshDashboard();
    if (screenId === "money-outside") refreshMoneyOutside();
    if (screenId === "audit")        refreshAudit();
    if (screenId === "scan")         startScanAnimation();
    if (screenId === "settings")     refreshSettings();
    if (screenId === "analytics")    refreshAnalytics();
    if (screenId === "tariff")       refreshTariff();
  }

  function getCurrent() {
    return currentScreen;
  }

  return { goto, getCurrent };
})();

/* ──────────────────────────────────────────────────────────────────────────────
 * 10. UTILITY FUNCTIONS  (declared early — used by other modules)
 * ────────────────────────────────────────────────────────────────────────── */

/** Format a number with UGX prefix and thousand separators. */
function formatUGX(n) {
  if (n === null || n === undefined || isNaN(n)) return "UGX 0";
  return "UGX " + Math.round(n).toLocaleString("en-UG");
}

/** Format a Date to "HH:MM AM/PM". */
function formatTime(d) {
  if (!(d instanceof Date)) d = new Date(d);
  let h = d.getHours();
  const m = String(d.getMinutes()).padStart(2, "0");
  const ampm = h >= 12 ? "PM" : "AM";
  h = h % 12 || 12;
  return `${h}:${m} ${ampm}`;
}

/** Format a Date to "DD MMM YYYY". */
function formatDate(d) {
  if (!(d instanceof Date)) d = new Date(d);
  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${d.getDate()} ${months[d.getMonth()]} ${d.getFullYear()}`;
}

/** Show a toast notification at the top of the screen. */
function showToast(message, type = "info") {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    container.style.cssText =
      "position:fixed;top:40px;left:50%;transform:translateX(-50%);z-index:10000;display:flex;flex-direction:column;gap:8px;pointer-events:none;";
    document.body.appendChild(container);
  }
  const colors = {
    success: "#22c55e",
    error:   "#ef4444",
    warning: "#f59e0b",
    info:    "#3b82f6",
  };
  const icons = { success: "✓", error: "✗", warning: "⚠", info: "ℹ" };
  const toast = document.createElement("div");
  toast.style.cssText = `background:${colors[type] || colors.info};color:#fff;padding:12px 24px;border-radius:12px;font-size:14px;font-weight:600;box-shadow:0 4px 12px rgba(0,0,0,.25);pointer-events:auto;opacity:0;transition:opacity .3s;max-width:320px;text-align:center;`;
  toast.textContent = `${icons[type] || ""} ${message}`;
  container.appendChild(toast);
  requestAnimationFrame(() => (toast.style.opacity = "1"));
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 350);
  }, 3000);
}

/** Update the phone status-bar clock element. */
function updateStatusBarTime() {
  const el = document.querySelector(".status-time");
  if (el) el.textContent = formatTime(new Date());
}

/** Animate a number counting up to its target. */
function animateValue(el, target, duration = 800, formatFn = formatUGX) {
  if (!el) return;
  if (el.textContent === "••••••") return; // Keep hidden for workers
  const start = 0;
  const startTime = performance.now();
  
  function update(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    // ease-out cubic
    const ease = 1 - Math.pow(1 - progress, 3);
    const current = start + (target - start) * ease;
    
    el.textContent = formatFn(current);
    
    if (progress < 1) {
      requestAnimationFrame(update);
    } else {
      el.textContent = formatFn(target);
    }
  }
  requestAnimationFrame(update);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 11. PRESET SMS MESSAGES
 * ────────────────────────────────────────────────────────────────────────── */

const SMS_PRESETS = {
  "mtn-deposit-50k": {
    sender: "MobileMoney",
    textTemplate(bal) {
      return `You have received UGX 50,000 from 0772345678. New balance: UGX ${fmtNum(bal + 50000)}.`;
    },
    network: "MTN",
    delta: 50000,
    type: "Deposit",
  },
  "mtn-withdraw-100k": {
    sender: "MobileMoney",
    textTemplate(bal) {
      return `Withdrawn UGX 100,000 from 0785432109. Commission earned: UGX 1,200. New balance: UGX ${fmtNum(bal - 100000)}.`;
    },
    network: "MTN",
    delta: -100000,
    type: "Withdrawal",
  },
  "mtn-withdraw-500k": {
    sender: "MobileMoney",
    textTemplate(bal) {
      return `Withdrawn UGX 500,000 from 0771234567. Commission earned: UGX 3,500. New balance: UGX ${fmtNum(bal - 500000)}.`;
    },
    network: "MTN",
    delta: -500000,
    type: "Withdrawal",
  },
  "airtel-deposit-200k": {
    sender: "AirtelMoney",
    textTemplate(bal) {
      return `You have received UGX 200,000 from 0702345678. Your Airtel Money balance is UGX ${fmtNum(bal + 200000)}.`;
    },
    network: "Airtel",
    delta: 200000,
    type: "Deposit",
  },
  "airtel-withdraw-75k": {
    sender: "AirtelMoney",
    textTemplate(bal) {
      return `Cash Out of UGX 75,000 to 0708765432 completed. Charge: UGX 700. Balance: UGX ${fmtNum(bal - 75000)}.`;
    },
    network: "Airtel",
    delta: -75000,
    type: "Withdrawal",
  },
  "mtn-commission": {
    sender: "MobileMoney",
    textTemplate() {
      return "Commission of UGX 2,500 earned on transaction TXN2024061234. Total commission: UGX 45,000.";
    },
    network: "MTN",
    delta: 0,
    type: "Commission",
  },
  "fraud-spoofed": {
    sender: "+256772000111",
    textTemplate(bal) {
      return `You have received UGX 1,000,000 from 0772111222. New balance: UGX ${fmtNum(bal + 1000000)}.`;
    },
    network: "MTN",
    delta: 1000000,
    type: "Deposit",
  },
  "fraud-bad-math": {
    sender: "MobileMoney",
    textTemplate() {
      return "You have received UGX 1,000,000 from 0772111222. New balance: UGX 99,999,999.";
    },
    network: "MTN",
    delta: 1000000,
    type: "Deposit",
  },
  "fraud-bad-format": {
    sender: "MobileMoney",
    textTemplate() {
      return "Congrats! You recieved UGX 500,000 from MoMo Promo. Bal: UGX 5,000,000. Claim at bit.ly/xyz";
    },
    network: "MTN",
    delta: 0,
    type: "Deposit",
  },
};

/** Format a plain number with commas (helper for SMS templates). */
function fmtNum(n) {
  return Math.round(n).toLocaleString("en-UG");
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 12. HISTORICAL DATA SEEDER
 * ────────────────────────────────────────────────────────────────────────── */

function seedHistoricalData() {
  const kioskId = DB.generateUUID();
  const ownerId = DB.generateUUID();

  DB.set("kc_kiosks", [
    {
      id: kioskId,
      name: "KioskControl Main",
      district: "Kampala Central",
      owner_id: ownerId,
      created_at: new Date().toISOString(),
    },
  ]);

  const mtnWalletId = DB.generateUUID();
  const airtelWalletId = DB.generateUUID();
  const bankWalletId = DB.generateUUID();

  const wallets = [
    {
      id: mtnWalletId,
      kiosk_id: kioskId,
      carrier_type: "MTN",
      current_float: 2400000,
      current_cash: 1500000,
    },
    {
      id: airtelWalletId,
      kiosk_id: kioskId,
      carrier_type: "Airtel",
      current_float: 850000,
      current_cash: 600000,
    },
    {
      id: bankWalletId,
      kiosk_id: kioskId,
      carrier_type: "Bank",
      current_float: 500000,
      current_cash: 500000,
    },
  ];
  DB.set("kc_wallets", wallets);

  // Transactions (30 days)
  const transactions = [];
  const now = new Date();
  let mtnBal = 2400000;
  let airBal = 850000;

  for (let day = 29; day >= 0; day--) {
    const numTxns = 30 + Math.floor(Math.random() * 51); // 30-80

    for (let t = 0; t < numTxns; t++) {
      const date = new Date(now);
      date.setDate(date.getDate() - day);
      date.setHours(8 + Math.floor(Math.random() * 12));
      date.setMinutes(Math.floor(Math.random() * 60));
      date.setSeconds(Math.floor(Math.random() * 60));

      const isMTN = Math.random() > 0.35;
      const walletId = isMTN ? mtnWalletId : airtelWalletId;
      const network = isMTN ? "MTN" : "Airtel";

      const isDeposit = Math.random() > 0.45;
      const type = isDeposit ? "Deposit" : "Withdrawal";
      const amountBands = [5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000, 2000000];
      const amount = amountBands[Math.floor(Math.random() * amountBands.length)];

      let commission = 0;
      if (type === "Withdrawal") {
        const calc = Tariff.calculate(amount, network, "Withdrawal");
        commission = calc.commission;
      }

      if (isMTN) {
        mtnBal += isDeposit ? amount : -amount;
        if (mtnBal < 50000) mtnBal = 500000;
      } else {
        airBal += isDeposit ? amount : -amount;
        if (airBal < 50000) airBal = 300000;
      }

      const phone = `07${7 + Math.floor(Math.random() * 3)}${String(
        Math.floor(Math.random() * 10000000)
      ).padStart(7, "0")}`;

      transactions.push({
        id: DB.generateUUID(),
        wallet_id: walletId,
        type,
        amount,
        commission_earned: commission,
        recorded_balance: isMTN ? mtnBal : airBal,
        counterparty: phone,
        timestamp: date.toISOString(),
        raw_payload: `${type} of UGX ${amount.toLocaleString("en-UG")} — ${network}`,
        source_type: "SMS_Legacy",
        security_flag: "Verified",
      });
    }
  }
  DB.set("kc_transactions", transactions);

  // Money Outside seed
  const moneyOutside = [];
  const names = ["Mukasa James", "Achieng Grace", "Okello David", "Nakato Sarah"];
  for (let i = 0; i < 3; i++) {
    const created = new Date();
    created.setDate(created.getDate() - Math.floor(Math.random() * 20 + 5));
    const targetDate = new Date(created);
    targetDate.setDate(targetDate.getDate() + 14);
    const principal = [200000, 500000, 150000][i];
    moneyOutside.push({
      id: DB.generateUUID(),
      kiosk_id: kioskId,
      party_name: names[i],
      transaction_direction: i < 2 ? "Lent_Out" : "Borrowed_In",
      principal_amount: principal,
      repaid_amount: i === 2 ? principal : 0,
      repayment_target_date: targetDate.toISOString(),
      cleared_timestamp: i === 2 ? new Date().toISOString() : null,
      status: i === 2 ? "Settled" : "Active",
      notes: "",
      created_at: created.toISOString(),
    });
  }
  DB.set("kc_money_outside", moneyOutside);

  // Credit Profile
  const kssResult = KSS.calculate();
  DB.set("kc_credit_profiles", [
    {
      id: DB.generateUUID(),
      kiosk_id: kioskId,
      rolling_90_day_volume: transactions.reduce((s, t) => s + t.amount, 0),
      daily_average_transactions: Math.round(transactions.length / 30),
      max_single_drawdown: 2000000,
      float_stockout_count: 1,
      overdue_loans_count: 0,
      last_reconciled_at: new Date().toISOString(),
      last_reconciled_count: 5,
      kiosk_stability_score: kssResult.score,
    },
  ]);

  // Final wallet balance sync
  wallets[0].current_float = mtnBal;
  wallets[1].current_float = airBal;
  DB.set("kc_wallets", wallets);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * SCREEN REFRESH HELPERS
 * ────────────────────────────────────────────────────────────────────────── */

/** Refresh the Dashboard screen with live data from DB. */
function refreshDashboard() {
  const wallets  = DB.get("kc_wallets");
  const txns     = DB.get("kc_transactions");
  const config   = DB.get("kc_config") || {};

  /* ── Greeting ── */
  const hour = new Date().getHours();
  let greeting;
  if (hour < 12)       greeting = "Good Morning 👋";
  else if (hour < 17)  greeting = "Good Afternoon ☀️";
  else                 greeting = "Good Evening 🌙";

  const elGreeting = document.getElementById("greeting-text");
  if (elGreeting) elGreeting.textContent = greeting;

  const elName = document.getElementById("dash-biz-name");
  if (elName) elName.textContent = config.business_name || "Your Business";

  /* ── Capital totals ── */
  const totalFloat = wallets.reduce((s, w) => s + (w.current_float || 0), 0);
  const totalCash  = wallets.reduce((s, w) => s + (w.current_cash  || 0), 0);

  const elCapital = document.getElementById("total-capital");
  if (elCapital) animateValue(elCapital, totalFloat + totalCash);

  const elFloat = document.getElementById("total-float");
  if (elFloat) animateValue(elFloat, totalFloat);

  const elCash = document.getElementById("total-cash");
  if (elCash) animateValue(elCash, totalCash);

  /* ── Per-wallet balances + status dots ── */
  wallets.forEach((w) => {
    const network = w.carrier_type.toLowerCase();
    const elBal  = document.getElementById(`${network}-balance`);
    const elDot  = document.getElementById(`${network}-status-dot`);

    if (elBal) animateValue(elBal, w.current_float);

    if (elDot) {
      const isLow = w.current_float < 200000;
      elDot.style.background = isLow ? "#EF4444" : "#10B981";
      elDot.title = isLow ? "Low float — restock soon" : "Float OK";
    }
  });

  /* ── Today's stats ── */
  const today = new Date().toISOString().slice(0, 10);
  const todayTxns = txns.filter((t) => t.timestamp && t.timestamp.startsWith(today));

  const todayDeposits   = todayTxns.filter((t) => t.type === "Deposit")
    .reduce((s, t) => s + t.amount, 0);
  const todayWithdrawals = todayTxns.filter((t) => t.type === "Withdrawal")
    .reduce((s, t) => s + t.amount, 0);
  const todayCommission = todayTxns
    .reduce((s, t) => s + (t.commission_earned || 0), 0);

  const elDep = document.getElementById("total-deposits");
  if (elDep) animateValue(elDep, todayDeposits);

  const elWd = document.getElementById("total-withdrawals");
  if (elWd) animateValue(elWd, todayWithdrawals);

  const elComm = document.getElementById("commission-earned");
  if (elComm) {
    if (config.role === "worker") elComm.textContent = "••••••";
    else animateValue(elComm, todayCommission);
  }

  const elCount = document.getElementById("transaction-count");
  if (elCount) animateValue(elCount, todayTxns.length, 800, (n) => Math.round(n).toString());

  /* ── KSS Score + Bar ── */
  const kss = KSS.calculate();
  const elScore = document.getElementById("kss-score");
  if (elScore) elScore.textContent = kss.score;

  const elGrade = document.getElementById("kss-grade");
  if (elGrade) {
    elGrade.textContent = kss.grade;
    elGrade.className = `kss-grade-tag grade-${kss.grade.toLowerCase()}`;
  }

  const elBar = document.getElementById("kss-bar");
  if (elBar) {
    // Animate bar fill
    elBar.style.transition = "width 1s cubic-bezier(0.16, 1, 0.3, 1)";
    setTimeout(() => { elBar.style.width = `${kss.score}%`; }, 100);

    // Colour by score
    if (kss.score >= 80)       elBar.style.background = "linear-gradient(90deg, #10B981, #059669)";
    else if (kss.score >= 60)  elBar.style.background = "linear-gradient(90deg, #3B82F6, #2563EB)";
    else if (kss.score >= 40)  elBar.style.background = "linear-gradient(90deg, #F59E0B, #D97706)";
    else                       elBar.style.background = "linear-gradient(90deg, #EF4444, #DC2626)";
  }

  /* ── Fraud badge ── */
  const fraudBadge = document.getElementById("fraud-alert-badge");
  const fraudCount = document.getElementById("fraud-alert-count");
  const flaggedTxns = todayTxns.filter((t) => t.security_flag === "Mismatch").length;
  if (fraudBadge) {
    fraudBadge.hidden = flaggedTxns === 0;
    if (fraudCount) fraudCount.textContent = flaggedTxns;
  }

  /* ── Recent transactions preview ── */
  renderRecentTransactions(todayTxns, wallets);

  /* ── Status bar ── */
  updateStatusBarTime();
}

/** Render the 5 most recent transactions in the dashboard preview strip. */
function renderRecentTransactions(todayTxns, wallets) {
  const preview = document.getElementById("recent-txns-preview");
  if (!preview) return;

  const recent = [...todayTxns].slice(-5).reverse();

  if (recent.length === 0) {
    preview.innerHTML = `
      <div class="empty-state-small">
        <span class="material-icons-outlined">inbox</span>
        <p>No transactions yet today</p>
      </div>`;
    return;
  }

  preview.innerHTML = recent.map((t) => {
    const wallet  = wallets ? wallets.find((w) => w.id === t.wallet_id) : null;
    const network = wallet ? wallet.carrier_type : "MTN";
    const isDeposit = t.type === "Deposit";
    const isComm    = t.type === "Commission";

    return `
      <div class="recent-txn-item">
        <div class="rtxn-icon ${isDeposit ? "deposit" : isComm ? "commission" : "withdrawal"}">
          <span class="material-icons-outlined">
            ${isDeposit ? "arrow_downward" : isComm ? "payments" : "arrow_upward"}
          </span>
        </div>
        <div class="rtxn-info">
          <span class="rtxn-type">${t.type}</span>
          <span class="rtxn-time">${formatTime(new Date(t.timestamp))}</span>
        </div>
        <span class="rtxn-network ${network.toLowerCase()}">${network}</span>
        <span class="rtxn-amount ${isDeposit || isComm ? "credit" : "debit"}">
          ${isDeposit || isComm ? "+" : "-"}${formatUGX(t.amount)}
        </span>
      </div>`;
  }).join("");
}

/** Refresh the Money Outside screen. */
function refreshMoneyOutside() {
  const entries = DB.get("kc_money_outside");
  const config  = DB.get("kc_config") || {};
  const list    = document.getElementById("loans-list");
  if (!list) return;

  // Get active filter — HTML uses .tab-btn (not .mo-tab)
  const activeTab = document.querySelector(".tab-btn.active");
  const filter    = activeTab ? activeTab.getAttribute("data-filter") || "all" : "all";

  const filtered = entries.filter((e) => {
    if (filter === "lent")     return e.transaction_direction === "Lent_Out";
    if (filter === "borrowed") return e.transaction_direction === "Borrowed_In";
    return true;
  });

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty-state">
        <span class="material-icons-outlined empty-icon">account_balance_wallet</span>
        <p>No entries yet. Tap + to add one.</p>
      </div>`;
  } else {
    list.innerHTML = filtered.map((e) => {
      const outstanding = e.principal_amount - (e.repaid_amount || 0);
      const isOverdue   = e.status === "Active" && new Date(e.repayment_target_date) < new Date();
      const statusLabel = isOverdue ? "Overdue" : e.status;
      const statusClass = isOverdue ? "overdue" : e.status === "Settled" ? "settled" : "active";

      return `
      <div class="loan-card" data-id="${e.id}">
        <div class="loan-header">
          <span class="loan-name">${e.party_name}</span>
          <span class="loan-status ${statusClass}">${statusLabel}</span>
        </div>
        <div class="loan-details">
          <span>${e.transaction_direction === "Lent_Out" ? "Lent" : "Borrowed"}: ${
            config.role === "worker" ? "••••••" : formatUGX(e.principal_amount)
          }</span>
          <span>Outstanding: ${formatUGX(outstanding)}</span>
        </div>
        <div class="loan-meta">
          <span>Due: ${formatDate(new Date(e.repayment_target_date))}</span>
          ${
            e.status !== "Settled"
              ? `<button class="btn-settle" data-loan-id="${e.id}">Mark Settled</button>`
              : `<span class="settled-label">✓ Settled</span>`
          }
        </div>
        ${outstanding > 0 && e.status !== "Settled" ? `
          <div class="loan-progress-track">
            <div class="loan-progress-fill" style="width: ${Math.round(((e.repaid_amount || 0) / e.principal_amount) * 100)}%"></div>
          </div>
        ` : ""}
      </div>`;
    }).join("");

    // Attach settle handlers
    list.querySelectorAll(".btn-settle").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const loanId  = btn.getAttribute("data-loan-id");
        const allLoans = DB.get("kc_money_outside");
        const idx     = allLoans.findIndex((l) => l.id === loanId);
        if (idx !== -1) {
          allLoans[idx].status          = "Settled";
          allLoans[idx].repaid_amount   = allLoans[idx].principal_amount;
          allLoans[idx].cleared_timestamp = new Date().toISOString();
          DB.set("kc_money_outside", allLoans);
          showToast("Loan marked as settled ✓", "success");
          refreshMoneyOutside();
        }
      });
    });
  }

  /* ── Totals ── */
  const totalOut = entries
    .filter((e) => e.transaction_direction === "Lent_Out" && e.status !== "Settled")
    .reduce((s, e) => s + (e.principal_amount - (e.repaid_amount || 0)), 0);
  const totalIn = entries
    .filter((e) => e.transaction_direction === "Borrowed_In" && e.status !== "Settled")
    .reduce((s, e) => s + (e.principal_amount - (e.repaid_amount || 0)), 0);

  const elOut = document.getElementById("mo-total-out");
  if (elOut) elOut.textContent = config.role === "worker" ? "••••••" : formatUGX(totalOut);
  const elIn  = document.getElementById("mo-total-in");
  if (elIn)  elIn.textContent = formatUGX(totalIn);

  /* ── Evening reminder ── */
  const hour = new Date().getHours();
  const banner = document.getElementById("reminder-banner");
  if (banner) banner.hidden = !(hour >= 18 && totalOut > 0);
}

/** Refresh the Audit screen. */
function refreshAudit() {
  const wallets = DB.get("kc_wallets");
  const txns    = DB.get("kc_transactions");
  const config  = DB.get("kc_config") || {};

  const today    = new Date().toISOString().slice(0, 10);
  const todayTxns = txns.filter((t) => t.timestamp && t.timestamp.startsWith(today));

  const totalFloat = wallets.reduce((s, w) => s + (w.current_float || 0), 0);
  const todayDep   = todayTxns.filter((t) => t.type === "Deposit")
    .reduce((s, t) => s + t.amount, 0);
  const todayWd    = todayTxns.filter((t) => t.type === "Withdrawal")
    .reduce((s, t) => s + t.amount, 0);
  const todayComm  = todayTxns.reduce((s, t) => s + (t.commission_earned || 0), 0);

  /* ── Populate audit date ── */
  const elDate = document.getElementById("audit-date");
  if (elDate) elDate.textContent = formatDate(new Date());

  /* ── Summary cards ── */
  const elExpFloat = document.getElementById("audit-expected-float");
  if (elExpFloat) elExpFloat.textContent = formatUGX(totalFloat);

  const elExpComm = document.getElementById("audit-expected-commission");
  if (elExpComm) elExpComm.textContent =
    config.role === "worker" ? "••••••" : formatUGX(todayComm);

  /* ── Stats row ── */
  const elDep = document.getElementById("audit-deposits");
  if (elDep) elDep.textContent = formatUGX(todayDep);

  const elWd = document.getElementById("audit-withdrawals");
  if (elWd) elWd.textContent = formatUGX(todayWd);

  const elCount = document.getElementById("audit-txn-count");
  if (elCount) elCount.textContent = todayTxns.length;

  /* ── Clear previous diagnosis ── */
  const discEl = document.getElementById("audit-discrepancy");
  if (discEl) { discEl.hidden = true; discEl.querySelector(".discrepancy-text").textContent = ""; }

  const diagEl = document.getElementById("audit-diagnosis");
  if (diagEl) diagEl.hidden = true;
}

/** Refresh the Settings screen. */
function refreshSettings() {
  const config = DB.get("kc_config") || {};

  // settings-biz-name is now an <input>
  const elBizName = document.getElementById("settings-biz-name");
  if (elBizName) elBizName.value = config.business_name || "";

  const elRole = document.getElementById("settings-role");
  if (elRole) elRole.textContent = config.role || "owner";

  const elTaxRate = document.getElementById("settings-tax-rate");
  if (elTaxRate) elTaxRate.value = config.tax_rate !== undefined ? config.tax_rate : 0.5;

  // Referral code from UUID
  const elRef = document.getElementById("referral-code");
  if (elRef && elRef.textContent === "KC-XXXXXX") {
    const seed = Math.random().toString(36).slice(2, 8).toUpperCase();
    elRef.textContent = `KC-${seed}`;
  }
}

/** Populate the Tariff quick-reference table. */
function refreshTariff() {
  const activeNetBtn = document.querySelector(".tariff-network-btn.active");
  const network = activeNetBtn ? activeNetBtn.dataset.network : "MTN";

  const quickAmounts = [5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000];
  const table = document.getElementById("tariff-quick-table");
  if (!table) return;

  table.innerHTML = `
    <div class="quick-ref-header">
      <span>Amount</span>
      <span>Fee</span>
      <span>Tax</span>
      <span>Customer Pays</span>
    </div>
    ${quickAmounts.map((amt) => {
      const r = Tariff.calculate(amt, network, "Withdrawal");
      return `
        <div class="quick-ref-row">
          <span>${formatUGX(amt)}</span>
          <span class="qr-fee">${formatUGX(r.fee)}</span>
          <span class="qr-tax">${formatUGX(r.tax)}</span>
          <span class="qr-total">${formatUGX(r.customerPays)}</span>
        </div>`;
    }).join("")}
  `;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 12. ANALYTICS ENGINE (Canvas-based charts)
 * ────────────────────────────────────────────────────────────────────────── */

/** Main analytics refresh — called on nav to analytics screen. */
function refreshAnalytics() {
  const txns       = DB.get("kc_transactions");
  const activeBtn  = document.querySelector(".analytics-range-btn.active");
  const days       = activeBtn ? parseInt(activeBtn.dataset.range, 10) : 7;

  const dailyData = buildDailyData(txns, days);

  renderBarChart("chart-volume", dailyData, days);
  renderCommissionChart("chart-commission", dailyData, days);
  renderAnalyticsSummary(dailyData);
}

/** Build day-by-day aggregated data for the given range. */
function buildDailyData(txns, days) {
  const data = [];
  const now  = new Date();

  for (let i = days - 1; i >= 0; i--) {
    const d       = new Date(now);
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().slice(0, 10);
    const dayTxns = txns.filter((t) => t.timestamp && t.timestamp.startsWith(dateStr));

    data.push({
      date:        dateStr,
      label:       `${d.getDate()}/${d.getMonth() + 1}`,
      deposits:    dayTxns.filter((t) => t.type === "Deposit").reduce((s, t) => s + t.amount, 0),
      withdrawals: dayTxns.filter((t) => t.type === "Withdrawal").reduce((s, t) => s + t.amount, 0),
      commission:  dayTxns.reduce((s, t) => s + (t.commission_earned || 0), 0),
      count:       dayTxns.length,
    });
  }
  return data;
}

/** Render a grouped bar chart (deposits vs withdrawals). */
function renderBarChart(canvasId, data, days) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  canvas.width  = canvas.parentElement ? canvas.parentElement.clientWidth : 320;
  const W       = canvas.width;
  const H       = canvas.height;
  const ctx     = canvas.getContext("2d");
  ctx.clearRect(0, 0, W, H);

  const pad    = { left: 8, right: 8, top: 8, bottom: 22 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top  - pad.bottom;
  const slotW  = chartW / data.length;
  const barW   = Math.max(3, slotW * 0.32);
  const maxVal = Math.max(...data.map((d) => d.deposits + d.withdrawals), 1);

  data.forEach((d, i) => {
    const cx = pad.left + i * slotW + slotW / 2;

    // Deposits bar (green)
    const depH = (d.deposits / maxVal) * chartH;
    if (depH > 0) {
      const gDep = ctx.createLinearGradient(0, pad.top + chartH - depH, 0, pad.top + chartH);
      gDep.addColorStop(0, "#10B981");
      gDep.addColorStop(1, "#059669");
      ctx.fillStyle = gDep;
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(cx - barW - 2, pad.top + chartH - depH, barW, depH, [3, 3, 0, 0]);
      } else {
        ctx.rect(cx - barW - 2, pad.top + chartH - depH, barW, depH);
      }
      ctx.fill();
    }

    // Withdrawals bar (blue)
    const wdH = (d.withdrawals / maxVal) * chartH;
    if (wdH > 0) {
      const gWd = ctx.createLinearGradient(0, pad.top + chartH - wdH, 0, pad.top + chartH);
      gWd.addColorStop(0, "#3B82F6");
      gWd.addColorStop(1, "#2563EB");
      ctx.fillStyle = gWd;
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(cx + 2, pad.top + chartH - wdH, barW, wdH, [3, 3, 0, 0]);
      } else {
        ctx.rect(cx + 2, pad.top + chartH - wdH, barW, wdH);
      }
      ctx.fill();
    }

    // Date label
    if (days <= 14 || i % Math.ceil(days / 7) === 0) {
      ctx.fillStyle  = "rgba(148, 163, 184, 0.8)";
      ctx.font       = "9px Inter, sans-serif";
      ctx.textAlign  = "center";
      ctx.fillText(d.label, cx, H - 5);
    }
  });
}

/** Render a filled area line chart (commission over time). */
function renderCommissionChart(canvasId, data, days) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  canvas.width  = canvas.parentElement ? canvas.parentElement.clientWidth : 320;
  const W       = canvas.width;
  const H       = canvas.height;
  const ctx     = canvas.getContext("2d");
  ctx.clearRect(0, 0, W, H);

  const pad    = { left: 8, right: 8, top: 8, bottom: 22 };
  const chartW = W - pad.left - pad.right;
  const chartH = H - pad.top  - pad.bottom;
  const slotW  = chartW / Math.max(data.length - 1, 1);
  const maxVal = Math.max(...data.map((d) => d.commission), 1);

  const pts = data.map((d, i) => ({
    x: pad.left + i * slotW,
    y: pad.top + chartH - (d.commission / maxVal) * chartH,
  }));

  // Filled area
  ctx.beginPath();
  ctx.moveTo(pts[0].x, pad.top + chartH);
  pts.forEach((p) => ctx.lineTo(p.x, p.y));
  ctx.lineTo(pts[pts.length - 1].x, pad.top + chartH);
  ctx.closePath();
  const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartH);
  grad.addColorStop(0, "rgba(139, 92, 246, 0.55)");
  grad.addColorStop(1, "rgba(139, 92, 246, 0.03)");
  ctx.fillStyle = grad;
  ctx.fill();

  // Stroke
  ctx.beginPath();
  pts.forEach((p, i) => (i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y)));
  ctx.strokeStyle = "#8B5CF6";
  ctx.lineWidth   = 2;
  ctx.lineJoin    = "round";
  ctx.stroke();

  // Dots + labels
  data.forEach((d, i) => {
    const p = pts[i];
    ctx.beginPath();
    ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = "#8B5CF6";
    ctx.fill();

    if (days <= 14 || i % Math.ceil(days / 7) === 0) {
      ctx.fillStyle  = "rgba(148, 163, 184, 0.8)";
      ctx.font       = "9px Inter, sans-serif";
      ctx.textAlign  = "center";
      ctx.fillText(d.label, p.x, H - 5);
    }
  });
}

/** Render the analytics summary stat cards. */
function renderAnalyticsSummary(dailyData) {
  const grid = document.getElementById("analytics-summary-grid");
  if (!grid) return;

  const totalDeposits    = dailyData.reduce((s, d) => s + d.deposits, 0);
  const totalWithdrawals = dailyData.reduce((s, d) => s + d.withdrawals, 0);
  const totalCommission  = dailyData.reduce((s, d) => s + d.commission, 0);
  const totalTxns        = dailyData.reduce((s, d) => s + d.count, 0);
  const avgDailyTxns     = dailyData.length ? Math.round(totalTxns / dailyData.length) : 0;
  const bestDay          = dailyData.reduce(
    (best, d) => (d.commission > best.commission ? d : best),
    dailyData[0] || { commission: 0, label: "—" }
  );

  grid.innerHTML = `
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Total Deposits</p>
      <p class="analytics-stat-value deposit">${formatUGX(totalDeposits)}</p>
    </div>
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Total Withdrawals</p>
      <p class="analytics-stat-value withdrawal">${formatUGX(totalWithdrawals)}</p>
    </div>
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Commission Earned</p>
      <p class="analytics-stat-value commission">${formatUGX(totalCommission)}</p>
    </div>
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Total Transactions</p>
      <p class="analytics-stat-value">${totalTxns.toLocaleString()}</p>
    </div>
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Avg Daily Transactions</p>
      <p class="analytics-stat-value">${avgDailyTxns}</p>
    </div>
    <div class="analytics-stat-card">
      <p class="analytics-stat-label">Best Commission Day</p>
      <p class="analytics-stat-value commission">${formatUGX(bestDay.commission)}</p>
    </div>
  `;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * SCAN ANIMATION
 * ────────────────────────────────────────────────────────────────────────── */

function startScanAnimation() {
  const bar         = document.getElementById("scan-progress-bar");
  const counter     = document.getElementById("scan-counter");
  const continueBtn = document.getElementById("btn-scan-continue");

  if (continueBtn) continueBtn.style.display = "none";
  if (bar) bar.style.width = "0%";
  if (counter) counter.textContent = "0";

  const targetCount = 600 + Math.floor(Math.random() * 601); // 600–1200
  const duration    = 4000; // 4 s
  const start       = performance.now();

  function tick(now) {
    const elapsed  = now - start;
    const progress = Math.min(elapsed / duration, 1);

    if (bar) bar.style.width = `${Math.round(progress * 100)}%`;
    if (counter) counter.textContent = Math.round(progress * targetCount);

    if (progress < 1) {
      requestAnimationFrame(tick);
    } else {
      seedHistoricalData();
      if (continueBtn) {
        continueBtn.style.display = "inline-flex";
      }
      showToast(`Imported ${targetCount.toLocaleString()} transactions`, "success");
    }
  }

  requestAnimationFrame(tick);
}

/* ──────────────────────────────────────────────────────────────────────────────
 * SIMULATOR — Process an SMS through the full pipeline
 * ────────────────────────────────────────────────────────────────────────── */

function processSimulatedSMS(sender, text) {
  const wallets      = DB.get("kc_wallets");
  const mtnWallet    = wallets.find((w) => w.carrier_type === "MTN");
  const airtelWallet = wallets.find((w) => w.carrier_type === "Airtel");

  const parsed = Parser.parse(text, sender);
  let currentBalance = null;
  let targetWallet   = mtnWallet;

  if (parsed.success) {
    if (parsed.network === "Airtel") targetWallet = airtelWallet;
    if (targetWallet) currentBalance = targetWallet.current_float;
  }

  // Security check
  const secResult = Security.validate(text, sender, currentBalance);
  logToSim(
    `🔒 Security: ${secResult.safe ? "SAFE" : "⚠ " + secResult.severity.toUpperCase()}`,
    secResult.safe ? "safe" : "danger"
  );

  if (secResult.flags.length > 0) {
    secResult.flags.forEach((f) =>
      logToSim(`   ↳ ${f.layer}: ${f.reason}`, "warning")
    );
  }

  // Critical → show fraud overlay
  if (!secResult.safe && secResult.severity === "critical") {
    showFraudAlert(sender, text, secResult.flags);
    return;
  }

  if (!parsed.success) {
    logToSim("❌ Parser: Could not match any known SMS pattern.", "danger");
    return;
  }

  logToSim(
    `✅ Parsed: ${parsed.type} of ${formatUGX(parsed.amount)} — ${parsed.network}`,
    "safe"
  );

  if (targetWallet) {
    const securityFlag = secResult.safe ? "Verified" : "Mismatch";

    const txn = {
      id:               DB.generateUUID(),
      wallet_id:        targetWallet.id,
      type:             parsed.type,
      amount:           parsed.amount,
      commission_earned: parsed.commission || 0,
      recorded_balance: parsed.balance || targetWallet.current_float,
      counterparty:     parsed.counterparty || "",
      timestamp:        new Date().toISOString(),
      raw_payload:      text,
      source_type:      "Notification",
      security_flag:    securityFlag,
    };

    const txns = DB.get("kc_transactions");
    txns.push(txn);
    DB.set("kc_transactions", txns);

    // Update wallet balance
    if (parsed.type === "Deposit") {
      targetWallet.current_float += parsed.amount;
      targetWallet.current_cash  -= parsed.amount;
    } else if (parsed.type === "Withdrawal") {
      targetWallet.current_float -= parsed.amount;
      targetWallet.current_cash  += parsed.amount;
    }
    if (parsed.commission) {
      targetWallet.current_float += parsed.commission;
    }

    DB.set("kc_wallets", wallets);

    logToSim(
      `💾 Saved: ${parsed.type} — New float: ${formatUGX(targetWallet.current_float)}`,
      "safe"
    );
  }

  if (Nav.getCurrent() === "dashboard") refreshDashboard();
}

/** Write a line to the simulator log area. */
function logToSim(message, type) {
  const log = document.getElementById("sim-log");
  if (!log) return;
  const line      = document.createElement("div");
  line.className  = `sim-log-line ${type || ""}`;
  line.textContent = `[${formatTime(new Date())}] ${message}`;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

/** Show the fraud alert overlay. */
function showFraudAlert(sender, text, flags) {
  // Fixed: correct element ID is "fraud-alert-overlay"
  const overlay = document.getElementById("fraud-alert-overlay");
  if (!overlay) return;
  overlay.hidden = false;

  const elSender = document.getElementById("fraud-sender");
  if (elSender) elSender.textContent = sender || "Unknown";

  const elMsg = document.getElementById("fraud-message");
  if (elMsg) elMsg.textContent = text.length > 120 ? text.slice(0, 120) + "…" : text;

  const elFlags = document.getElementById("fraud-flags");
  if (elFlags) {
    elFlags.innerHTML = flags
      .map((f) => `<div class="fraud-flag-item">⚠ <strong>${f.layer}</strong>: ${f.reason}</div>`)
      .join("");
  }
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 9. EVENT HANDLERS — wired on DOMContentLoaded
 * ────────────────────────────────────────────────────────────────────────── */

function attachEventHandlers() {
  /* ── Helper shortcuts ── */
  function on(selector, handler) {
    const el = document.querySelector(selector);
    if (el) el.addEventListener("click", handler);
    return el;
  }
  function onAll(selector, handler) {
    document.querySelectorAll(selector).forEach((el) =>
      el.addEventListener("click", handler)
    );
  }

  /* =================================================================
   * CONSENT SCREEN
   * ============================================================== */
  on("#btn-decline", () => {
    showToast("You must accept to use KioskControl", "error");
  });

  on("#btn-accept", () => {
    const log = DB.get("kc_consent_log");
    log.push({
      timestamp:   new Date().toISOString(),
      action:      "consent_granted",
      device_hash: navigator.userAgent.slice(0, 40),
    });
    DB.set("kc_consent_log", log);
    Nav.goto("setup");
  });

  /* =================================================================
   * SETUP SCREEN
   * ============================================================== */
  onAll(".role-card", function () {
    document.querySelectorAll(".role-card").forEach((c) => {
      c.classList.remove("selected");
      c.setAttribute("aria-pressed", "false");
    });
    this.classList.add("selected");
    this.setAttribute("aria-pressed", "true");
  });

  on("#btn-setup-continue", () => {
    const nameInput = document.getElementById("input-biz-name");
    const bizName   = nameInput ? nameInput.value.trim() : "";
    if (!bizName) {
      showToast("Please enter your business name", "warning");
      return;
    }
    const selectedRole = document.querySelector(".role-card.selected");
    const role = selectedRole ? (selectedRole.getAttribute("data-role") || "owner") : "owner";

    DB.set("kc_config", {
      business_name:    bizName,
      role,
      pin:              null,
      consent_timestamp: new Date().toISOString(),
      networks:         ["MTN", "Airtel"],
      tariff_rates:     DEFAULT_TARIFFS,
      tax_rate:         0.5,
    });
    Nav.goto("pin-setup");
  });

  /* =================================================================
   * PIN SCREEN
   * ============================================================== */
  let pinBuffer = "";

  function updatePinDots() {
    document.querySelectorAll(".pin-dot").forEach((dot, i) => {
      dot.classList.toggle("filled", i < pinBuffer.length);
    });
  }

  onAll(".num-key", function () {
    const val = this.getAttribute("data-key") || this.textContent.trim();

    if (val === "back" || val === "⌫") {
      pinBuffer = pinBuffer.slice(0, -1);
      updatePinDots();
      return;
    }

    if (pinBuffer.length >= 4) return;
    pinBuffer += val;
    updatePinDots();

    if (pinBuffer.length === 4) {
      const config = DB.get("kc_config") || {};
      config.pin   = pinBuffer;
      DB.set("kc_config", config);
      showToast("PIN set successfully ✓", "success");
      pinBuffer = "";
      Nav.goto("scan");
    }
  });

  /* =================================================================
   * SCAN SCREEN
   * ============================================================== */
  on("#btn-scan-continue", () => {
    Nav.goto("dashboard");
  });

  /* =================================================================
   * BOTTOM NAVIGATION
   * ============================================================== */
  onAll(".nav-item", function () {
    const screen = this.getAttribute("data-screen");
    if (screen) Nav.goto(screen);
  });

  /* =================================================================
   * DASHBOARD
   * ============================================================== */
  on("#btn-verify-balance", () => {
    const input = prompt("Enter your counted cash total (UGX):");
    if (input === null) return;
    const actual = Number(String(input).replace(/,/g, ""));
    if (isNaN(actual) || actual === 0) {
      showToast("Please enter a valid number", "error");
      return;
    }
    const wallets  = DB.get("kc_wallets");
    const expected = wallets.reduce((s, w) => s + (w.current_cash || 0), 0);
    const diff     = expected - actual;

    if (Math.abs(diff) < 500) {
      showToast("✓ Cash balances match! You're all good.", "success");
    } else {
      showToast(
        `Discrepancy of ${formatUGX(Math.abs(diff))} — ${diff > 0 ? "short" : "over"}`,
        "warning"
      );
    }
  });

  function openTxnModal() {
    const modal = document.getElementById("modal-transactions");
    if (!modal) return;
    modal.hidden = false;

    const wallets   = DB.get("kc_wallets");
    const txns      = DB.get("kc_transactions");
    const activeFilter = document.querySelector(".txn-filter-btn.active");
    const filter    = activeFilter ? activeFilter.dataset.filter : "all";
    const today     = new Date().toISOString().slice(0, 10);
    let todayTxns   = txns.filter((t) => t.timestamp && t.timestamp.startsWith(today));

    if (filter === "deposit")    todayTxns = todayTxns.filter((t) => t.type === "Deposit");
    if (filter === "withdrawal") todayTxns = todayTxns.filter((t) => t.type === "Withdrawal");

    const recent = [...todayTxns].reverse().slice(0, 100);
    const list   = document.getElementById("txn-list");
    if (!list) return;

    if (recent.length === 0) {
      list.innerHTML = `<div class="empty-state-small"><span class="material-icons-outlined">inbox</span><p>No transactions today</p></div>`;
      return;
    }

    list.innerHTML = recent.map((t) => {
      const wallet  = wallets.find((w) => w.id === t.wallet_id);
      const network = wallet ? wallet.carrier_type : "";
      const isDeposit = t.type === "Deposit";
      return `
        <div class="txn-item ${t.type.toLowerCase()} ${t.security_flag === "Mismatch" ? "flagged" : ""}">
          <div class="txn-icon-wrap ${t.type.toLowerCase()}">
            <span class="material-icons-outlined">${isDeposit ? "arrow_downward" : "arrow_upward"}</span>
          </div>
          <div class="txn-info">
            <span class="txn-type">${t.type} ${t.security_flag === "Mismatch" ? "⚠" : ""}</span>
            <span class="txn-party">${t.counterparty || "—"}</span>
          </div>
          <div class="txn-right">
            <span class="txn-network-badge ${network.toLowerCase()}">${network}</span>
            <span class="txn-time">${formatTime(new Date(t.timestamp))}</span>
            <span class="txn-amount ${isDeposit ? "credit" : "debit"}">
              ${isDeposit ? "+" : "-"}${formatUGX(t.amount)}
            </span>
          </div>
        </div>`;
    }).join("");
  }

  on("#btn-view-txns",     openTxnModal);
  on("#btn-view-all-txns", openTxnModal);

  // Filter tabs inside modal
  onAll(".txn-filter-btn", function () {
    document.querySelectorAll(".txn-filter-btn").forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    this.classList.add("active");
    this.setAttribute("aria-selected", "true");
    openTxnModal();
  });

  /* =================================================================
   * MONEY OUTSIDE — tabs use .tab-btn (fixed from .mo-tab)
   * ============================================================== */
  onAll(".tab-btn", function () {
    // Only affect the money-outside tab group
    const parentGroup = this.closest(".money-tabs");
    if (!parentGroup) return;
    parentGroup.querySelectorAll(".tab-btn").forEach((t) => {
      t.classList.remove("active");
      t.setAttribute("aria-selected", "false");
    });
    this.classList.add("active");
    this.setAttribute("aria-selected", "true");
    refreshMoneyOutside();
  });

  on("#btn-add-loan", () => {
    const modal = document.getElementById("modal-add-loan");
    if (modal) modal.hidden = false;
  });

  // Direction buttons in loan form
  onAll(".direction-btn", function () {
    document.querySelectorAll(".direction-btn").forEach((b) => b.classList.remove("selected"));
    this.classList.add("selected");
  });

  on("#btn-submit-loan", () => {
    const nameEl   = document.getElementById("loan-person");
    const amountEl = document.getElementById("loan-amount");
    const dueEl    = document.getElementById("loan-due");
    const notesEl  = document.getElementById("loan-notes");
    // Get selected direction from button — fixed: was looking for #loan-direction select
    const dirBtn   = document.querySelector(".direction-btn.selected");

    if (!nameEl || !nameEl.value.trim()) {
      showToast("Enter the person's name", "warning");
      return;
    }
    if (!amountEl || !Number(amountEl.value)) {
      showToast("Enter a valid amount", "warning");
      return;
    }

    const kiosks  = DB.get("kc_kiosks");
    const kioskId = kiosks.length > 0 ? kiosks[0].id : DB.generateUUID();

    const entry = {
      id:                    DB.generateUUID(),
      kiosk_id:              kioskId,
      party_name:            nameEl.value.trim(),
      transaction_direction: dirBtn ? dirBtn.dataset.direction : "Lent_Out",
      principal_amount:      Number(amountEl.value),
      repaid_amount:         0,
      repayment_target_date: dueEl && dueEl.value
        ? new Date(dueEl.value).toISOString()
        : new Date(Date.now() + 14 * 86400000).toISOString(),
      cleared_timestamp:     null,
      status:                "Active",
      notes:                 notesEl ? notesEl.value : "",
      created_at:            new Date().toISOString(),
    };

    const entries = DB.get("kc_money_outside");
    entries.push(entry);
    DB.set("kc_money_outside", entries);

    const modal = document.getElementById("modal-add-loan");
    if (modal) modal.hidden = true;

    showToast("Entry added ✓", "success");
    refreshMoneyOutside();

    // Clear form
    if (nameEl)   nameEl.value   = "";
    if (amountEl) amountEl.value = "";
    if (notesEl)  notesEl.value  = "";
  });

  /* =================================================================
   * TARIFF CALCULATOR — use .tariff-network-btn / .tariff-type-btn
   * ============================================================== */
  onAll(".tariff-network-btn", function () {
    document.querySelectorAll(".tariff-network-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
    refreshTariff(); // regenerate quick-ref table for selected network
  });

  onAll(".tariff-type-btn", function () {
    document.querySelectorAll(".tariff-type-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
  });

  on("#btn-calc-tariff", () => {
    const amtInput = document.getElementById("tariff-amount");
    const amount   = amtInput ? Number(String(amtInput.value).replace(/,/g, "")) : 0;
    if (!amount || amount < 500) {
      showToast("Enter an amount of at least UGX 500", "warning");
      return;
    }

    const netBtn  = document.querySelector(".tariff-network-btn.active");
    const typeBtn = document.querySelector(".tariff-type-btn.active");
    const network = netBtn  ? netBtn.dataset.network  || "MTN"        : "MTN";
    const type    = typeBtn ? typeBtn.dataset.type     || "Withdrawal" : "Withdrawal";

    const result  = Tariff.calculate(amount, network, type);

    const card    = document.getElementById("tariff-result");
    const config  = DB.get("kc_config") || {};
    const taxRate = config.tax_rate !== undefined ? config.tax_rate : 0.5;

    if (card) {
      card.hidden = false;
      document.getElementById("result-amount").textContent     = formatUGX(result.amount);
      document.getElementById("result-fee").textContent        = formatUGX(result.fee);
      document.getElementById("result-tax").textContent        = `${formatUGX(result.tax)} (${taxRate}%)`;
      document.getElementById("result-commission").textContent = formatUGX(result.commission);
      document.getElementById("result-total").textContent      = formatUGX(result.customerPays);
      card.classList.add("fade-in");
    }
  });

  /* =================================================================
   * ANALYTICS
   * ============================================================== */
  onAll(".analytics-range-btn", function () {
    document.querySelectorAll(".analytics-range-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
    refreshAnalytics();
  });

  on("#btn-export-report", () => {
    const txns    = DB.get("kc_transactions");
    const config  = DB.get("kc_config") || {};
    const today   = new Date().toISOString().slice(0, 10);
    const todayTxns = txns.filter((t) => t.timestamp && t.timestamp.startsWith(today));

    const dep  = todayTxns.filter((t) => t.type === "Deposit")    .reduce((s, t) => s + t.amount, 0);
    const wd   = todayTxns.filter((t) => t.type === "Withdrawal")  .reduce((s, t) => s + t.amount, 0);
    const comm = todayTxns.reduce((s, t) => s + (t.commission_earned || 0), 0);

    const report = `*KioskControl Daily Report — ${today}*
Business: ${config.business_name || "—"}

📥 Deposits:      ${formatUGX(dep)}
📤 Withdrawals:   ${formatUGX(wd)}
💰 Commission:    ${formatUGX(comm)}
🔢 Transactions:  ${todayTxns.length}

Generated by KioskControl UG`;

    const waUrl = `https://wa.me/?text=${encodeURIComponent(report)}`;
    window.open(waUrl, "_blank");
  });

  /* =================================================================
   * AUDIT SCREEN
   * ============================================================== */
  on("#btn-verify-audit", () => {
    const inputFloat = document.getElementById("audit-actual-float");
    const inputCash  = document.getElementById("audit-actual-cash");

    const actualFloat = inputFloat ? Number(String(inputFloat.value).replace(/,/g, "")) : 0;
    const actualCash  = inputCash  ? Number(String(inputCash.value).replace(/,/g, ""))  : 0;

    if (!actualFloat && !actualCash) {
      showToast("Enter at least one actual balance", "warning");
      return;
    }

    const wallets      = DB.get("kc_wallets");
    const expectedFloat = wallets.reduce((s, w) => s + (w.current_float || 0), 0);
    const expectedCash  = wallets.reduce((s, w) => s + (w.current_cash  || 0), 0);

    const floatDiff = expectedFloat - actualFloat;
    const cashDiff  = expectedCash  - actualCash;

    const discEl = document.getElementById("audit-discrepancy");
    if (discEl) {
      discEl.hidden = false;
      const txt = discEl.querySelector(".discrepancy-text");
      const parts = [];
      if (actualFloat > 0) {
        parts.push(`Float: ${formatUGX(Math.abs(floatDiff))} ${floatDiff > 0 ? "short" : floatDiff < 0 ? "over" : "✓ match"}`);
      }
      if (actualCash > 0) {
        parts.push(`Cash: ${formatUGX(Math.abs(cashDiff))} ${cashDiff > 0 ? "short" : cashDiff < 0 ? "over" : "✓ match"}`);
      }
      if (txt) txt.textContent = parts.join(" | ");
      discEl.className = `discrepancy-alert ${(Math.abs(floatDiff) > 500 || Math.abs(cashDiff) > 500) ? "alert-warn" : "alert-ok"}`;
    }

    // AI Diagnosis (on float)
    const diagEl = document.getElementById("audit-diagnosis");
    if (diagEl && actualFloat > 0) {
      diagEl.hidden = false;
      const diagnosis = AIReconciler.diagnose(expectedFloat, actualFloat);
      const listEl    = document.getElementById("diagnosis-list");
      if (listEl) {
        if (typeof diagnosis === "string") {
          listEl.innerHTML = `<li class="diag-perfect">${diagnosis}</li>`;
        } else {
          listEl.innerHTML = diagnosis.map((d) => `
            <li class="diag-item">
              <span class="diag-icon">${d.icon}</span>
              <span class="diag-text">${d.text}</span>
              ${d.amount ? `<span class="diag-amount">${formatUGX(d.amount)}</span>` : ""}
            </li>`).join("");
        }
      }
    }

    // Update reconciliation count
    const profiles = DB.get("kc_credit_profiles");
    if (profiles.length > 0) {
      profiles[0].last_reconciled_at    = new Date().toISOString();
      profiles[0].last_reconciled_count = (profiles[0].last_reconciled_count || 0) + 1;
      DB.set("kc_credit_profiles", profiles);
    }

    showToast("Reconciliation complete", "success");
  });

  /* =================================================================
   * SETTINGS
   * ============================================================== */
  on("#btn-change-pin", () => {
    const config = DB.get("kc_config");
    if (config) {
      config.pin = null;
      DB.set("kc_config", config);
      Nav.goto("pin-setup");
    }
  });

  on("#btn-backup", () => {
    const b64  = DB.export();
    const area = document.getElementById("backup-code-area");
    const ta   = document.getElementById("backup-textarea");
    if (area) { area.hidden = false; }
    if (ta)   { ta.value = b64; }

    if (navigator.clipboard) {
      navigator.clipboard
        .writeText(b64)
        .then(() => showToast("Backup copied to clipboard ✓", "success"))
        .catch(() => showToast("Backup generated — copy it manually", "info"));
    } else {
      showToast("Backup generated — copy it from the box", "info");
    }
  });

  on("#btn-copy-backup", () => {
    const ta = document.getElementById("backup-textarea");
    if (!ta) return;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(ta.value)
        .then(() => showToast("Copied ✓", "success"))
        .catch(() => { ta.select(); document.execCommand("copy"); showToast("Copied ✓", "success"); });
    } else {
      ta.select();
      document.execCommand("copy");
      showToast("Copied ✓", "success");
    }
  });

  on("#btn-restore", () => {
    const area = document.getElementById("restore-input-area");
    if (area) area.hidden = false;
  });

  on("#btn-restore-confirm", () => {
    const area = document.getElementById("restore-code-area");
    if (!area || !area.value.trim()) {
      showToast("Paste a backup code first", "warning");
      return;
    }
    const ok = DB.import(area.value.trim());
    if (ok) {
      showToast("Data restored! Reloading…", "success");
      setTimeout(() => location.reload(), 1200);
    } else {
      showToast("Invalid backup code", "error");
    }
  });

  on("#btn-wipe", () => {
    if (confirm("⚠ This will erase ALL data permanently. Are you sure?")) {
      DB.reset();
      showToast("All data wiped. Reloading…", "warning");
      setTimeout(() => location.reload(), 1200);
    }
  });

  on("#btn-save-tariffs", () => {
    const config    = DB.get("kc_config") || {};
    const taxInput  = document.getElementById("settings-tax-rate");
    const nameInput = document.getElementById("settings-biz-name");

    if (taxInput)  config.tax_rate     = Number(taxInput.value)  || 0.5;
    if (nameInput && nameInput.value.trim()) config.business_name = nameInput.value.trim();

    DB.set("kc_config", config);
    showToast("Settings saved ✓", "success");
    refreshDashboard();
  });

  /* =================================================================
   * SIMULATOR / CONTROL PANEL
   * ============================================================== */
  onAll(".sim-preset-btn", function () {
    const presetKey = this.getAttribute("data-preset");
    const preset    = SMS_PRESETS[presetKey];
    if (!preset) return;

    const wallets   = DB.get("kc_wallets");
    const netWallet = wallets.find((w) => w.carrier_type === preset.network);
    const curBal    = netWallet ? netWallet.current_float : 0;

    const text      = preset.textTemplate(curBal);
    const sender    = preset.sender;

    const senderInput = document.getElementById("sim-sender");
    const msgInput    = document.getElementById("sim-message");
    if (senderInput) senderInput.value = sender;
    if (msgInput)    msgInput.value    = text;

    logToSim(`━━━ Preset: ${presetKey} ━━━`, "info");
    processSimulatedSMS(sender, text);
  });

  on("#btn-sim-send", () => {
    const senderInput = document.getElementById("sim-sender");
    const msgInput    = document.getElementById("sim-message");
    const sender      = senderInput ? senderInput.value.trim() : "";
    const text        = msgInput    ? msgInput.value.trim()    : "";

    if (!sender || !text) {
      showToast("Enter both sender and message", "warning");
      return;
    }
    logToSim("━━━ Custom SMS ━━━", "info");
    processSimulatedSMS(sender, text);
  });

  /* ── Role Toggle ── */
  on("#role-owner", () => {
    const config = DB.get("kc_config") || {};
    config.role  = "owner";
    DB.set("kc_config", config);
    showToast("Switched to Owner view", "info");
    if (Nav.getCurrent()) Nav.goto(Nav.getCurrent());
  });

  on("#role-worker", () => {
    const config = DB.get("kc_config") || {};
    config.role  = "worker";
    DB.set("kc_config", config);
    showToast("Switched to Worker view (restricted)", "info");
    if (Nav.getCurrent()) Nav.goto(Nav.getCurrent());
  });

  /* ── Control Panel Buttons ── */
  on("#btn-reset-all", () => {
    if (confirm("Reset all data and reload?")) {
      DB.reset();
      location.reload();
    }
  });

  on("#btn-trigger-reminder", () => {
    const entries = DB.get("kc_money_outside").filter((e) => e.status === "Active");
    if (entries.length > 0) {
      const total = entries.reduce(
        (s, e) => s + (e.principal_amount - (e.repaid_amount || 0)), 0
      );
      showToast(
        `🔔 ${entries.length} outstanding entries — ${formatUGX(total)} to collect!`,
        "warning"
      );
    } else {
      showToast("🔔 No outstanding money outside. All clear!", "success");
    }
    Nav.goto("money-outside");
  });

  on("#btn-trigger-eod", () => {
    Nav.goto("audit");
  });

  on("#btn-run-scan", () => {
    Nav.goto("scan");
  });

  /* =================================================================
   * FRAUD OVERLAY
   * ============================================================== */
  on("#btn-dismiss-fraud", () => {
    const overlay = document.getElementById("fraud-alert-overlay");
    if (overlay) overlay.hidden = true;
  });

  /* =================================================================
   * MODALS — unified close via .modal-close class
   * ============================================================== */
  onAll(".modal-close", function () {
    const modal = this.closest(".modal-overlay");
    if (modal) modal.hidden = true;
  });

  // Close modal on backdrop click
  document.querySelectorAll(".modal-overlay").forEach((modal) => {
    modal.addEventListener("click", function (e) {
      if (e.target === this) this.hidden = true;
    });
  });
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 8. APP INITIALISATION
 * ────────────────────────────────────────────────────────────────────────── */

const App = (() => {
  function init() {
    attachEventHandlers();

    // Status-bar clock
    updateStatusBarTime();
    setInterval(updateStatusBarTime, 60000);

    // Determine starting screen
    const config = DB.get("kc_config");

    if (!config) {
      Nav.goto("consent");
    } else if (!config.pin) {
      Nav.goto("pin-setup");
    } else {
      Nav.goto("dashboard");
    }
  }

  return { init };
})();

/* ── Bootstrap ── */
document.addEventListener("DOMContentLoaded", App.init);

/* ── Global Ripple Effect ── */
document.addEventListener("click", function (e) {
  const btn = e.target.closest("button, .nav-item, .role-card, .tab-btn, .num-key");
  if (btn) {
    const rect = btn.getBoundingClientRect();
    const ripple = document.createElement("span");
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;
    
    ripple.style.width = ripple.style.height = `${size}px`;
    ripple.style.left = `${x}px`;
    ripple.style.top = `${y}px`;
    ripple.className = "ripple";
    
    btn.appendChild(ripple);
    setTimeout(() => ripple.remove(), 600);
  }
});
/ *   = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =  
   *   M U L T I - K I O S K   D A S H B O A R D   L O G I C  
   *   = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =   * /  
  
 f u n c t i o n   r e f r e s h M u l t i K i o s k ( )   {  
     c o n s t   g r i d   =   d o c u m e n t . g e t E l e m e n t B y I d ( " k i o s k - g r i d " ) ;  
     i f   ( ! g r i d )   r e t u r n ;  
  
     c o n s t   a l l P r o f i l e s   =   D B . g e t ( " k c _ c r e d i t _ p r o f i l e s " )   | |   [ ] ;  
     i f   ( a l l P r o f i l e s . l e n g t h   = = =   0 )   {  
         g r i d . i n n e r H T M L   =   ` < p   s t y l e = " c o l o r : v a r ( - - t e x t - m u t e d ) ;   t e x t - a l i g n : c e n t e r ;   p a d d i n g :   2 0 p x ; " > N o   k i o s k s   f o u n d . < / p > ` ;  
         r e t u r n ;  
     }  
  
     g r i d . i n n e r H T M L   =   a l l P r o f i l e s . m a p ( ( p ,   i n d e x )   = >   {  
         l e t   l o c   =   " N a n s a n a   M a i n " ;  
         l e t   f l o a t   =   D B . g e t ( " k c _ w a l l e t s " ) . r e d u c e ( ( s ,   w )   = >   s   +   ( w . c u r r e n t _ f l o a t   | |   0 ) ,   0 ) ;  
         l e t   m a n a g e r   =   " C o l l i n   ( Y o u ) " ;  
         l e t   s t a t u s   =   " n o r m a l " ;  
         l e t   s t a t u s L a b e l   =   " � � �   N o r m a l " ;  
         l e t   d a t a P t s   =   [ 4 ,   6 ,   5 ,   8 ,   7 ,   1 0 ,   9 ] ;  
          
         i f   ( i n d e x   = = =   1 )   {  
             l o c   =   " K y e b a n d o   B r a n c h " ;  
             f l o a t   =   8 5 0 0 0 0 ;  
             m a n a g e r   =   " S a r a h " ;  
             s t a t u s   =   " s h o r t a g e " ;  
             s t a t u s L a b e l   =   " � � � � � �   U G X   1 5 0 K   S h o r t a g e " ;  
             d a t a P t s   =   [ 8 ,   7 ,   5 ,   4 ,   3 ,   2 ,   4 ] ;  
         }   e l s e   i f   ( i n d e x   = = =   2 )   {  
             l o c   =   " M a k i n d y e   B r a n c h " ;  
             f l o a t   =   3 2 0 0 0 0 0 ;  
             m a n a g e r   =   " J o h n " ;  
             s t a t u s   =   " n o r m a l " ;  
             s t a t u s L a b e l   =   " � � �   N o r m a l " ;  
             d a t a P t s   =   [ 2 ,   3 ,   5 ,   8 ,   9 ,   1 2 ,   1 4 ] ;  
         }  
  
         r e t u r n   `  
             < d i v   c l a s s = " k i o s k - c a r d "   o n c l i c k = " o p e n K i o s k D e t a i l ( ' $ { l o c } ' ,   ' $ { s t a t u s L a b e l } ' ,   $ { f l o a t } ) " >  
                 < d i v   c l a s s = " k i o s k - h e a d e r " >  
                     < d i v   c l a s s = " k i o s k - i n f o " >  
                         < h 3 > $ { l o c } < / h 3 >  
                         < s p a n   c l a s s = " k i o s k - m a n a g e r " > M a n a g e r :   $ { m a n a g e r } < / s p a n >  
                     < / d i v >  
                     < d i v   c l a s s = " k i o s k - s t a t u s - b a d g e   $ { s t a t u s } " > $ { s t a t u s L a b e l } < / d i v >  
                 < / d i v >  
                 < d i v   c l a s s = " k i o s k - m e t r i c s " >  
                     < d i v   c l a s s = " k i o s k - m e t r i c - b l o c k " >  
                         < s p a n   c l a s s = " k i o s k - m e t r i c - l a b e l " > T o t a l   C a p i t a l < / s p a n >  
                         < s p a n   c l a s s = " k i o s k - m e t r i c - v a l u e " > $ { f o r m a t U G X ( f l o a t ) } < / s p a n >  
                     < / d i v >  
                     < d i v   c l a s s = " k i o s k - s p a r k l i n e - c o n t a i n e r " >  
                         < c a n v a s   i d = " s p a r k l i n e - $ { i n d e x } "   c l a s s = " k i o s k - s p a r k l i n e " > < / c a n v a s >  
                     < / d i v >  
                 < / d i v >  
             < / d i v >  
         ` ;  
     } ) . j o i n ( " " ) ;  
  
     a l l P r o f i l e s . f o r E a c h ( ( p ,   i n d e x )   = >   {  
         c o n s t   c a n v a s   =   d o c u m e n t . g e t E l e m e n t B y I d ( ` s p a r k l i n e - $ { i n d e x } ` ) ;  
         l e t   d a t a P t s   =   [ 4 ,   6 ,   5 ,   8 ,   7 ,   1 0 ,   9 ] ;  
         i f   ( i n d e x   = = =   1 )   d a t a P t s   =   [ 8 ,   7 ,   5 ,   4 ,   3 ,   2 ,   4 ] ;  
         i f   ( i n d e x   = = =   2 )   d a t a P t s   =   [ 2 ,   3 ,   5 ,   8 ,   9 ,   1 2 ,   1 4 ] ;  
         i f   ( c a n v a s )   d r a w S p a r k l i n e ( c a n v a s ,   d a t a P t s ) ;  
     } ) ;  
 }  
  
 f u n c t i o n   o p e n K i o s k D e t a i l ( n a m e ,   s t a t u s L a b e l ,   t o t a l F l o a t )   {  
     c o n s t   m o d a l   =   d o c u m e n t . g e t E l e m e n t B y I d ( " m o d a l - k i o s k - d e t a i l " ) ;  
     c o n s t   t i t l e   =   d o c u m e n t . g e t E l e m e n t B y I d ( " m o d a l - k i o s k - n a m e " ) ;  
     c o n s t   b o d y   =   d o c u m e n t . g e t E l e m e n t B y I d ( " m o d a l - k i o s k - b o d y " ) ;  
      
     i f   ( m o d a l   & &   t i t l e   & &   b o d y )   {  
         t i t l e . t e x t C o n t e n t   =   n a m e ;  
         b o d y . i n n e r H T M L   =   `  
             < d i v   c l a s s = " k d - s t a t - r o w " >  
                 < s p a n   c l a s s = " k d - l a b e l " > M T N   F l o a t < / s p a n >  
                 < s p a n   c l a s s = " k d - v a l u e " > $ { f o r m a t U G X ( t o t a l F l o a t   *   0 . 6 ) } < / s p a n >  
             < / d i v >  
             < d i v   c l a s s = " k d - s t a t - r o w " >  
                 < s p a n   c l a s s = " k d - l a b e l " > A i r t e l   F l o a t < / s p a n >  
                 < s p a n   c l a s s = " k d - v a l u e " > $ { f o r m a t U G X ( t o t a l F l o a t   *   0 . 3 ) } < / s p a n >  
             < / d i v >  
             < d i v   c l a s s = " k d - s t a t - r o w " >  
                 < s p a n   c l a s s = " k d - l a b e l " > C a s h   i n   D r a w e r < / s p a n >  
                 < s p a n   c l a s s = " k d - v a l u e " > $ { f o r m a t U G X ( t o t a l F l o a t   *   0 . 1 ) } < / s p a n >  
             < / d i v >  
             $ { s t a t u s L a b e l . i n c l u d e s ( ' S h o r t a g e ' )   ?   `  
                 < d i v   c l a s s = " k d - a l e r t - b o x " >  
                     < s t r o n g > � � � � � �   S h o r t a g e   D e t e c t e d < / s t r o n g > < b r >  
                     S y s t e m   e x p e c t e d   U G X   1 , 0 0 0 , 0 0 0   i n   C a p i t a l   b a s e d   o n   E n d   o f   D a y   a u d i t ,   b u t   a g e n t   r e p o r t e d   U G X   8 5 0 , 0 0 0 .  
                 < / d i v >  
             `   :   ' ' }  
         ` ;  
         m o d a l . h i d d e n   =   f a l s e ;  
     }  
 }  
  
 f u n c t i o n   d r a w S p a r k l i n e ( c a n v a s ,   d a t a )   {  
     c o n s t   c t x   =   c a n v a s . g e t C o n t e x t ( ' 2 d ' ) ;  
     c o n s t   w   =   c a n v a s . w i d t h   =   c a n v a s . o f f s e t W i d t h ;  
     c o n s t   h   =   c a n v a s . h e i g h t   =   c a n v a s . o f f s e t H e i g h t ;  
      
     c t x . c l e a r R e c t ( 0 ,   0 ,   w ,   h ) ;  
     c o n s t   m a x   =   M a t h . m a x ( . . . d a t a ) ;  
     c o n s t   s t e p   =   w   /   ( d a t a . l e n g t h   -   1 ) ;  
      
     c t x . b e g i n P a t h ( ) ;  
     c t x . m o v e T o ( 0 ,   h   -   ( d a t a [ 0 ] / m a x ) * h ) ;  
     f o r ( l e t   i = 1 ;   i < d a t a . l e n g t h ;   i + + )   {  
         c t x . l i n e T o ( i * s t e p ,   h   -   ( d a t a [ i ] / m a x ) * h ) ;  
     }  
     c t x . s t r o k e S t y l e   =   ' # 8 B 5 C F 6 ' ;  
     c t x . l i n e W i d t h   =   2 ;  
     c t x . s t r o k e ( ) ;  
 }  
  
 / /   H o o k   u p   t h e   C o n t r o l   P a n e l   b u t t o n   a n d   R o l e   r e s t r i c t i o n s  
 d o c u m e n t . a d d E v e n t L i s t e n e r ( " D O M C o n t e n t L o a d e d " ,   ( )   = >   {  
     c o n s t   b t n S e e d   =   d o c u m e n t . g e t E l e m e n t B y I d ( " b t n - s e e d - k i o s k s " ) ;  
     i f   ( b t n S e e d )   {  
         b t n S e e d . a d d E v e n t L i s t e n e r ( " c l i c k " ,   ( )   = >   {  
             c o n s t   p r o f i l e s   =   D B . g e t ( " k c _ c r e d i t _ p r o f i l e s " )   | |   [ ] ;  
             i f   ( p r o f i l e s . l e n g t h   = = =   1 )   {  
                 p r o f i l e s . p u s h ( {   i d :   D B . g e n e r a t e U U I D ( ) ,   k i o s k _ i d :   " k y e b a n d o - 1 " ,   k i o s k _ s t a b i l i t y _ s c o r e :   4 5   } ) ;  
                 p r o f i l e s . p u s h ( {   i d :   D B . g e n e r a t e U U I D ( ) ,   k i o s k _ i d :   " m a k i n d y e - 1 " ,   k i o s k _ s t a b i l i t y _ s c o r e :   9 5   } ) ;  
                 D B . s e t ( " k c _ c r e d i t _ p r o f i l e s " ,   p r o f i l e s ) ;  
                 s h o w T o a s t ( " S e e d e d   2   r e m o t e   k i o s k s   f o r   d e m o " ,   " s u c c e s s " ) ;  
                 i f   ( N a v . g e t C u r r e n t ( )   = = =   " m u l t i - k i o s k " )   r e f r e s h M u l t i K i o s k ( ) ;  
             }  
         } ) ;  
     }  
  
     / /   H a n d l e   w o r k e r   r o l e   r e s t r i c t i o n s   d y n a m i c a l l y  
     c o n s t   o r i g R o l e S w i t c h   =   d o c u m e n t . g e t E l e m e n t B y I d ( " r o l e - w o r k e r " ) ;  
     i f   ( o r i g R o l e S w i t c h )   {  
         o r i g R o l e S w i t c h . a d d E v e n t L i s t e n e r ( " c h a n g e " ,   ( )   = >   {  
             c o n s t   n a v M u l t i   =   d o c u m e n t . g e t E l e m e n t B y I d ( " n a v - m u l t i - k i o s k " ) ;  
             i f   ( n a v M u l t i )   n a v M u l t i . s t y l e . d i s p l a y   =   " n o n e " ;  
         } ) ;  
     }  
     c o n s t   o r i g R o l e O w n e r   =   d o c u m e n t . g e t E l e m e n t B y I d ( " r o l e - o w n e r " ) ;  
     i f   ( o r i g R o l e O w n e r )   {  
         o r i g R o l e O w n e r . a d d E v e n t L i s t e n e r ( " c h a n g e " ,   ( )   = >   {  
             c o n s t   n a v M u l t i   =   d o c u m e n t . g e t E l e m e n t B y I d ( " n a v - m u l t i - k i o s k " ) ;  
             i f   ( n a v M u l t i )   n a v M u l t i . s t y l e . d i s p l a y   =   " f l e x " ;  
         } ) ;  
     }  
  
     / /   I n i t i a l   h i d i n g   i f   a l r e a d y   w o r k e r  
     c o n s t   r o l e   =   ( D B . g e t ( " k c _ c o n f i g " )   | |   { } ) . r o l e   | |   " o w n e r " ;  
     c o n s t   n a v M u l t i   =   d o c u m e n t . g e t E l e m e n t B y I d ( " n a v - m u l t i - k i o s k " ) ;  
     i f   ( n a v M u l t i )   {  
         n a v M u l t i . s t y l e . d i s p l a y   =   r o l e   = = =   " w o r k e r "   ?   " n o n e "   :   " f l e x " ;  
     }  
 } ) ;  
 
/* ============================================================================
   NATIVE ANDROID SMS BRIDGE � Production Bridge
   ---------------------------------------------------------------------------
   SmsBroadcastReceiver.java fires 'nativeSmsReceived' via evaluateJavascript.
   This listener catches that event and routes it through the same
   processSimulatedSMS() pipeline used by the simulator, meaning:
   - Regex parsing  (Parser module)
   - Fraud detection (Security module � 3-layer)
   - DB write + wallet update
   - Toast notification to the agent
   Works on any Android 6+ device with a real MTN/Airtel SIM.
   ============================================================================ */

window.addEventListener('nativeSmsReceived', function(event) {
  const { sender, body, isTrusted } = event.detail;

  // Safety: ignore empty payloads
  if (!body || body.trim() === '') return;

  // Route directly into the core SMS processing pipeline
  processSimulatedSMS(sender || 'UNKNOWN', body);

  // Show a subtle 'auto-recorded' indicator on the dashboard
  const config = DB.get('kc_config') || {};
  if (config.role !== 'worker') {
    showToast('SMS auto-recorded \u2714 ' + (isTrusted ? '' : '\u26a0\ufe0f Verify sender!'), isTrusted ? 'success' : 'warning');
  }

  // If dashboard is currently visible, refresh it immediately
  if (Nav.getCurrent() === 'dashboard') {
    refreshDashboard();
  }
});

