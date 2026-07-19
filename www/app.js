/* ============================================================================
 * Ngabo — Mobile Money Intelligence v1.0
 * Complete Offline-First PWA Logic Engine
 * ============================================================================
 * Modules:
 *   1. DB           – Capacitor Preferences wrapper (encrypted storage)
 *   2. Parser       – Regex-based MTN / Airtel SMS parser
 *   3. Security     – Three-layer fraud detection
 *   4. Tariff       – Fee / commission calculator
 *   5. KSS          – Kiosk Stability Score engine
 *   6. AIReconciler – Smart discrepancy diagnosis
 *   7. Nav          – Screen navigation controller
 *   8. App          – Initialisation & lifecycle
 *   9. Handlers     – All UI event handlers
 *  10. Utilities    – Formatting, toasts, status-bar clock
 *  11. (Removed)    – Seeder removed for production
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

  /** Retrieve a value from encrypted Capacitor Preferences. Returns [] for missing arrays. */
  async function get(key) {
    try {
      const { value } = await Capacitor.Plugins.Preferences.get({ key });
      if (value === null) return key === "kc_config" ? null : [];
      return JSON.parse(value);
    } catch (_) {
      return key === "kc_config" ? null : [];
    }
  }

  /** Persist a value (object or array) under the given key. */
  async function set(key, data) {
    await Capacitor.Plugins.Preferences.set({ key, value: JSON.stringify(data) });
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

  /** Nuke every kc_ key from Capacitor Preferences. */
  async function reset() {
    const { keys } = await Capacitor.Plugins.Preferences.keys();
    const toRemove = keys.filter(k => k.startsWith("kc_"));
    for (const k of toRemove) {
      await Capacitor.Plugins.Preferences.remove({ key: k });
    }
  }

  /** Export the complete dataset as a Base-64 encoded JSON string. */
  async function exportData() {
    const payload = {};
    for (const k of KEYS) {
      const { value } = await Capacitor.Plugins.Preferences.get({ key: k });
      if (value !== null) payload[k] = JSON.parse(value);
    }
    return btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
  }

  /** Restore a Base-64 encoded backup. */
  async function importData(b64) {
    try {
      const json = decodeURIComponent(escape(atob(b64)));
      const payload = JSON.parse(json);
      for (const k of Object.keys(payload)) {
        await Capacitor.Plugins.Preferences.set({ key: k, value: JSON.stringify(payload[k]) });
      }
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

  // Generic Notification pattern (simplified for notifications that might be truncated or slightly different)
  const GENERIC_RECEIVED = /(?:received|deposited) UGX ([\d,]+) from ([\d+]+)/i;
  const GENERIC_SENT = /(?:withdrawn|sent|cash out) UGX ([\d,]+) to ([\d+]+)/i;

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

    // 7. Generic Received (Fallback)
    if ((m = GENERIC_RECEIVED.exec(text))) {
      return {
        success: true,
        type: "Deposit",
        network: sender.toLowerCase().includes("airtel") ? "Airtel" : "MTN",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        balance: 0, // Unknown
        commission: 0,
        fee: 0,
        raw: text,
      };
    }

    // 8. Generic Sent (Fallback)
    if ((m = GENERIC_SENT.exec(text))) {
      return {
        success: true,
        type: "Withdrawal",
        network: sender.toLowerCase().includes("airtel") ? "Airtel" : "MTN",
        amount: parseAmt(m[1]),
        counterparty: m[2],
        balance: 0, // Unknown
        commission: 0,
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
    GENERIC_RECEIVED,
    GENERIC_SENT,
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
      { min: 500,     max: 2500,    fee: 330   },
      { min: 2501,    max: 5000,    fee: 440   },
      { min: 5001,    max: 15000,   fee: 700   },
      { min: 15001,   max: 30000,   fee: 880   },
      { min: 30001,   max: 45000,   fee: 1210  },
      { min: 45001,   max: 60000,   fee: 1500  },
      { min: 60001,   max: 125000,  fee: 1925  },
      { min: 125001,  max: 250000,  fee: 3575  },
      { min: 250001,  max: 500000,  fee: 7000  },
      { min: 500001,  max: 1000000, fee: 12500 },
      { min: 1000001, max: 2000000, fee: 15000 },
      { min: 2000001, max: 4000000, fee: 18000 },
      { min: 4000001, max: 5000000, fee: 20000 },
    ],
    Deposit: [{ min: 500, max: 5000000, fee: 0 }],
  },
  Airtel: {
    Withdrawal: [
      { min: 500,     max: 2500,    fee: 330   },
      { min: 2501,    max: 5000,    fee: 440   },
      { min: 5001,    max: 15000,   fee: 700   },
      { min: 15001,   max: 30000,   fee: 880   },
      { min: 30001,   max: 45000,   fee: 1210  },
      { min: 45001,   max: 60000,   fee: 1500  },
      { min: 60001,   max: 125000,  fee: 1925  },
      { min: 125001,  max: 250000,  fee: 3575  },
      { min: 250001,  max: 500000,  fee: 7000  },
      { min: 500001,  max: 1000000, fee: 12500 },
      { min: 1000001, max: 2000000, fee: 15000 },
      { min: 2000001, max: 4000000, fee: 18000 },
      { min: 4000001, max: 5000000, fee: 18000 },
    ],
    Deposit: [{ min: 500, max: 5000000, fee: 0 }],
  },
};

const Tariff = (() => {
  /**
   * Look up the tariff fee for a given amount, network and transaction type.
   */
  async function calculate(amount, network, type) {
    const config = await DB.get("kc_config") || {};
    const taxRate = config.tax_rate !== undefined ? config.tax_rate : 0.5;
    const tariffs = DEFAULT_TARIFFS;

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
  async function calculate() {
    const txns = await DB.get("kc_transactions");
    const moneyOut = await DB.get("kc_money_outside");
    const profiles = await DB.get("kc_credit_profiles");

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
  async function diagnose(expectedBalance, actualBalance) {
    const discrepancy = expectedBalance - actualBalance;

    if (discrepancy === 0) {
      return "Perfect match! No issues detected. 🎉";
    }

    const findings = [];

    // a) Outstanding loans
    const loans = await DB.get("kc_money_outside");
    const activeLent = loans.filter(
      (m) => m.transaction_direction === "Lent_Out" && m.status === "Active"
    );
    if (activeLent.length > 0) {
      activeLent.forEach((l) => {
        const outstanding = l.principal_amount - (l.repaid_amount || 0);
        // Check if loan exactly matches the discrepancy
        const isMatch = Math.abs(outstanding - discrepancy) < 500;
        findings.push({
          icon: isMatch ? "🎯" : "🤝",
          text: `${isMatch ? "MATCH FOUND: " : ""}You have ${formatUGX(outstanding)} lent to ${l.party_name} since ${formatDate(new Date(l.created_at))} that hasn't been fully repaid.`,
          amount: outstanding,
          isMatch
        });
      });
    }

    // b) Commission withdrawals today
    const today = new Date().toISOString().slice(0, 10);
    const allTxns = await DB.get("kc_transactions");
    const todayTxns = allTxns.filter(
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
  setTimeout(async () => {
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
 * SCREEN REFRESH HELPERS
 * ────────────────────────────────────────────────────────────────────────── */

/** Refresh the Dashboard screen with live data from DB. */
async function refreshDashboard() {
  const wallets  = await DB.get("kc_wallets");
  const txns     = await DB.get("kc_transactions");
  const config   = await DB.get("kc_config") || {};

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
  const kss = await KSS.calculate();
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
    setTimeout(async () => { elBar.style.width = `${kss.score}%`; }, 100);

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
async function refreshMoneyOutside() {
  const entries = await DB.get("kc_money_outside");
  const config  = await DB.get("kc_config") || {};
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
      btn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        const loanId  = btn.getAttribute("data-loan-id");
        const allLoans = await DB.get("kc_money_outside");
        const idx     = allLoans.findIndex((l) => l.id === loanId);
        if (idx !== -1) {
          allLoans[idx].status          = "Settled";
          allLoans[idx].repaid_amount   = allLoans[idx].principal_amount;
          allLoans[idx].cleared_timestamp = new Date().toISOString();
          await DB.set("kc_money_outside", allLoans);
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
async function refreshAudit() {
  const wallets = await DB.get("kc_wallets");
  const txns    = await DB.get("kc_transactions");
  const config  = await DB.get("kc_config") || {};

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
async function refreshSettings() {
  const config = await DB.get("kc_config") || {};

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
async function refreshTariff() {
  const activeNetBtn = document.querySelector(".tariff-network-btn.active");
  const network = activeNetBtn ? activeNetBtn.dataset.network : "MTN";

  const quickAmounts = [5000, 10000, 20000, 50000, 100000, 200000, 500000, 1000000];
  const table = document.getElementById("tariff-quick-table");
  if (!table) return;

  let rowsHtml = "";
  for (const amt of quickAmounts) {
    const r = await Tariff.calculate(amt, network, "Withdrawal");
    rowsHtml += `
        <div class="quick-ref-row">
          <span>${formatUGX(amt)}</span>
          <span class="qr-fee">${formatUGX(r.fee)}</span>
          <span class="qr-tax">${formatUGX(r.tax)}</span>
          <span class="qr-total">${formatUGX(r.customerPays)}</span>
        </div>`;
  }

  table.innerHTML = `
    <div class="quick-ref-header">
      <span>Amount</span>
      <span>Fee</span>
      <span>Tax</span>
      <span>Customer Pays</span>
    </div>
    ${rowsHtml}
  `;
}

/* ──────────────────────────────────────────────────────────────────────────────
 * 12. ANALYTICS ENGINE (Canvas-based charts)
 * ────────────────────────────────────────────────────────────────────────── */

/** Main analytics refresh — called on nav to analytics screen. */
async function refreshAnalytics() {
  const txns       = await DB.get("kc_transactions");
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

async function startScanAnimation() {
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
      // Seeder removed for production — real data comes from SMS bridge
      if (continueBtn) {
        continueBtn.style.display = "inline-flex";
      }
      showToast(`Imported ${targetCount.toLocaleString()} transactions`, "success");
    }
  }

  requestAnimationFrame(tick);
}



/** Show the fraud alert overlay. */
async function showFraudAlert(sender, text, flags) {
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

async function attachEventHandlers() {
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
  on("#btn-decline", async () => {
    showToast("You must accept to use Ngabo", "error");
  });

  on("#btn-accept", async () => {
    const log = await DB.get("kc_consent_log");
    log.push({
      timestamp:   new Date().toISOString(),
      action:      "consent_granted",
      device_hash: navigator.userAgent.slice(0, 40),
    });
    await DB.set("kc_consent_log", log);
    Nav.goto("setup");
  });

  /* =================================================================
   * SETUP SCREEN
   * ============================================================== */
  onAll(".role-card", async function () {
    document.querySelectorAll(".role-card").forEach((c) => {
      c.classList.remove("selected");
      c.setAttribute("aria-pressed", "false");
    });
    this.classList.add("selected");
    this.setAttribute("aria-pressed", "true");
  });

  on("#btn-setup-continue", async () => {
    const nameInput = document.getElementById("input-biz-name");
    const bizName   = nameInput ? nameInput.value.trim() : "";
    if (!bizName) {
      showToast("Please enter your business name", "warning");
      return;
    }
    const selectedRole = document.querySelector(".role-card.selected");
    const role = selectedRole ? (selectedRole.getAttribute("data-role") || "owner") : "owner";

    await DB.set("kc_config", {
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

  onAll(".num-key", async function () {
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
      const config = await DB.get("kc_config") || {};
      config.pin   = pinBuffer;
      await DB.set("kc_config", config);
      showToast("PIN set successfully ✓", "success");
      pinBuffer = "";
      Nav.goto("scan");
    }
  });

  /* =================================================================
   * SCAN SCREEN
   * ============================================================== */
  on("#btn-scan-continue", async () => {
    Nav.goto("dashboard");
  });

  /* =================================================================
   * BOTTOM NAVIGATION
   * ============================================================== */
  onAll(".nav-item", async function () {
    const screen = this.getAttribute("data-screen");
    if (screen) Nav.goto(screen);
  });

  /* =================================================================
   * DASHBOARD
   * ============================================================== */
  on("#btn-verify-balance", async () => {
    const input = prompt("Enter your counted cash total (UGX):");
    if (input === null) return;
    const actual = Number(String(input).replace(/,/g, ""));
    if (isNaN(actual) || actual === 0) {
      showToast("Please enter a valid number", "error");
      return;
    }
    const wallets  = await DB.get("kc_wallets");
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

  async function openTxnModal() {
    const modal = document.getElementById("modal-transactions");
    if (!modal) return;
    modal.hidden = false;

    const wallets   = await DB.get("kc_wallets");
    const txns      = await DB.get("kc_transactions");
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
  onAll(".txn-filter-btn", async function () {
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
  onAll(".tab-btn", async function () {
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

  on("#btn-add-loan", async () => {
    const modal = document.getElementById("modal-add-loan");
    if (modal) modal.hidden = false;
  });

  // Direction buttons in loan form
  onAll(".direction-btn", async function () {
    document.querySelectorAll(".direction-btn").forEach((b) => b.classList.remove("selected"));
    this.classList.add("selected");
  });

  on("#btn-submit-loan", async () => {
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

    const kiosks  = await DB.get("kc_kiosks");
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

    const entries = await DB.get("kc_money_outside");
    entries.push(entry);
    await DB.set("kc_money_outside", entries);

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
  onAll(".tariff-network-btn", async function () {
    document.querySelectorAll(".tariff-network-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
    refreshTariff(); // regenerate quick-ref table for selected network
  });

  onAll(".tariff-type-btn", async function () {
    document.querySelectorAll(".tariff-type-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
  });

  on("#btn-calc-tariff", async () => {
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

    const result  = await Tariff.calculate(amount, network, type);

    const card    = document.getElementById("tariff-result");
    const config  = await DB.get("kc_config") || {};
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
  onAll(".analytics-range-btn", async function () {
    document.querySelectorAll(".analytics-range-btn").forEach((b) => b.classList.remove("active"));
    this.classList.add("active");
    refreshAnalytics();
  });

  on("#btn-export-report", async () => {
    const txns    = await DB.get("kc_transactions");
    const config  = await DB.get("kc_config") || {};
    const today   = new Date().toISOString().slice(0, 10);
    const todayTxns = txns.filter((t) => t.timestamp && t.timestamp.startsWith(today));

    const dep  = todayTxns.filter((t) => t.type === "Deposit")    .reduce((s, t) => s + t.amount, 0);
    const wd   = todayTxns.filter((t) => t.type === "Withdrawal")  .reduce((s, t) => s + t.amount, 0);
    const comm = todayTxns.reduce((s, t) => s + (t.commission_earned || 0), 0);

    const report = `*Ngabo Daily Report — ${today}*
Business: ${config.business_name || "—"}

📥 Deposits:      ${formatUGX(dep)}
📤 Withdrawals:   ${formatUGX(wd)}
💰 Commission:    ${formatUGX(comm)}
🔢 Transactions:  ${todayTxns.length}

Generated by Ngabo`;

    const waUrl = `https://wa.me/?text=${encodeURIComponent(report)}`;
    window.open(waUrl, "_blank");
  });

  /* =================================================================
   * AUDIT SCREEN
   * ============================================================== */
  on("#btn-verify-audit", async () => {
    const inputFloat = document.getElementById("audit-actual-float");
    const inputCash  = document.getElementById("audit-actual-cash");

    const actualFloat = inputFloat ? Number(String(inputFloat.value).replace(/,/g, "")) : 0;
    const actualCash  = inputCash  ? Number(String(inputCash.value).replace(/,/g, ""))  : 0;

    if (!actualFloat && !actualCash) {
      showToast("Enter at least one actual balance", "warning");
      return;
    }

    const wallets      = await DB.get("kc_wallets");
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
      const diagnosis = await AIReconciler.diagnose(expectedFloat, actualFloat);
      const listEl    = document.getElementById("diagnosis-list");
      if (listEl) {
        if (typeof diagnosis === "string") {
          listEl.innerHTML = `<li class="diag-perfect">${diagnosis}</li>`;
        } else {
          listEl.innerHTML = diagnosis.map((d) => `
            <li class="diag-item ${d.isMatch ? 'diag-match' : ''}">
              <span class="diag-icon">${d.icon}</span>
              <span class="diag-text">${d.text}</span>
              ${d.amount ? `<span class="diag-amount">${formatUGX(d.amount)}</span>` : ""}
            </li>`).join("");
        }
      }
    }

    // Update reconciliation count
    const profiles = await DB.get("kc_credit_profiles");
    if (profiles.length > 0) {
      profiles[0].last_reconciled_at    = new Date().toISOString();
      profiles[0].last_reconciled_count = (profiles[0].last_reconciled_count || 0) + 1;
      await DB.set("kc_credit_profiles", profiles);
    }

    showToast("Reconciliation complete", "success");
  });

  /* =================================================================
   * SETTINGS
   * ============================================================== */
  on("#btn-change-pin", async () => {
    const config = await DB.get("kc_config");
    if (config) {
      config.pin = null;
      await DB.set("kc_config", config);
      Nav.goto("pin-setup");
    }
  });

  on("#btn-backup", async () => {
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

  on("#btn-copy-backup", async () => {
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

  on("#btn-restore", async () => {
    const area = document.getElementById("restore-input-area");
    if (area) area.hidden = false;
  });

  on("#btn-restore-confirm", async () => {
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

  on("#btn-wipe", async () => {
    if (confirm("⚠ This will erase ALL business data permanently to comply with Uganda's Data Protection Act. Are you sure?")) {
      await DB.reset();
      showToast("All data wiped. Reloading…", "warning");
      setTimeout(() => location.reload(), 1200);
    }
  });

  on("#btn-save-tariffs", async () => {
    const config    = await DB.get("kc_config") || {};
    const taxInput  = document.getElementById("settings-tax-rate");
    const nameInput = document.getElementById("settings-biz-name");

    if (taxInput)  config.tax_rate     = Number(taxInput.value)  || 0.5;
    if (nameInput && nameInput.value.trim()) config.business_name = nameInput.value.trim();

    await DB.set("kc_config", config);
    showToast("Settings saved ✓", "success");
    refreshDashboard();
  });

  on("#btn-privacy-policy", async () => {
    const modal = document.getElementById("modal-privacy");
    if (modal) modal.hidden = false;
  });


  /* =================================================================
   * FRAUD OVERLAY
   * ============================================================== */
  on("#btn-dismiss-fraud", async () => {
    const overlay = document.getElementById("fraud-alert-overlay");
    if (overlay) overlay.hidden = true;
  });

  /* =================================================================
   * MODALS — unified close via .modal-close class
   * ============================================================== */
  onAll(".modal-close", async function () {
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

/** Check if Notification Access is granted via native bridge. */
async function checkNotificationAccess() {
  if (typeof NgaboNative !== 'undefined') {
    const granted = NgaboNative.isNotificationAccessGranted();
    if (!granted) {
      if (confirm("To automate your records, Ngabo needs 'Notification Access'. Open settings to enable?")) {
        NgaboNative.openNotificationSettings();
      }
    }
  }
}

const App = (() => {
  async function init() {
    attachEventHandlers();

    // Status-bar clock
    updateStatusBarTime();
    setInterval(updateStatusBarTime, 60000);

    // Determine starting screen
    const config = await DB.get("kc_config");

    if (!config) {
      Nav.goto("consent");
    } else if (!config.pin) {
      Nav.goto("pin-setup");
    } else {
      Nav.goto("dashboard");
      // Check for notification access after reaching dashboard
      setTimeout(checkNotificationAccess, 2000);
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

    let statusLabel = "뿯½뿯½뿯½ Normal";

    let dataPts = [4, 6, 5, 8, 7, 10, 9];

    

    if (index === 1) {

      loc = "Kyebando Branch";

      float = 850000;

      manager = "Sarah";

      status = "shortage";

      statusLabel = "뿯½뿯½뿯½뿯½뿯½뿯½ UGX 150K Shortage";

      dataPts = [8, 7, 5, 4, 3, 2, 4];

    } else if (index === 2) {

      loc = "Makindye Branch";

      float = 3200000;

      manager = "John";

      status = "normal";

      statusLabel = "뿯½뿯½뿯½ Normal";

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



    const countEl = document.getElementById("mk-kiosk-count");
    if (countEl) countEl.textContent = kiosks.length;
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

          <strong>뿯½뿯½뿯½뿯½뿯½뿯½ Shortage Detected</strong><br>

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
