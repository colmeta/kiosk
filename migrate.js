const fs = require('fs');

function migrateFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  let content = fs.readFileSync(filePath, 'utf8');

  // 1. Update DB.get and DB.set definitions
  content = content.replace(
    /function get\(key\) \{[\s\S]*?raw = localStorage\.getItem\(key\);[\s\S]*?\}/,
    `async function get(key) {\n    try {\n      const { value } = await Capacitor.Plugins.Preferences.get({ key });\n      if (value === null) return key === "kc_config" ? null : [];\n      return JSON.parse(value);\n    } catch (_) {\n      return key === "kc_config" ? null : [];\n    }\n  }`
  );

  content = content.replace(
    /function set\(key, data\) \{\n\s*localStorage\.setItem\(key, JSON\.stringify\(data\)\);\n\s*\}/,
    `async function set(key, data) {\n    await Capacitor.Plugins.Preferences.set({ key, value: JSON.stringify(data) });\n  }`
  );

  content = content.replace(
    /function reset\(\) \{[\s\S]*?for \(let i = 0; i < localStorage\.length; i\+\+\) \{[\s\S]*?localStorage\.removeItem\(k\)\);\n\s*\}/,
    `async function reset() {\n    const { keys } = await Capacitor.Plugins.Preferences.keys();\n    const toRemove = keys.filter(k => k.startsWith("kc_"));\n    for (const k of toRemove) {\n      await Capacitor.Plugins.Preferences.remove({ key: k });\n    }\n  }`
  );

  // 2. Add await to DB.get and DB.set calls
  content = content.replace(/DB\.get\(/g, 'await DB.get(');
  content = content.replace(/DB\.set\(/g, 'await DB.set(');
  content = content.replace(/DB\.reset\(/g, 'await DB.reset(');

  // 3. Make containing functions async
  const funcsToAsync = [
    'function refreshDashboard',
    'function refreshMoneyOutside',
    'function refreshAnalytics',
    'function buildMoneyOutsideList',
    'function buildTransactionHistory',
    'function refreshSettings',
    'function showFraudAlert',
    'function checkKioskStability',
    'function startScanAnimation',
    'function openKioskDetail',
    'function refreshMultiKiosk'
  ];

  funcsToAsync.forEach(fn => {
    content = content.replace(new RegExp(fn, 'g'), 'async ' + fn);
  });

  // 4. Make callbacks async
  content = content.replace(/on\("[^"]+", \(\) => \{/g, match => match.replace('() => {', 'async () => {'));
  content = content.replace(/on\("[^"]+", function \(\) \{/g, match => match.replace('function () {', 'async function () {'));
  content = content.replace(/setTimeout\(\(\) => \{/g, match => 'setTimeout(async () => {');
  
  content = content.replace(/addEventListener\("click", \(\) => \{/g, 'addEventListener("click", async () => {');
  content = content.replace(/addEventListener\('DOMContentLoaded', \(\) => \{/g, "addEventListener('DOMContentLoaded', async () => {");
  content = content.replace(/document.addEventListener\("DOMContentLoaded", \(\) => \{/g, 'document.addEventListener("DOMContentLoaded", async () => {');

  // Also check App.init
  content = content.replace(/function init\(\) \{/, 'async function init() {');
  
  // App.init calls refresh functions which are now async. But they might not be awaited.
  // We can leave them un-awaited or just leave as is.
  
  // Handlers may need async for their parameters
  content = content.replace(/onAll\(".+?", function \(\) \{/g, match => match.replace('function () {', 'async function () {'));

  // Remove duplicate async if any
  content = content.replace(/async async/g, 'async');

  fs.writeFileSync(filePath, content);
  console.log(`Migrated ${filePath}`);
}

migrateFile('app.js');
migrateFile('www/app.js');
migrateFile('app-addendum.js');
