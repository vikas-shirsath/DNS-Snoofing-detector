/**
 * background.js — MV3 service worker for DNS Shield.
 *
 * Listens for completed main-frame navigations, extracts the server IP
 * the browser connected to, and runs the detector analysis.  Results are
 * cached (60 s), stored in chrome.storage.local, surfaced on the action
 * badge, and (optionally) shown as desktop notifications.
 */

import { analyze } from './detector.js';

/* ── In-memory cache keyed by hostname|ip (60 s TTL, 0 s in demo mode) ── */
const cache = new Map();       // 'hostname|ip' -> { ts, result }
const CACHE_TTL = 60_000;

/** Return effective cache TTL (0 in demo mode so every load re-scans). */
async function getCacheTTL() {
  const { settings } = await chrome.storage.local.get('settings');
  return (settings && settings.demoMode) ? 0 : CACHE_TTL;
}

function getCached(cacheKey, ttl) {
  const entry = cache.get(cacheKey);
  if (entry && Date.now() - entry.ts < ttl) return entry.result;
  cache.delete(cacheKey);
  return null;
}
function setCache(cacheKey, result) {
  cache.set(cacheKey, { ts: Date.now(), result });
}

/* ── Per-tab latest result ────────────────────────────────────────────── */
const tabResults = new Map();  // tabId -> result

/* ── Badge helpers ────────────────────────────────────────────────────── */
const BADGE = {
  SAFE:        { text: 'OK', color: '#00c853' },
  SUSPICIOUS:  { text: '!',  color: '#ff9100' },
  SPOOFED:     { text: 'X',  color: '#d50000' },
  UNKNOWN:     { text: '?',  color: '#616161' },
};

async function updateBadge(tabId, result) {
  const cfg = BADGE[result.verdict] || BADGE.UNKNOWN;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  } catch { /* tab may have closed */ }
}

/* ── Notification helper ──────────────────────────────────────────────── */
async function notifyUser(result) {
  const { settings } = await chrome.storage.local.get('settings');
  if (settings && settings.notifications === false) return;

  const id = `dns-shield-${result.domain}-${Date.now()}`;
  try {
    chrome.notifications.create(id, {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: `DNS Shield — ${result.verdict}`,
      message: `${result.domain} (${result.observedIp})\n${result.reasons[0] || ''}`,
      priority: result.verdict === 'SPOOFED' ? 2 : 1,
    });
  } catch { /* notifications may be blocked */ }
}

/* ── History management (max 100 entries in storage) ──────────────────── */
async function addToHistory(result) {
  const { history = [] } = await chrome.storage.local.get('history');
  history.unshift(result);
  if (history.length > 100) history.length = 100;
  await chrome.storage.local.set({ history });
}

/* ═══════════════════════════════════════════════════════════════════════
 * Install / startup — seed trusted records on first run
 * ═══════════════════════════════════════════════════════════════════════ */

chrome.runtime.onInstalled.addListener(async () => {
  /* Load default trusted records from the bundled JSON file */
  try {
    const resp = await fetch(chrome.runtime.getURL('trusted.json'));
    const defaults = await resp.json();
    const { trusted } = await chrome.storage.local.get('trusted');
    if (!trusted) {
      await chrome.storage.local.set({ trusted: defaults });
    }
  } catch (err) {
    console.warn('[DNS Shield] Failed to load trusted.json defaults:', err);
  }

  /* Ensure default settings exist */
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings) {
    await chrome.storage.local.set({
      settings: { enabled: true, notifications: true, sensitivity: 'normal', demoMode: false },
    });
  }
});

/* ═══════════════════════════════════════════════════════════════════════
 * Main listener — webRequest.onCompleted for main_frame loads
 * ═══════════════════════════════════════════════════════════════════════ */

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    /* Only process successful main-frame loads with an IP */
    if (!details.ip) return;

    let hostname;
    try {
      const parsed = new URL(details.url);
      if (!parsed.protocol.startsWith('http')) return;
      hostname = parsed.hostname;
    } catch { return; }

    /*
     * Skip noise by URL hostname only (never by the observed IP — a
     * public domain resolving to 127.0.0.1 is exactly the kind of
     * spoofing we need to catch).
     */
    if (!hostname) return;
    if (hostname === 'localhost') return;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return;      // bare IPv4
    if (hostname.startsWith('[')) return;                         // IPv6 literal

    /* Check if the extension is enabled */
    const { settings } = await chrome.storage.local.get('settings');
    if (settings && settings.enabled === false) return;

    /* Check cache — key includes the IP so a changed IP is re-analyzed */
    const cacheKey = `${hostname}|${details.ip}`;
    const ttl = (settings && settings.demoMode) ? 0 : CACHE_TTL;
    const cached = getCached(cacheKey, ttl);
    if (cached) {
      tabResults.set(details.tabId, cached);
      await updateBadge(details.tabId, cached);
      return;
    }

    /* ── Run analysis ────────────────────────────────────────────────── */
    let result;
    try {
      result = await analyze(hostname, details.ip);
    } catch (err) {
      console.error('[DNS Shield] Analysis error for', hostname, err);
      result = {
        domain: hostname,
        observedIp: details.ip,
        score: 0,
        verdict: 'UNKNOWN',
        reasons: [`Internal error: ${err.message}`],
        checks: {},
        resolvers: [],
        timestamp: Date.now(),
      };
    }

    /* Cache & store */
    setCache(cacheKey, result);
    tabResults.set(details.tabId, result);
    await addToHistory(result);
    await updateBadge(details.tabId, result);

    /* Store per-tab result so the popup can retrieve it */
    const { tabResultsStore = {} } = await chrome.storage.local.get('tabResultsStore');
    tabResultsStore[details.tabId] = result;
    /* Prune old tab entries (keep last 50) */
    const keys = Object.keys(tabResultsStore);
    if (keys.length > 50) {
      for (const k of keys.slice(0, keys.length - 50)) delete tabResultsStore[k];
    }
    await chrome.storage.local.set({ tabResultsStore });

    /* Notify for SUSPICIOUS / SPOOFED */
    if (result.verdict === 'SUSPICIOUS' || result.verdict === 'SPOOFED') {
      await notifyUser(result);
    }

    /* ── Change #5: inject a red warning banner for SPOOFED verdicts ── */
    if (result.verdict === 'SPOOFED') {
      await injectSpoofBanner(details.tabId, result);
    }
  },
  { urls: ['<all_urls>'], types: ['main_frame'] }
);

/* ═══════════════════════════════════════════════════════════════════════
 * Spoof-warning banner injection (Change #5)
 *
 * When the verdict is SPOOFED, inject a red fixed banner at the top of
 * the page warning the user.  Uses chrome.scripting.executeScript so it
 * works on http:// and https:// pages.
 * ═══════════════════════════════════════════════════════════════════════ */

async function injectSpoofBanner(tabId, result) {
  /* Build the list of trusted IPs from resolvers (skip Browser row) */
  const trustedIps = (result.resolvers || [])
    .filter(r => r.name !== 'Browser' && !r.error && r.ips.length)
    .flatMap(r => r.ips);
  const uniqueTrusted = [...new Set(trustedIps)].slice(0, 6).join(', ') || 'unknown';

  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: (observedIp, trustedIpStr) => {
        /* Guard: don't inject twice */
        if (document.getElementById('dns-shield-spoof-banner')) return;

        const banner = document.createElement('div');
        banner.id = 'dns-shield-spoof-banner';
        banner.style.cssText = [
          'position:fixed', 'top:0', 'left:0', 'width:100%', 'z-index:2147483647',
          'background:linear-gradient(135deg,#d50000,#ff1744)', 'color:#fff',
          'font:600 14px/1.4 -apple-system,BlinkMacSystemFont,sans-serif',
          'padding:12px 20px', 'box-shadow:0 4px 24px rgba(0,0,0,0.4)',
          'display:flex', 'align-items:center', 'gap:12px',
        ].join(';');

        const icon = document.createElement('span');
        icon.textContent = '\u26A0\uFE0F';
        icon.style.fontSize = '20px';

        const msg = document.createElement('span');
        msg.style.flex = '1';
        msg.textContent =
          `DNS Shield: possible DNS spoofing detected. ` +
          `This site resolved to ${observedIp} but trusted resolvers say ${trustedIpStr}. ` +
          `Do not enter passwords.`;

        const btn = document.createElement('button');
        btn.textContent = 'Dismiss';
        btn.style.cssText = [
          'background:rgba(255,255,255,0.2)', 'color:#fff', 'border:1px solid rgba(255,255,255,0.4)',
          'border-radius:6px', 'padding:5px 14px', 'cursor:pointer',
          'font:600 13px sans-serif', 'white-space:nowrap',
        ].join(';');
        btn.addEventListener('click', () => banner.remove());

        banner.append(icon, msg, btn);
        document.documentElement.prepend(banner);
      },
      args: [result.observedIp, uniqueTrusted],
    });
  } catch (err) {
    /* Page may be a chrome:// or otherwise restricted — silently ignore */
    console.warn('[DNS Shield] Could not inject banner:', err.message);
  }
}

/* ── Clean up per-tab data when a tab is closed ───────────────────────── */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

/* ═══════════════════════════════════════════════════════════════════════
 * Message handler — popup sends requests for data / re-scan
 * ═══════════════════════════════════════════════════════════════════════ */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'getTabResult') {
    /* Return the in-memory result for this tab, falling back to storage */
    const mem = tabResults.get(msg.tabId);
    if (mem) {
      sendResponse({ result: mem });
    } else {
      chrome.storage.local.get('tabResultsStore').then(({ tabResultsStore = {} }) => {
        sendResponse({ result: tabResultsStore[msg.tabId] || null });
      });
      return true; // async sendResponse
    }
  }

  if (msg.type === 'rescan') {
    /* Force a fresh analysis for the given domain / IP / tab */
    const cacheKey = `${msg.domain}|${msg.observedIp}`;
    cache.delete(cacheKey);
    analyze(msg.domain, msg.observedIp).then(async (result) => {
      setCache(cacheKey, result);
      tabResults.set(msg.tabId, result);
      await addToHistory(result);
      await updateBadge(msg.tabId, result);

      const { tabResultsStore = {} } = await chrome.storage.local.get('tabResultsStore');
      tabResultsStore[msg.tabId] = result;
      await chrome.storage.local.set({ tabResultsStore });

      if (result.verdict === 'SUSPICIOUS' || result.verdict === 'SPOOFED') {
        await notifyUser(result);
      }
      sendResponse({ result });
    }).catch(err => {
      sendResponse({ result: null, error: err.message });
    });
    return true; // async sendResponse
  }

  if (msg.type === 'toggleEnabled') {
    chrome.storage.local.get('settings').then(({ settings = {} }) => {
      settings.enabled = msg.enabled;
      chrome.storage.local.set({ settings }).then(() => {
        sendResponse({ ok: true });
      });
    });
    return true;
  }
});
