/**
 * popup.js — Drives the DNS Shield popup UI.
 *
 * On open: reads the current tab's result from the background service
 * worker, renders the gauge / reasons / resolver table / check pills,
 * and shows the 8 most-recent scans.
 */

/* ── DOM references ────────────────────────────────────────────────────── */
const $loading     = document.getElementById('state-loading');
const $empty       = document.getElementById('state-empty');
const $disabled    = document.getElementById('state-disabled');
const $result      = document.getElementById('state-result');

const $gaugeRing   = document.getElementById('gauge-ring');
const $gaugeScore  = document.getElementById('gauge-score');
const $gaugeVerdict= document.getElementById('gauge-verdict');
const $domain      = document.getElementById('result-domain');
const $mismatch    = document.getElementById('mismatch-alert');
const $chipIp      = document.getElementById('chip-ip');
const $chipTtl     = document.getElementById('chip-ttl');
const $reasonsList = document.getElementById('reasons-list');
const $resolverTb  = document.getElementById('resolver-tbody');
const $checksList  = document.getElementById('checks-list');
const $recentList  = document.getElementById('recent-list');
const $recentEmpty = document.getElementById('recent-empty');

const $toggle      = document.getElementById('toggle-enabled');
const $btnRescan   = document.getElementById('btn-rescan');
const $linkOptions = document.getElementById('link-options');

/* ── Constants ─────────────────────────────────────────────────────────── */
const GAUGE_CIRCUMFERENCE = 314.16;  // 2 * PI * 50

const VERDICT_COLORS = {
  SAFE:       { stroke: '#00e676', glow: 'rgba(0,230,118,0.3)' },
  SUSPICIOUS: { stroke: '#ffab40', glow: 'rgba(255,171,64,0.3)' },
  SPOOFED:    { stroke: '#ff1744', glow: 'rgba(255,23,68,0.3)' },
  UNKNOWN:    { stroke: '#8b949e', glow: 'rgba(139,148,158,0.2)' },
};

const MATCH_BADGE = {
  exact:    '<span class="match-badge badge-exact">Exact</span>',
  prefix:   '<span class="match-badge badge-prefix">Prefix</span>',
  mismatch: '<span class="match-badge badge-mismatch">Mismatch</span>',
  error:    '<span class="match-badge badge-error">Error</span>',
  empty:    '<span class="match-badge badge-empty">Empty</span>',
  baseline: '<span class="match-badge badge-baseline">Browser</span>',
};

/* ── State ─────────────────────────────────────────────────────────────── */
let currentTabId = null;
let currentResult = null;

/* ═══════════════════════════════════════════════════════════════════════
 * Rendering helpers
 * ═══════════════════════════════════════════════════════════════════════ */

/** Show exactly one of the state containers. */
function showState(el) {
  [$loading, $empty, $disabled, $result].forEach(s => s.hidden = true);
  el.hidden = false;
}

/** Animate the SVG gauge ring to display the given score and verdict. */
function renderGauge(score, verdict) {
  const offset = GAUGE_CIRCUMFERENCE * (1 - score / 100);
  const colors = VERDICT_COLORS[verdict] || VERDICT_COLORS.UNKNOWN;

  $gaugeRing.style.stroke = colors.stroke;
  $gaugeRing.style.filter = `drop-shadow(0 0 8px ${colors.glow})`;

  /* Trigger reflow so the CSS transition animates from the starting offset */
  $gaugeRing.style.transition = 'none';
  $gaugeRing.setAttribute('stroke-dashoffset', GAUGE_CIRCUMFERENCE);
  void $gaugeRing.getBoundingClientRect();          // force reflow
  $gaugeRing.style.transition = '';

  requestAnimationFrame(() => {
    $gaugeRing.setAttribute('stroke-dashoffset', offset);
  });

  /* Animate the score number counting up */
  animateCounter($gaugeScore, 0, score, 800);

  $gaugeVerdict.textContent = verdict;
  $gaugeVerdict.style.fill = colors.stroke;
}

/** Smoothly count a text element from `from` to `to` over `duration` ms. */
function animateCounter(el, from, to, duration) {
  const start = performance.now();
  function step(now) {
    const t = Math.min((now - start) / duration, 1);
    el.textContent = Math.round(from + (to - from) * easeOut(t));
    if (t < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}
function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

/** Format a timestamp to a short relative or time string. */
function timeAgo(ts) {
  const diff = (Date.now() - ts) / 1000;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return new Date(ts).toLocaleDateString();
}

/* ═══════════════════════════════════════════════════════════════════════
 * Render a full scan result
 * ═══════════════════════════════════════════════════════════════════════ */

function renderResult(result) {
  showState($result);
  currentResult = result;

  /* Gauge */
  renderGauge(result.score, result.verdict);
  $domain.textContent = result.domain;

  /*
   * Change #7 — mismatch sentence at the top of the result.
   * Shows "Browser connected to X, trusted resolvers say Y" for
   * non-SAFE verdicts so the user immediately sees the discrepancy.
   */
  if (result.verdict !== 'SAFE') {
    const dohIps = (result.resolvers || [])
      .filter(r => r.name !== 'Browser' && !r.error && r.ips.length)
      .flatMap(r => r.ips);
    const unique = [...new Set(dohIps)].slice(0, 6).join(', ') || 'none';
    $mismatch.textContent =
      `Browser connected to ${result.observedIp}, trusted resolvers say ${unique}.`;
    $mismatch.className = 'mismatch-alert level-' + result.verdict.toLowerCase();
    $mismatch.hidden = false;
  } else {
    $mismatch.hidden = true;
  }
  /* Chips */
  $chipIp.textContent = result.observedIp;
  const ttls = (result.resolvers || []).filter(r => r.ttl !== null).map(r => r.ttl);
  $chipTtl.textContent = ttls.length ? `${Math.min(...ttls)}s` : '—';

  /* Reasons */
  $reasonsList.innerHTML = '';
  for (const reason of result.reasons) {
    const li = document.createElement('li');
    const icon = document.createElement('span');
    icon.className = 'reason-icon';
    icon.textContent = result.verdict === 'SAFE' ? '\u2714' : '\u26A0';
    li.appendChild(icon);
    li.appendChild(document.createTextNode(reason));
    $reasonsList.appendChild(li);
  }

  /* Resolver comparison table */
  $resolverTb.innerHTML = '';
  for (const r of (result.resolvers || [])) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td style="white-space:nowrap;font-weight:600">${esc(r.name)}</td>
      <td style="font-family:monospace;font-size:10.5px">${esc(r.ips.join(', ') || '—')}</td>
      <td style="text-align:center">${r.ttl !== null ? r.ttl : '—'}</td>
      <td>${MATCH_BADGE[r.match] || esc(r.match)}</td>
    `;
    $resolverTb.appendChild(tr);
  }

  /* Check pills */
  $checksList.innerHTML = '';
  for (const [name, status] of Object.entries(result.checks || {})) {
    const cls = status === 'PASS' ? 'pill-pass'
              : status === 'FAIL' ? 'pill-fail'
              : status === 'NEW'  ? 'pill-new'
              : 'pill-skip';
    const pill = document.createElement('span');
    pill.className = `check-pill ${cls}`;
    pill.textContent = `${formatCheckName(name)}: ${status}`;
    $checksList.appendChild(pill);
  }
}

/** Convert snake_case check names to Title Case. */
function formatCheckName(name) {
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/** Simple HTML-escape. */
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

/* ═══════════════════════════════════════════════════════════════════════
 * Render the recent-scans list (last 8)
 * ═══════════════════════════════════════════════════════════════════════ */

function renderRecent(history) {
  $recentList.innerHTML = '';
  if (!history || history.length === 0) {
    $recentList.innerHTML = '<p class="state-sub">No scans yet.</p>';
    return;
  }

  const items = history.slice(0, 8);
  for (const h of items) {
    const dotClass = h.verdict === 'SAFE'       ? 'dot-safe'
                   : h.verdict === 'SUSPICIOUS' ? 'dot-suspicious'
                   : h.verdict === 'SPOOFED'    ? 'dot-spoofed'
                   : 'dot-unknown';

    const row = document.createElement('div');
    row.className = 'recent-item';
    row.innerHTML = `
      <span class="recent-dot ${dotClass}"></span>
      <span class="recent-domain" title="${esc(h.domain)}">${esc(h.domain)}</span>
      <span class="recent-score">${h.score}</span>
      <span class="recent-time">${timeAgo(h.timestamp)}</span>
    `;

    /* Click to expand detail */
    row.addEventListener('click', () => {
      const existing = row.nextElementSibling;
      if (existing && existing.classList.contains('recent-detail')) {
        existing.remove();
        return;
      }
      /* Remove any other open detail */
      $recentList.querySelectorAll('.recent-detail').forEach(d => d.remove());

      const detail = document.createElement('div');
      detail.className = 'recent-detail';
      detail.innerHTML = `
        <strong>IP:</strong> ${esc(h.observedIp)}&emsp;
        <strong>Verdict:</strong> ${esc(h.verdict)}<br>
        ${(h.reasons || []).map(r => `&bull; ${esc(r)}`).join('<br>')}
      `;
      row.after(detail);
    });

    $recentList.appendChild(row);
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Initialisation
 * ═══════════════════════════════════════════════════════════════════════ */

async function init() {
  /* Load settings for the toggle */
  const { settings = {} } = await chrome.storage.local.get('settings');
  const enabled = settings.enabled !== false;
  $toggle.checked = enabled;

  if (!enabled) {
    showState($disabled);
    /* Still load recent scans */
    const { history = [] } = await chrome.storage.local.get('history');
    renderRecent(history);
    return;
  }

  /* Get the active tab */
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) { showState($empty); return; }
  currentTabId = tab.id;

  /* Ask the background for this tab's result */
  chrome.runtime.sendMessage(
    { type: 'getTabResult', tabId: tab.id },
    async (resp) => {
      if (resp && resp.result) {
        renderResult(resp.result);
      } else {
        showState($empty);
      }

      /* Load recent scans */
      const { history = [] } = await chrome.storage.local.get('history');
      renderRecent(history);
    }
  );
}

/* ── Event listeners ───────────────────────────────────────────────────── */

/* Toggle enabled/disabled */
$toggle.addEventListener('change', () => {
  const enabled = $toggle.checked;
  chrome.runtime.sendMessage({ type: 'toggleEnabled', enabled });
  if (!enabled) {
    showState($disabled);
  } else {
    init();
  }
});

/* Re-scan button */
$btnRescan.addEventListener('click', async () => {
  if (!currentResult || !currentTabId) return;
  showState($loading);

  chrome.runtime.sendMessage(
    {
      type: 'rescan',
      domain: currentResult.domain,
      observedIp: currentResult.observedIp,
      tabId: currentTabId,
    },
    async (resp) => {
      if (resp && resp.result) {
        renderResult(resp.result);
      } else {
        showState($empty);
      }
      const { history = [] } = await chrome.storage.local.get('history');
      renderRecent(history);
    }
  );
});

/* Options link */
$linkOptions.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

/* ── Boot ──────────────────────────────────────────────────────────────── */
init();
