/**
 * options.js — Controller for the DNS Shield options page.
 *
 * Manages trusted domains, notification toggle, sensitivity setting,
 * and data-clearing operations.  All state is persisted in
 * chrome.storage.local.
 */

/* ── DOM refs ──────────────────────────────────────────────────────────── */
const $notifications = document.getElementById('opt-notifications');
const $sensitivity   = document.getElementById('opt-sensitivity');
const $demo          = document.getElementById('opt-demo');
const $trustedTbody  = document.getElementById('trusted-tbody');
const $addDomain     = document.getElementById('add-domain');
const $addIps        = document.getElementById('add-ips');
const $btnAdd        = document.getElementById('btn-add');
const $btnClearHist  = document.getElementById('btn-clear-history');
const $btnClearBase  = document.getElementById('btn-clear-baseline');
const $btnReset      = document.getElementById('btn-reset-trusted');
const $toast         = document.getElementById('toast');

/* ── Toast helper ──────────────────────────────────────────────────────── */
let toastTimer = null;
function showToast(msg) {
  clearTimeout(toastTimer);
  $toast.textContent = msg;
  $toast.hidden = false;
  toastTimer = setTimeout(() => { $toast.hidden = true; }, 2200);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Render the trusted-domains table
 * ═══════════════════════════════════════════════════════════════════════ */

function renderTrusted(trusted) {
  $trustedTbody.innerHTML = '';

  const domains = Object.keys(trusted).sort();
  if (domains.length === 0) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td colspan="3" style="color:var(--text-dim);text-align:center;padding:16px">No trusted domains configured.</td>';
    $trustedTbody.appendChild(tr);
    return;
  }

  for (const domain of domains) {
    const ips = trusted[domain];
    const tr = document.createElement('tr');

    /* Domain cell */
    const tdDomain = document.createElement('td');
    tdDomain.textContent = domain;
    tdDomain.style.fontWeight = '600';
    tr.appendChild(tdDomain);

    /* Editable IPs cell */
    const tdIps = document.createElement('td');
    tdIps.className = 'ip-cell';
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'ip-edit';
    input.value = ips.join(', ');
    input.addEventListener('change', async () => {
      const newIps = input.value
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
      if (newIps.length === 0) {
        /* Treat empty IPs as removal */
        delete trusted[domain];
      } else {
        trusted[domain] = newIps;
      }
      await chrome.storage.local.set({ trusted });
      showToast('Trusted records saved');
      renderTrusted(trusted);
    });
    tdIps.appendChild(input);
    tr.appendChild(tdIps);

    /* Delete button */
    const tdDel = document.createElement('td');
    const btnDel = document.createElement('button');
    btnDel.className = 'btn btn-icon';
    btnDel.title = 'Remove domain';
    btnDel.textContent = '\u2715'; // ✕
    btnDel.addEventListener('click', async () => {
      delete trusted[domain];
      await chrome.storage.local.set({ trusted });
      showToast(`Removed ${domain}`);
      renderTrusted(trusted);
    });
    tdDel.appendChild(btnDel);
    tr.appendChild(tdDel);

    $trustedTbody.appendChild(tr);
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Initialisation — load all settings from storage
 * ═══════════════════════════════════════════════════════════════════════ */

async function init() {
  const { settings = {}, trusted = {} } = await chrome.storage.local.get([
    'settings', 'trusted',
  ]);

  /* General settings */
  $notifications.checked = settings.notifications !== false;
  $sensitivity.value = settings.sensitivity || 'normal';
  $demo.checked = !!settings.demoMode;

  /* Trusted domains */
  renderTrusted(trusted);
}

/* ═══════════════════════════════════════════════════════════════════════
 * Event listeners
 * ═══════════════════════════════════════════════════════════════════════ */

/* Notifications toggle */
$notifications.addEventListener('change', async () => {
  const { settings = {} } = await chrome.storage.local.get('settings');
  settings.notifications = $notifications.checked;
  await chrome.storage.local.set({ settings });
  showToast(settings.notifications ? 'Notifications enabled' : 'Notifications disabled');
});

/* Sensitivity select */
$sensitivity.addEventListener('change', async () => {
  const { settings = {} } = await chrome.storage.local.get('settings');
  settings.sensitivity = $sensitivity.value;
  await chrome.storage.local.set({ settings });
  showToast(`Sensitivity set to ${settings.sensitivity}`);
});

/* Demo mode toggle — sets cache to 0 s and forces notifications on */
$demo.addEventListener('change', async () => {
  const { settings = {} } = await chrome.storage.local.get('settings');
  settings.demoMode = $demo.checked;
  if ($demo.checked) {
    /* Force notifications on so every scan fires an alert */
    settings.notifications = true;
    $notifications.checked = true;
  }
  await chrome.storage.local.set({ settings });
  showToast($demo.checked ? 'Demo mode ON — cache disabled, notifications forced' : 'Demo mode OFF');
});

/* Add trusted domain */
$btnAdd.addEventListener('click', async () => {
  const domain = $addDomain.value.trim().toLowerCase();
  const ipsRaw = $addIps.value.trim();

  if (!domain) { $addDomain.focus(); return; }

  const ips = ipsRaw
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (ips.length === 0) { $addIps.focus(); return; }

  const { trusted = {} } = await chrome.storage.local.get('trusted');
  /* Merge with existing IPs if the domain already exists */
  const existing = new Set(trusted[domain] || []);
  ips.forEach(ip => existing.add(ip));
  trusted[domain] = [...existing];

  await chrome.storage.local.set({ trusted });
  showToast(`Added ${domain}`);
  renderTrusted(trusted);

  $addDomain.value = '';
  $addIps.value = '';
});

/* Clear scan history */
$btnClearHist.addEventListener('click', async () => {
  await chrome.storage.local.set({ history: [], tabResultsStore: {} });
  showToast('Scan history cleared');
});

/* Clear hash baseline */
$btnClearBase.addEventListener('click', async () => {
  await chrome.storage.local.set({ baseline: {} });
  showToast('Hash baseline cleared');
});

/* Reset trusted to defaults */
$btnReset.addEventListener('click', async () => {
  try {
    const resp = await fetch(chrome.runtime.getURL('trusted.json'));
    const defaults = await resp.json();
    await chrome.storage.local.set({ trusted: defaults });
    showToast('Trusted records reset to defaults');
    renderTrusted(defaults);
  } catch (err) {
    showToast('Error loading defaults: ' + err.message);
  }
});

/* ── Boot ──────────────────────────────────────────────────────────────── */
init();
