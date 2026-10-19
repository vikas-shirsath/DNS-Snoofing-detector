/**
 * detector.js — Core DNS-spoof-detection engine (ES module).
 *
 * Compares an observed IP (the one the browser connected to) against
 * DNS-over-HTTPS answers from Google, Cloudflare, and Quad9, plus a
 * user-curated trusted-records list and a hash-based baseline.
 *
 * Exports: analyze(domain, observedIp) -> Promise<Result>
 */

/* ── DoH resolver configuration ───────────────────────────────────────── */

const DOH_RESOLVERS = [
  {
    name: 'Google',
    url: 'https://dns.google/resolve',
    headers: {},
  },
  {
    name: 'Cloudflare',
    url: 'https://cloudflare-dns.com/dns-query',
    headers: { Accept: 'application/dns-json' },
  },
  {
    name: 'Quad9',
    url: 'https://dns.quad9.net:5053/dns-query',
    headers: { Accept: 'application/dns-json' },
  },
];

const DOH_TIMEOUT_MS = 3000;

/* ═══════════════════════════════════════════════════════════════════════
 * IP utilities
 * ═══════════════════════════════════════════════════════════════════════ */

/** Return the /16 network prefix string for an IPv4 address. */
function prefix16(ip) {
  const parts = ip.split('.');
  return `${parts[0]}.${parts[1]}.0.0`;
}

/** True when at least one /16 prefix is shared between two IP arrays. */
function prefixesOverlap(ipsA, ipsB) {
  const setA = new Set(ipsA.map(prefix16));
  for (const ip of ipsB) {
    if (setA.has(prefix16(ip))) return true;
  }
  return false;
}

/**
 * True if the address is private, loopback, link-local, or reserved.
 * Covers IPv4 (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 0.0.0.0,
 * multicast 224+) and IPv6 (::1, fc00::/7, fe80::/10).
 */
function isPrivateOrReserved(ip) {
  /* ── IPv6 checks ───────────────────────────────────────────────────── */
  if (ip.includes(':')) {
    const lower = ip.toLowerCase();
    if (lower === '::1') return true;                      // IPv6 loopback
    /* fc00::/7 — unique-local (fc… or fd…) */
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    /* fe80::/10 — link-local */
    if (lower.startsWith('fe80')) return true;
    return false;
  }

  /* ── IPv4 checks ───────────────────────────────────────────────────── */
  const [a, b] = ip.split('.').map(Number);
  if (Number.isNaN(a)) return false;
  if (a === 127) return true;                              // 127.0.0.0/8 loopback
  if (a === 10) return true;                               // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true;        // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                  // 192.168.0.0/16
  if (a === 169 && b === 254) return true;                  // 169.254.0.0/16 link-local
  if (a === 0 || a >= 224) return true;                     // 0.x / multicast / reserved
  return false;
}

/** SHA-256 hex digest via the Web Crypto API. */
async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/* ═══════════════════════════════════════════════════════════════════════
 * DoH query helper
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Send a JSON-format A-record query to a DoH resolver.
 * @returns {{ name:string, ips:string[], ttl:number|null, error:string|null }}
 */
async function queryDoH(resolver, domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);

  try {
    const url = new URL(resolver.url);
    url.searchParams.set('name', domain);
    url.searchParams.set('type', 'A');

    const resp = await fetch(url.toString(), {
      headers: resolver.headers,
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!resp.ok) {
      return { name: resolver.name, ips: [], ttl: null, error: `HTTP ${resp.status}` };
    }

    const json = await resp.json();
    /* Filter for type-1 (A) records only — ignore CNAMEs etc. */
    const answers = (json.Answer || []).filter(r => r.type === 1);
    const ips = answers.map(r => r.data).sort();
    const ttl = answers.length ? Math.min(...answers.map(r => r.TTL)) : null;
    return { name: resolver.name, ips, ttl, error: null };
  } catch (err) {
    clearTimeout(timer);
    const msg = err.name === 'AbortError' ? 'Timeout' : (err.message || 'Unknown');
    return { name: resolver.name, ips: [], ttl: null, error: msg };
  }
}

/* ═══════════════════════════════════════════════════════════════════════
 * Main analysis entry point
 * ═══════════════════════════════════════════════════════════════════════ */

/**
 * Analyse a domain by comparing the browser's observed IP against
 * independent DoH resolvers, trusted records, and a hash baseline.
 *
 * @param {string} domain      The hostname being loaded.
 * @param {string} observedIp  The IP the browser actually connected to.
 * @returns {Promise<{
 *   domain: string,
 *   observedIp: string,
 *   score: number,
 *   verdict: string,
 *   reasons: string[],
 *   checks: Record<string, string>,
 *   resolvers: Array<{name:string, ips:string[], ttl:number|null, match:string, error:string|null}>,
 *   timestamp: number,
 * }>}
 */
export async function analyze(domain, observedIp) {
  let score = 0;
  const reasons = [];
  const checks = {};

  /* ── 1. Query all DoH resolvers in parallel ─────────────────────────── */
  const dohResults = await Promise.all(
    DOH_RESOLVERS.map(r => queryDoH(r, domain))
  );

  const allDoHIps = new Set();
  let successCount = 0;
  for (const r of dohResults) {
    if (!r.error) {
      r.ips.forEach(ip => allDoHIps.add(ip));
      successCount++;
    }
  }

  /* Build the resolver comparison table for the popup */
  const resolvers = [
    { name: 'Browser', ips: [observedIp], ttl: null, match: 'baseline', error: null },
    ...dohResults.map(r => {
      let match;
      if (r.error) {
        match = 'error';
      } else if (r.ips.includes(observedIp)) {
        match = 'exact';
      } else if (r.ips.length && prefixesOverlap([observedIp], r.ips)) {
        match = 'prefix';
      } else if (r.ips.length === 0) {
        match = 'empty';
      } else {
        match = 'mismatch';
      }
      return { name: r.name, ips: r.ips, ttl: r.ttl, match, error: r.error };
    }),
  ];

  /* If every DoH call failed (network errors / timeouts), bail with UNKNOWN */
  if (successCount === 0) {
    return {
      domain, observedIp, score: 0,
      verdict: 'UNKNOWN',
      reasons: ['All DoH resolvers were unreachable — analysis cannot proceed.'],
      checks: {}, resolvers, timestamp: Date.now(),
    };
  }

  /*
   * NXDOMAIN / NO-ANSWER: DoH calls succeeded but returned zero A records,
   * yet the browser connected to *something*.  This is suspicious — a real
   * domain should have public records.
   */
  if (allDoHIps.size === 0 && successCount > 0) {
    return {
      domain, observedIp,
      score: 35,
      verdict: 'SUSPICIOUS',
      reasons: [
        'Public resolvers have no A record for this domain, but the browser connected anyway.',
      ],
      checks: { phantom_domain: 'FAIL' },
      resolvers,
      timestamp: Date.now(),
    };
  }

  /* ── Load trusted records, baseline, and settings from storage ──────── */
  const storage = await chrome.storage.local.get(['trusted', 'baseline', 'settings']);
  const trusted  = storage.trusted  || {};
  const baseline = storage.baseline || {};
  const settings = storage.settings || {};
  const strict   = settings.sensitivity === 'strict';

  /* ═══ CHECK 1 — Cross-resolver validation (+50) ═════════════════════ */
  if (allDoHIps.size > 0) {
    const exactMatch  = allDoHIps.has(observedIp);
    const prefixMatch = prefixesOverlap([observedIp], [...allDoHIps]);

    if (!exactMatch && !prefixMatch) {
      score += 50;
      reasons.push(
        `Cross-resolver mismatch: ${observedIp} has no overlap (exact or /16) with any DoH answer.`
      );
      checks.cross_resolver = 'FAIL';
    } else {
      checks.cross_resolver = 'PASS';
    }
  } else {
    checks.cross_resolver = 'SKIP';
    reasons.push('Cross-resolver check skipped: no successful DoH responses.');
  }

  /* ═══ CHECK 2 — Resolver disagreement (+10) ═════════════════════════ */
  const okResults = dohResults.filter(r => !r.error && r.ips.length > 0);
  if (okResults.length >= 2) {
    let disagreeCount = 0;
    for (let i = 0; i < okResults.length; i++) {
      for (let j = i + 1; j < okResults.length; j++) {
        const exact = okResults[i].ips.some(ip => okResults[j].ips.includes(ip));
        const pref  = prefixesOverlap(okResults[i].ips, okResults[j].ips);
        if (!exact && !pref) disagreeCount++;
      }
    }
    if (disagreeCount > 0) {
      score += 10;
      reasons.push(`Resolver disagreement: ${disagreeCount} pair(s) have no IP overlap.`);
      checks.resolver_agreement = 'FAIL';
    } else {
      checks.resolver_agreement = 'PASS';
    }
  } else {
    checks.resolver_agreement = 'SKIP';
  }

  /* ═══ CHECK 3 — Trusted records (+30) ═══════════════════════════════ */
  if (trusted[domain]) {
    const trustedSet = new Set(trusted[domain]);
    if (!trustedSet.has(observedIp)) {
      score += 30;
      reasons.push(`Trusted-record mismatch: ${observedIp} not in the trusted list for ${domain}.`);
      checks.trusted_records = 'FAIL';
    } else {
      checks.trusted_records = 'PASS';
    }
  } else {
    checks.trusted_records = 'SKIP';
  }

  /* ═══ CHECK 4 — Hash baseline (+15) ═════════════════════════════════ */
  const sortedDoHIps = [...allDoHIps].sort();
  const currentHash = sortedDoHIps.length ? await sha256(sortedDoHIps.join(',')) : '';

  if (baseline[domain]) {
    if (currentHash && currentHash !== baseline[domain]) {
      score += 15;
      reasons.push('Baseline hash changed: DoH answer-set differs from a previously stored safe baseline.');
      checks.hash_baseline = 'FAIL';
    } else {
      checks.hash_baseline = 'PASS';
    }
  } else {
    checks.hash_baseline = 'NEW';
  }

  /* ═══ CHECK 5a — Private / reserved IP (+25) ════════════════════════ */
  if (isPrivateOrReserved(observedIp)) {
    score += 25;
    reasons.push(`Private/reserved IP ${observedIp} returned for a public domain.`);
    checks.private_ip = 'FAIL';
  } else {
    checks.private_ip = 'PASS';
  }

  /* ═══ CHECK 5b — Low TTL (+10) ══════════════════════════════════════ */
  const ttls = dohResults.filter(r => r.ttl !== null).map(r => r.ttl);
  const minTTL = ttls.length ? Math.min(...ttls) : null;
  if (minTTL !== null && minTTL < 30) {
    score += 10;
    reasons.push(`Suspiciously low TTL (${minTTL}s < 30s threshold).`);
    checks.low_ttl = 'FAIL';
  } else {
    checks.low_ttl = 'PASS';
  }

  /* ═══ CHECK 5c — Record-count anomaly (+5) ══════════════════════════ */
  const ipCounts = okResults.map(r => r.ips.length);
  if (ipCounts.length >= 2) {
    const maxC = Math.max(...ipCounts);
    const minC = Math.min(...ipCounts);
    if (maxC - minC > Math.max(maxC * 0.6, 3)) {
      score += 5;
      reasons.push(`Record-count anomaly: resolver answers vary widely (${minC} to ${maxC}).`);
      checks.answer_count = 'FAIL';
    } else {
      checks.answer_count = 'PASS';
    }
  } else {
    checks.answer_count = 'SKIP';
  }

  /* ═══ Verdict ═══════════════════════════════════════════════════════ */
  score = Math.min(score, 100);

  const safeCutoff = strict ? 20 : 30;
  const spoofCutoff = strict ? 45 : 60;

  let verdict;
  if (score < safeCutoff)       verdict = 'SAFE';
  else if (score < spoofCutoff) verdict = 'SUSPICIOUS';
  else                          verdict = 'SPOOFED';

  /* Store a new baseline only when verdict is SAFE */
  if (verdict === 'SAFE' && !baseline[domain] && currentHash) {
    baseline[domain] = currentHash;
    await chrome.storage.local.set({ baseline });
  }

  if (reasons.length === 0) {
    reasons.push('All checks passed — no anomalies detected.');
  }

  return { domain, observedIp, score, verdict, reasons, checks, resolvers, timestamp: Date.now() };
}
