# DNS Shield — Chrome Extension 🛡️

A Manifest V3 Chrome extension that detects DNS spoofing in real time.
For every page you visit it compares the IP the browser connected to
against independent DNS-over-HTTPS answers from Google, Cloudflare,
and Quad9, then scores and reports the result.

## Quick Start

### 1. Generate the icons

```bash
cd extension
python generate_icons.py      # requires Pillow (pip install Pillow)
```

### 2. Load the extension

1. Open **chrome://extensions** in Chrome.
2. Enable **Developer mode** (toggle in the top-right).
3. Click **Load unpacked** and select the `extension/` folder.
4. The green shield icon appears in the toolbar.

### 3. Browse normally

Navigate to any website — the extension analyses every page load
automatically.  Click the toolbar icon to see the full report.

---

## How It Works

| Step | Detail |
|------|--------|
| **1. Intercept** | `webRequest.onCompleted` captures the server IP the browser connected to. |
| **2. DoH queries** | A records are fetched in parallel from Google, Cloudflare, and Quad9 via DNS-over-HTTPS (3 s timeout each). |
| **3. Score** | The observed IP is compared against DoH answers, trusted records, hash baselines, and anomaly rules. |
| **4. Verdict** | Score < 30 → **SAFE**, 30–59 → **SUSPICIOUS**, ≥ 60 → **SPOOFED**. |
| **5. Report** | Badge updates on the toolbar; a notification fires for SUSPICIOUS/SPOOFED; full details in the popup. |

### Checks & Scoring

| Check | Points | Trigger |
|-------|--------|---------|
| Cross-resolver mismatch | +50 | Browser IP not in any DoH answer (exact or /16) |
| Resolver disagreement | +10 | DoH resolvers heavily disagree with each other |
| Trusted records | +30 | IP not in `trusted.json` list for this domain |
| Hash baseline | +15 | SHA-256 of DoH answer set differs from stored baseline |
| Private/reserved IP | +25 | Loopback / RFC-1918 address for a public domain |
| Low TTL | +10 | Any resolver TTL below 30 s |
| Record-count anomaly | +5 | Answer counts vary sharply across resolvers |

## Files

| File | Purpose |
|------|---------|
| `manifest.json` | MV3 manifest — permissions, service worker, popup |
| `background.js` | Service worker — intercepts navigations, runs analysis, manages badge/notifications |
| `detector.js` | Core engine — DoH queries, scoring, verdict (ES module) |
| `popup.html/css/js` | Popup UI — gauge, reasons, resolver table, recent scans |
| `options.html/css/js` | Options page — trusted domains editor, settings, data management |
| `trusted.json` | Seed known-good IPs (loaded into storage on install) |
| `generate_icons.py` | One-time helper to create shield PNGs (requires Pillow) |

## Demo: Simulate a Spoofed Response

### Option A — hosts file

1. Open your hosts file (Windows: `C:\Windows\System32\drivers\etc\hosts`
   / Mac/Linux: `/etc/hosts`) **as admin**.
2. Add a line that maps a domain to a suspicious IP:
   ```
   192.168.1.99  testsite.example.com
   ```
3. Navigate to `http://testsite.example.com` in Chrome.
4. The extension should flag it as **SPOOFED** because:
   - `192.168.1.99` is a private IP (+25)
   - It won't match any DoH response (+50)
5. **Remove the hosts entry when done.**

### Option B — compare with a real domain

1. Simply browse to `google.com`, `github.com`, or `example.com`.
2. Click the shield icon — you should see **SAFE** with a green gauge.
3. The resolver comparison table shows the browser IP vs. DoH answers.

## Options Page

Right-click the shield icon → **Options**, or click "Options" in the popup footer.

- **Notifications**: toggle desktop alerts on/off.
- **Sensitivity**: *Normal* (default) or *Strict* (lower thresholds).
- **Trusted Domains**: add, edit, or remove known-good IP lists.
- **Data**: clear scan history or hash baseline.
