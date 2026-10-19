# DNS Spoof Detector 🛡️

A hackathon prototype that detects suspicious/spoofed DNS responses by
comparing a suspect resolver against multiple independent trusted sources.

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. CLI — scan a domain
python cli.py google.com
python cli.py example.com --host 8.8.8.8 --port 53
python cli.py github.com --json

# 3. Streamlit dashboard
streamlit run app.py
```

## How It Works

The detector queries your **suspect resolver** and cross-checks its answers
against Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9).

### Checks & Scoring

| Check                  | Points | Trigger                                          |
|------------------------|--------|--------------------------------------------------|
| Cross-resolver         | +50    | Suspect IPs have zero overlap (exact or /16)     |
| Trusted records        | +30    | IPs not in `trusted.json`                        |
| Hash baseline          | +15    | SHA-256 of answer set differs from baseline      |
| Private/reserved IP    | +25    | Loopback/RFC-1918 address for a public domain    |
| Low TTL                | +10    | TTL below 30 seconds                             |
| Answer-count anomaly   | +5     | Count differs sharply from public resolvers      |
| DNSSEC validation gap  | +10    | Signed domain but suspect lacks AD/RRSIG         |

### Verdicts

| Score   | Verdict      |
|---------|-------------|
| 0–29    | ✅ SAFE      |
| 30–59   | ⚠️ SUSPICIOUS|
| 60–100  | 🔴 SPOOFED   |

## Files

| File              | Purpose                                          |
|-------------------|--------------------------------------------------|
| `detector.py`     | Core analysis engine                             |
| `cli.py`          | Coloured command-line interface                  |
| `app.py`          | Streamlit web dashboard                          |
| `trusted.json`    | Known-good IPs per domain (editable)             |
| `baseline.json`   | Auto-created hash baseline (safe answers)        |
| `requirements.txt`| Python dependencies                              |

## Editing Trusted Records

Open `trusted.json` and add your own domains and known-good IPs:

```json
{
  "example.com": ["93.184.216.34"],
  "internal.corp": ["10.0.0.5"]
}
```

## Demo Tips

- **Normal scan**: `python cli.py google.com` — expect SAFE.
- **Simulate spoof**: point `--host` at a rogue resolver (or a local one
  returning bad IPs) and watch the score spike.
- **Batch scan**: paste multiple domains in the Streamlit dashboard's batch box.
