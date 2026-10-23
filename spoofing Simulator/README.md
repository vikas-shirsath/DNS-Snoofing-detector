# Local DNS spoofing lab

**Emergency restore:** if cleanup is interrupted, run `restore_hosts.bat` as Administrator. It copies the saved `hosts.backup` over the Windows hosts file and flushes the DNS cache. It requires a backup created by `hosts_lab.py add` or `hosts_lab.py demo`.

This is an educational, local-machine-only simulation. The fake website and DNS server bind only to `127.0.0.1`. Never enter real credentials.

## Demo 1: browser extension via hosts file

1. From Administrator PowerShell, run `python hosts_lab.py status`. If the entry is ACTIVE, run `python hosts_lab.py remove` first. Then visit **`http://example.com/`** explicitly while the entry is inactive; the extension should show **SAFE**.
2. Open **Administrator PowerShell** in this folder and run `python run_lab.py`. It starts the fake site in a background thread, installs the marked `example.com -> 127.0.0.1` hosts entry, flushes DNS, and waits for Enter.
3. During the prompt, reload `http://example.com/`. The red **FAKE SITE - DNS SPOOFING LAB DEMO** page should appear; the extension should report **SPOOFED**. Press Enter or Ctrl+C to restore the hosts entry and stop the site.
4. If Chrome serves a cached/HTTPS page, clear its host cache at `chrome://net-internals/#dns`, flush socket pools at `chrome://net-internals/#sockets`, and turn off **Always use secure connections** in Chrome settings for the demo.
5. For manual control, `python hosts_lab.py status` reports the managed entry and backup; `python hosts_lab.py add`, `python hosts_lab.py remove`, and `python hosts_lab.py demo` are available from an elevated terminal.

## Demo 2: Python CLI or Streamlit detector via fake DNS

1. Install the dependency: `python -m pip install dnslib`.
2. Start the DNS resolver with `python fake_dns_server.py`. It reads `spoof_config.json` on each query; set `"mode": "spoof"` for a loopback A answer with TTL 5, or `"mode": "honest"` to forward all queries to `8.8.8.8`.
3. From the detector folder, run `python cli.py example.com --host 127.0.0.1 --port 5353` (or start its Streamlit app and use the same resolver/port). Stop the DNS server with Ctrl+C.

## Demo 3: emergency hosts restore

Run `restore_hosts.bat` as Administrator to restore the full original hosts-file backup and flush the Windows DNS cache. This restores the snapshot as it existed before the lab first added its mapping; use `python hosts_lab.py remove` during normal cleanup to preserve unrelated later edits.
