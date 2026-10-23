"""Manage this lab's marked example.com entry in the Windows hosts file."""
import argparse
import atexit
import ctypes
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BEGIN = "# BEGIN DNS SPOOFING LAB (managed by hosts_lab.py)"
END = "# END DNS SPOOFING LAB (managed by hosts_lab.py)"
ENTRY = "127.0.0.1 example.com"
SCRIPT_DIR = Path(__file__).resolve().parent
BACKUP_PATH = SCRIPT_DIR / "hosts.backup"
BLOCK_RE = re.compile(rf"(?m)^{re.escape(BEGIN)}\r?\n.*?^{re.escape(END)}(?:\r?\n)?", re.DOTALL)


def hosts_path():
    if os.name != "nt":
        raise RuntimeError("This helper only supports Windows hosts files.")
    windows_dir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    return windows_dir / "System32" / "drivers" / "etc" / "hosts"


def require_admin():
    if os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Administrator rights are required. Open PowerShell with 'Run as administrator' and try again.")


def read_hosts(path):
    data = path.read_bytes()
    has_bom = data.startswith(b"\xef\xbb\xbf")
    text = data.decode("utf-8-sig" if has_bom else "utf-8", errors="surrogateescape")
    return text, has_bom


def write_hosts(path, text, has_bom):
    data = text.encode("utf-8", errors="surrogateescape")
    path.write_bytes((b"\xef\xbb\xbf" if has_bom else b"") + data)


def flush_dns_cache():
    try:
        result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, check=False)
    except OSError as exc:
        print(f"Could not run ipconfig /flushdns ({exc}). Flush the Windows DNS cache manually.")
        return False
    if result.returncode == 0:
        print("Windows DNS cache flushed.")
        return True
    print("Could not flush DNS automatically. Run `ipconfig /flushdns` as Administrator.")
    return False


def entry_is_active(text):
    match = BLOCK_RE.search(text)
    if not match:
        return False
    block = match.group(0)
    return any(line.split("#", 1)[0].strip().lower() == ENTRY.lower() for line in block.splitlines())


def status(path=None):
    path = path or hosts_path()
    text, _ = read_hosts(path)
    active = entry_is_active(text)
    print(f"Lab hosts entry: {'ACTIVE (example.com -> 127.0.0.1)' if active else 'inactive'}")
    print(f"hosts.backup: {'exists' if BACKUP_PATH.is_file() else 'missing'} ({BACKUP_PATH})")
    return active


def add_entry(path=None):
    path = path or hosts_path()
    text, has_bom = read_hosts(path)
    if BEGIN in text or END in text:
        if BEGIN in text and END in text and entry_is_active(text):
            print("The lab hosts entry is already installed.")
            return False
        raise RuntimeError("Found an incomplete or unexpected managed block. Inspect the hosts file before changing it.")

    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and "example.com" in [name.lower() for name in fields[1:]]:
            raise RuntimeError(f"An existing example.com hosts entry is present: {line.strip()!r}. Review it manually first.")

    if not BACKUP_PATH.exists():
        shutil.copy2(path, BACKUP_PATH)
        print(f"Original hosts file backed up to: {BACKUP_PATH}")
    else:
        print(f"Keeping the existing backup unchanged: {BACKUP_PATH}")

    newline = "\r\n" if "\r\n" in text else "\n"
    if text and not text.endswith(("\n", "\r")):
        text += newline
    text += newline.join((BEGIN, ENTRY, END, ""))
    write_hosts(path, text, has_bom)
    flush_dns_cache()
    print("Installed example.com -> 127.0.0.1. Visit http://example.com/.")
    return True


def remove_entry(path=None):
    path = path or hosts_path()
    text, has_bom = read_hosts(path)
    updated, count = BLOCK_RE.subn("", text, count=1)
    if count == 0:
        print("No managed lab entry found; hosts file left unchanged.")
        flush_dns_cache()
        return False
    write_hosts(path, updated, has_bom)
    print("Removed only the managed lab block; unrelated hosts entries were preserved.")
    flush_dns_cache()
    if BACKUP_PATH.exists():
        print(f"Original backup retained at: {BACKUP_PATH}")
    return True


def _cleanup_at_exit(path):
    try:
        remove_entry(path)
    except Exception as exc:
        print(f"Cleanup at exit could not remove the lab hosts entry: {exc}", file=sys.stderr)
        flush_dns_cache()


def run_demo_flow(path=None):
    """Install the mapping, wait for the browser demo, then always restore it."""
    require_admin()
    path = path or hosts_path()
    if status(path):
        raise RuntimeError("The lab entry is already active. Remove it first, then rerun demo so cleanup cannot remove a pre-existing mapping.")

    cleanup = lambda: _cleanup_at_exit(path)
    atexit.register(cleanup)
    try:
        add_entry(path)
        print("\nDemo is active. Open http://example.com/ and observe the browser extension's verdict.")
        print("The local page is clearly labeled FAKE SITE - DNS SPOOFING LAB DEMO.")
        print("Press Enter to restore the hosts file, or Ctrl+C to restore and exit.")
        input()
    finally:
        try:
            _cleanup_at_exit(path)
        finally:
            atexit.unregister(cleanup)


def main():
    parser = argparse.ArgumentParser(description="Local-only example.com hosts-file demo.")
    parser.add_argument("action", choices=("add", "remove", "status", "demo"))
    args = parser.parse_args()
    try:
        require_admin()
        path = hosts_path()
        if not path.is_file():
            raise FileNotFoundError(f"Windows hosts file not found: {path}")
        if args.action == "add":
            add_entry(path)
        elif args.action == "remove":
            remove_entry(path)
        elif args.action == "status":
            status(path)
        else:
            run_demo_flow(path)
    except KeyboardInterrupt:
        print("\nDemo interrupted; cleanup has run.")
    except (OSError, RuntimeError, PermissionError) as exc:
        print(f"hosts_lab.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
