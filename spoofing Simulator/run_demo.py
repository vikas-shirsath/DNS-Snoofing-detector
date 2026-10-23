"""Run the detector against honest, spoofed, and flaky local DNS answers."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONFIG = HERE / "spoof_config.json"
SERVER = HERE / "fake_dns_server.py"
DETECTOR_DIR = HERE if (HERE / "cli.py").is_file() else HERE.parent / "detector"
DETECTOR = DETECTOR_DIR / "cli.py"
SCENARIOS = [
    ("honest", "example.com", "SAFE", "Forwards to Google DNS"),
    ("spoof", "example.com", "SPOOFED", "Returns the configured fake IP"),
    ("flaky", "example.com", "SUSPICIOUS", "Randomly mixes upstream and fake answers; repeat to observe changes"),
]


def set_mode(mode):
    config = json.loads(CONFIG.read_text(encoding="utf-8-sig"))
    config["mode"] = mode
    CONFIG.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def main():
    original_config = CONFIG.read_text(encoding="utf-8-sig")
    server = subprocess.Popen([sys.executable, str(SERVER)], cwd=HERE)
    try:
        # Give the UDP server time to bind, while still noticing startup errors promptly.
        for _ in range(40):
            if server.poll() is not None:
                raise RuntimeError("DNS server exited before it was ready")
            time.sleep(0.1)
        for mode, domain, expected, explanation in SCENARIOS:
            set_mode(mode)
            print(f"\n=== {mode.upper()} mode: {domain} (expect {expected}) ===")
            print(explanation)
            command = [sys.executable, "cli.py", domain, "--host", "127.0.0.1", "--port", "5353"]
            if DETECTOR.is_file():
                detector_env = os.environ.copy()
                detector_env["PYTHONIOENCODING"] = "utf-8"
                subprocess.run(command, cwd=DETECTOR_DIR, check=False, env=detector_env)
            else:
                print("Detector cli.py is missing; run when available:")
                print(f"python cli.py {domain} --host 127.0.0.1 --port 5353")
    finally:
        CONFIG.write_text(original_config, encoding="utf-8")
        server.terminate()
        try:
            server.wait(timeout=3)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    main()
