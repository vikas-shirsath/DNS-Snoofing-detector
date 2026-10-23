"""Serve an unmistakable, non-collecting fake login page on loopback only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 80

PAGE = b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - DNS spoofing lab</title>
  <style>
    :root { color-scheme: light; font: 16px system-ui, sans-serif; }
    body { margin: 0; background: #f3f4f6; color: #18212f; }
    .banner { padding: 22px 12px; background: #b00020; color: #fff; text-align: center;
              font-size: clamp(1.35rem, 5vw, 2.3rem); font-weight: 900; letter-spacing: .04em; }
    main { width: min(420px, calc(100% - 40px)); margin: 48px auto; padding: 28px;
           background: white; border-radius: 12px; box-shadow: 0 8px 28px #18212f20; }
    h1 { margin-top: 0; }
    label { display: block; margin: 16px 0 6px; }
    input { box-sizing: border-box; width: 100%; padding: 10px; }
    button { width: 100%; margin-top: 20px; padding: 11px; background: #263b66;
             color: white; border: 0; border-radius: 6px; font-size: 1rem; }
    .warning { padding: 12px; background: #fff0f0; color: #8c0019; font-weight: 800; }
  </style>
</head>
<body>
  <div class="banner">FAKE SITE - DNS SPOOFING LAB DEMO</div>
  <main>
    <p class="warning">Never enter real credentials.</p>
    <h1>Login</h1>
    <p>This fake page is served by the local lab at <code>127.0.0.1</code>.</p>
    <form onsubmit="event.preventDefault(); document.getElementById('notice').hidden = false;">
      <label for="username">Demo username</label>
      <input id="username" autocomplete="off" placeholder="Do not use a real account">
      <label for="password">Demo password</label>
      <input id="password" type="password" autocomplete="off" placeholder="Do not use a real password">
      <button type="submit">Login</button>
    </form>
    <p id="notice" class="warning" hidden>Lab demo only: nothing was submitted, sent, or stored.</p>
  </main>
</body>
</html>
"""


class FakeSiteHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(PAGE)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(PAGE)

    def do_POST(self):
        # Do not read or retain form data; this demo never accepts submissions.
        self.send_error(405, "This lab page does not accept login submissions")

    def log_message(self, format_string, *args):
        print(f"[{self.log_date_time_string()}] {self.client_address[0]} {format_string % args}", flush=True)


def create_server():
    # Keep this literal loopback address; there is no host override.
    return ThreadingHTTPServer((HOST, PORT), FakeSiteHandler)


def main():
    print("LAB SIMULATION - local only")
    try:
        server = create_server()
    except PermissionError:
        print("Could not bind to 127.0.0.1:80: port 80 needs Administrator rights. Run PowerShell as Administrator.")
        return 1
    except OSError as exc:
        print(f"Could not bind to 127.0.0.1:80 ({exc}). If port 80 is busy, stop its service (for example IIS) and retry as Administrator.")
        print("To find the process using port 80, run: netstat -ano | findstr :80")
        return 1
    print(f"Serving the fake lab page at http://{HOST}:{PORT}/. Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nFake site stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
