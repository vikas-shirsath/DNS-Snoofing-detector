"""Run the fake site and hosts-file demonstration as one local lab command."""
import sys
import threading

import fake_site
import hosts_lab


def main():
    try:
        hosts_lab.require_admin()
        server = fake_site.create_server()
    except PermissionError as exc:
        print(f"{exc}\nRun PowerShell as Administrator before starting the lab.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Could not start the local page on 127.0.0.1:80 ({exc}).", file=sys.stderr)
        print("Close the service using port 80 (for example IIS), then retry in Administrator PowerShell.", file=sys.stderr)
        print("Find the process with: netstat -ano | findstr :80", file=sys.stderr)
        return 1

    web_thread = threading.Thread(target=server.serve_forever, name="fake-site", daemon=True)
    web_thread.start()
    print("LAB SIMULATION - local only")
    print("Fake page is ready at http://127.0.0.1/ (bound to loopback only).")
    try:
        hosts_lab.run_demo_flow()
    except KeyboardInterrupt:
        print("\nCtrl+C received; restoring the hosts file and stopping the fake page.")
    except (OSError, RuntimeError) as exc:
        print(f"Lab stopped: {exc}", file=sys.stderr)
        return 1
    finally:
        # run_demo_flow owns hosts cleanup; the runner always stops its web server.
        server.shutdown()
        server.server_close()
        web_thread.join(timeout=3)
        print("Fake page server stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
