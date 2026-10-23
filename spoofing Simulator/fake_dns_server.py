"""Loopback-only educational DNS spoofing resolver (dnslib required)."""
import json
import logging
import socket
import socketserver
import sys
from datetime import datetime
from pathlib import Path

from dnslib import A, DNSRecord, QTYPE, RCODE, RR

BIND_ADDRESS = "127.0.0.1"
BIND_PORT = 5353
UPSTREAM_ADDRESS = "8.8.8.8"
UPSTREAM_PORT = 53
UPSTREAM_TIMEOUT_SECONDS = 2.0
CONFIG_PATH = Path(__file__).with_name("spoof_config.json")
VALID_MODES = {"spoof", "honest"}
COLORS = {"SPOOFED": "\033[91m", "FORWARDED": "\033[92m", "SERVFAIL": "\033[93m"}
RESET = "\033[0m"


class LabFormatter(logging.Formatter):
    def format(self, record):
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp} {record.domain} {record.outcome} -> {record.result}"
        color = COLORS.get(record.outcome, "") if sys.stdout.isatty() else ""
        return f"{color}{line}{RESET}" if color else line


LOGGER = logging.getLogger("fake_dns_lab")
LOGGER.setLevel(logging.INFO)
LOGGER.handlers.clear()
console = logging.StreamHandler(sys.stdout)
console.setFormatter(LabFormatter())
LOGGER.addHandler(console)
LOGGER.propagate = False


def log_query(domain, outcome, result):
    LOGGER.info("", extra={"domain": domain, "outcome": outcome, "result": result or "(no A record)"})


def load_mode():
    """Read the selected mode for every incoming DNS request."""
    with CONFIG_PATH.open(encoding="utf-8-sig") as config_file:
        config = json.load(config_file)
    mode = config.get("mode", "spoof")
    if mode not in VALID_MODES:
        raise ValueError("spoof_config.json mode must be 'spoof' or 'honest'")
    return mode


class DNSRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, client_socket = self.request
        request = None
        domain = "<unparseable>"
        try:
            request = DNSRecord.parse(packet)
            if not request.questions:
                raise ValueError("DNS request has no question")
            question = request.questions[0]
            domain = str(question.qname).rstrip(".") or "."
            mode = load_mode()

            if mode == "spoof" and QTYPE[question.qtype] == "A" and domain.lower() == "example.com":
                response = request.reply()
                response.add_answer(RR(question.qname, QTYPE.A, rdata=A("127.0.0.1"), ttl=5))
                client_socket.sendto(response.pack(), self.client_address)
                log_query(domain, "SPOOFED", "127.0.0.1 (TTL 5)")
                return

            # Forward the original wire packet and relay the upstream response unchanged.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                upstream.settimeout(UPSTREAM_TIMEOUT_SECONDS)
                upstream.sendto(packet, (UPSTREAM_ADDRESS, UPSTREAM_PORT))
                response_packet, _ = upstream.recvfrom(65535)
            client_socket.sendto(response_packet, self.client_address)
            parsed = DNSRecord.parse(response_packet)
            addresses = [str(record.rdata) for record in parsed.rr if QTYPE[record.rtype] == "A"]
            log_query(domain, "FORWARDED", ", ".join(addresses))
        except Exception as exc:
            print(f"DNS request for {domain} failed ({exc}); replying SERVFAIL.", file=sys.stderr)
            if request is not None:
                try:
                    response = request.reply()
                    response.header.rcode = RCODE.SERVFAIL
                    response.rr = []
                    response.auth = []
                    response.ar = []
                    client_socket.sendto(response.pack(), self.client_address)
                except OSError:
                    pass
            log_query(domain, "SERVFAIL", "")


class LocalDNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    print("LAB SIMULATION - local only")
    print(f"Listening on {BIND_ADDRESS}:{BIND_PORT}/udp; upstream {UPSTREAM_ADDRESS}")
    try:
        with LocalDNSServer((BIND_ADDRESS, BIND_PORT), DNSRequestHandler) as server:
            server.serve_forever()
    except OSError as exc:
        print(f"Could not start local DNS server: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nDNS server stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
