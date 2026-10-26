"""certwatch.py - check TLS certificates on a list of endpoints and flag problems early.

Usage:
    python certwatch.py endpoints.txt              # table on screen
    python certwatch.py endpoints.txt --report report.md --json results.json
Exit code 0 = all OK, 1 = at least one WARN, CRIT or ERROR (so CI can alert).
"""

import argparse
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass

DEFAULT_PORT = 443


@dataclass
class Result:
    endpoint: str
    status: str  # OK, WARN, CRIT or ERROR
    days_left: int | None
    expires: str
    issuer: str
    detail: str


def parse_endpoint(line: str) -> tuple[str, int] | None:
    """Turn 'example.com' or 'example.com:8443' into (host, port); skip blanks and # comments."""
    line = line.split("#", 1)[0].strip()
    if not line:
        return None
    line = line.removeprefix("https://").split("/", 1)[0]
    host, _, port = line.partition(":")
    return host.lower(), int(port) if port else DEFAULT_PORT


def classify(days_left: int, warn: int, crit: int) -> str:
    """OK above the warning line, WARN inside it, CRIT inside the critical line or expired."""
    if days_left <= crit:
        return "CRIT"
    if days_left <= warn:
        return "WARN"
    return "OK"


def issuer_name(cert: dict) -> str:
    """The issuer's organization (or common name) from Python's certificate dict."""
    fields = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
    return fields.get("organizationName") or fields.get("commonName") or "unknown"


def check(host: str, port: int, warn: int, crit: int, timeout: float = 10) -> Result:
    """Open a verified TLS connection, read the certificate and judge it."""
    name = host if port == DEFAULT_PORT else f"{host}:{port}"
    context = ssl.create_default_context()  # checks the chain AND that the name matches
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as e:
        # Expired, wrong host name, self-signed, unknown root: the handshake refuses it
        return Result(name, "ERROR", None, "", "", f"verification failed: {e.verify_message}")
    except (OSError, ssl.SSLError) as e:  # DNS failure, refused, timeout, TLS error
        return Result(name, "ERROR", None, "", "", f"connection failed: {e}")
    expires_at = ssl.cert_time_to_seconds(cert["notAfter"])
    days_left = int((expires_at - time.time()) // 86400)
    expires = time.strftime("%Y-%m-%d", time.gmtime(expires_at))
    status = classify(days_left, warn, crit)
    return Result(name, status, days_left, expires, issuer_name(cert), f"{days_left} days left")


def to_markdown(results: list[Result]) -> str:
    """A table for GitHub issues and the job summary, problems first."""
    order = {"ERROR": 0, "CRIT": 1, "WARN": 2, "OK": 3}
    rows = sorted(results, key=lambda r: (order[r.status], r.days_left or 0))
    lines = ["| Status | Endpoint | Expires | Days left | Issuer | Detail |", "|---|---|---|---|---|---|"]
    for r in rows:
        days = "" if r.days_left is None else str(r.days_left)
        lines.append(f"| {r.status} | {r.endpoint} | {r.expires} | {days} | {r.issuer} | {r.detail} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check TLS certificates before they cause an outage.")
    parser.add_argument("endpoints", help="text file with one host or host:port per line")
    parser.add_argument("--warn", type=int, default=21, help="WARN when this many days or fewer are left")
    parser.add_argument("--crit", type=int, default=7, help="CRIT when this many days or fewer are left")
    parser.add_argument("--report", help="also write a Markdown report to this file")
    parser.add_argument("--json", dest="json_path", help="also write the results as JSON to this file")
    args = parser.parse_args()

    with open(args.endpoints, encoding="utf-8") as f:
        targets = [t for t in (parse_endpoint(line) for line in f) if t]
    results = [check(host, port, args.warn, args.crit) for host, port in targets]

    for r in results:
        print(f"{r.status:<6} {r.endpoint:<40} {r.detail}")
    report = to_markdown(results)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report)
    if args.json_path:
        with open(args.json_path, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2)

    problems = [r for r in results if r.status != "OK"]
    print(f"\n{len(results)} checked, {len(problems)} need attention")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
