#!/usr/bin/env python3
"""Metho DoH proxy — a local UDP DNS listener that forwards every query over
DNS-over-HTTPS (RFC 8484) to trusted endpoints.

Why this exists
---------------
dnsx is the pipeline's resolver and it does a lot more than send packets:
wildcard detection (``-auto-wildcard``/``-wd``), rcode filtering (``-rcode``),
record-type queries (``-a -aaaa -cname -mx -ns -txt``), PTR lookups and retry
rotation all live inside it. Re-implementing those to gain a new transport
would be a large, risky rewrite.

So instead of replacing the resolver, we replace only the *transport*. dnsx is
pointed at 127.0.0.1 and this process answers on the other side of that socket
by POSTing the query to a DoH endpoint. dnsx cannot tell the difference.

Why not dnsx's own ``doh:`` resolvers? In dnsx v1.3.1 they do not work at all:
every ``doh:https://…`` entry fails with ``Post "https://…/dns-query": EOF``
even on networks where ``curl -X POST`` and Python ``requests`` complete the
identical request against the identical endpoint (HTTP 200). ``dot:`` and
``tcp:`` transports likewise return zero results while a plain UDP resolver
works. The format is right — retryabledns' ``parseResolver()`` documents
exactly the form we emit — the client is what is broken. See
``docs/../README`` for the reproduction.

Design notes
------------
* The proxy never parses DNS. It moves opaque wire-format bytes from a UDP
  socket to an HTTPS POST and the response back. That is the whole contract,
  which is why it can stay this small.
* Per-thread ``requests.Session`` with a bounded connection pool: a fresh TLS
  handshake per query would cap throughput far below what dnsx needs.
* Endpoint rotation on failure — one dead endpoint must not stall the run.
* A query that fails on every endpoint is DROPPED, not answered with SERVFAIL.
  dnsx then times out and retries it through its own retry logic, which is the
  behaviour we want; synthesising a failure would be recorded as a definitive
  negative answer and quietly corrupt the canonical DNS dataset.
* Nothing is written to stdout. The caller learns the bound port from
  ``--port-file``, so stdout/stderr stay free for logs.
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter

# Probe name for endpoint health checks. Deliberately NOT a well-known
# DoH-endpoint hostname (one.one.one.one, dns.google, …): some DNS security
# appliances sinkhole those names for ANY destination, which would make a dead
# endpoint look alive. whoami.akamai.net is answered only by a genuine
# recursive resolver.
PROBE_NAME = "whoami.akamai.net"

# Default endpoints are IP literals on purpose: resolving a DoH hostname such
# as cloudflare-dns.com would need the very resolver we are trying to replace.
#
# Ordered with the providers observed to survive a heavily filtered network
# first. Probe results from the network this was tuned on — where the original
# three-endpoint default left exactly ONE usable endpoint, so the run had no
# failover and every query funnelled through a single provider:
#
#     reachable : 8.8.8.8, 8.8.4.4 (Google)
#                 94.140.14.14, 94.140.15.15 (AdGuard)
#                 208.67.222.222, 208.67.220.220 (OpenDNS)
#     filtered  : 1.1.1.1, 1.0.0.1 (Cloudflare), 9.9.9.9, 149.112.112.112
#                 (Quad9), 76.76.2.0 (ControlD), 194.242.2.2 (Mullvad),
#                 193.110.81.0 / 185.253.5.254 (dns0.eu), 185.228.168.9
#                 (CleanBrowsing), 64.6.64.6, 156.154.70.1, 101.101.101.101,
#                 77.88.8.8, 223.5.5.5, 180.184.1.1
#
# All six reachable entries were verified to return real A records AND a
# genuine NXDOMAIN (rcode 3) for a nonexistent name — the latter matters
# because the NXDOMAIN-settling pass filters on rcode, so an endpoint that
# answered only positive queries would silently break it.
#
# Cloudflare and Quad9 are kept in the list anyway: two of the three original
# defaults being filtered here is a property of THIS network, not of the tool.
# The startup probe demotes anything unreachable, and `EndpointPool` keeps
# demoted endpoints as a last resort, so they cost one parallel probe attempt
# and buy coverage on networks where Google/AdGuard/OpenDNS are the blocked
# ones.
DEFAULT_ENDPOINTS = (
    "https://8.8.8.8/dns-query",
    "https://8.8.4.4/dns-query",
    "https://94.140.14.14/dns-query",
    "https://94.140.15.15/dns-query",
    "https://208.67.222.222/dns-query",
    "https://208.67.220.220/dns-query",
    "https://1.1.1.1/dns-query",
    "https://9.9.9.9/dns-query",
)

# DNS-over-HTTPS messages are small (A/AAAA/CNAME answers are a few dozen
# bytes). This bound exists so a pathological response cannot be handed to a
# UDP socket that expects a datagram, not a stream.
MAX_UDP_RESPONSE = 4096
_TRUNCATED_FLAG = 0x02  # byte 2, bit 1 of the DNS header


def build_query(name: str, qtype: int = 1) -> bytes:
    """Minimal wire-format A query — no DNS library needed, the proxy never
    parses DNS and only needs bytes to send."""
    header = struct.pack(">HHHHHH", 0x2D0F, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(label)]) + label.encode()
                     for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", qtype, 1)


def probe_endpoints(endpoints, timeout: float) -> dict[str, bool]:
    """Return {url: answered}. Used at startup (and by --probe) to learn which
    endpoints are usable from THIS network before the run depends on them."""
    wire = build_query(PROBE_NAME)
    results: dict[str, bool] = {}

    def check(url: str) -> tuple[str, bool]:
        try:
            session = requests.Session()
            session.mount("https://", HTTPAdapter(pool_maxsize=1, max_retries=0))
            response = session.post(
                url, data=wire,
                headers={"content-type": "application/dns-message",
                         "accept": "application/dns-message"},
                timeout=timeout,
            )
            # A DNS response is at least the 12-byte header; anything shorter
            # is not an answer, even if the HTTP status said 200.
            return url, response.status_code == 200 and len(response.content) >= 12
        except Exception:  # noqa: BLE001 — a probe that raises is a failed probe
            return url, False
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass

    with ThreadPoolExecutor(max_workers=max(1, len(endpoints))) as pool:
        for url, ok in pool.map(check, endpoints):
            results[url] = ok
    return results


class EndpointPool:
    """Orders DoH endpoints by health so a blocked or tarpitted one cannot
    hold up the run.

    This is not hypothetical: on the network this proxy was developed
    against, 1.1.1.1 answered DoH POSTs promptly while 8.8.8.8 accepted the
    TCP connection and then never replied. Plain round-robin sent a third of
    all queries into that black hole, where each one burned the full request
    timeout — a 60 q/s transport collapsed to 6 q/s.

    A endpoint is demoted after `fail_threshold` consecutive failures and
    retried after `cooldown` seconds, so a transient outage self-heals without
    a restart. Demoted endpoints stay in the rotation as a last resort: a
    query that could still be answered is better than one dropped.
    """

    def __init__(self, endpoints, fail_threshold: int = 3, cooldown: float = 60.0):
        self._lock = threading.Lock()
        self._urls = list(endpoints)
        self._fails = {u: 0 for u in self._urls}
        self._down_until = {u: 0.0 for u in self._urls}
        self._cursor = 0
        self._fail_threshold = fail_threshold
        self._cooldown = cooldown

    def candidates(self) -> list[str]:
        """Endpoints to try for one query, best first."""
        now = time.monotonic()
        with self._lock:
            up = [u for u in self._urls if self._down_until[u] <= now]
            down = [u for u in self._urls if self._down_until[u] > now]
            # Rotate within the healthy set so load spreads across endpoints;
            # append demoted ones only as a last resort.
            if up:
                start = self._cursor % len(up)
                self._cursor = (self._cursor + 1) % len(up)
                up = up[start:] + up[:start]
            return up + down

    def note_ok(self, url: str) -> None:
        with self._lock:
            if self._fails.get(url, 0) >= self._fail_threshold:
                print(f"[doh-proxy] endpoint recovered: {url}", file=sys.stderr, flush=True)
            self._fails[url] = 0
            self._down_until[url] = 0.0

    def note_fail(self, url: str) -> None:
        with self._lock:
            self._fails[url] = self._fails.get(url, 0) + 1
            # `>=`, not `==`: the counter keeps climbing past the threshold, and
            # an equality test fires exactly once. After the first cooldown
            # expired the endpoint came back for good, so a permanently blocked
            # endpoint silently rejoined the rotation and cost every batch the
            # full request timeout on a third of its queries. Refreshing the
            # deadline on each failure keeps a dead endpoint out while still
            # letting a transiently-failing one return once it stops failing.
            if self._fails[url] >= self._fail_threshold:
                self._down_until[url] = time.monotonic() + self._cooldown
                if self._fails[url] == self._fail_threshold:
                    print(
                        f"[doh-proxy] endpoint demoted after {self._fail_threshold} "
                        f"consecutive failures (rechecked every {self._cooldown:.0f}s): {url}",
                        file=sys.stderr, flush=True,
                    )

    def demote(self, url: str) -> None:
        """Take an endpoint out of the rotation immediately (startup probe)."""
        with self._lock:
            self._down_until[url] = time.monotonic() + self._cooldown
            self._fails[url] = max(self._fails.get(url, 0), self._fail_threshold)

    def healthy(self) -> list[str]:
        now = time.monotonic()
        with self._lock:
            return [u for u in self._urls if self._down_until[u] <= now]


class Stats:
    """Query counters, reported periodically so a failing path is visible."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.queries = 0
        self.answered = 0
        self.dropped = 0
        self.endpoint_errors: dict[str, int] = {}

    def bump(self, field: str, n: int = 1) -> None:
        with self.lock:
            setattr(self, field, getattr(self, field) + n)

    def endpoint_error(self, err: str) -> None:
        with self.lock:
            key = err.split(":")[0][:40]
            self.endpoint_errors[key] = self.endpoint_errors.get(key, 0) + 1

    def snapshot(self) -> tuple[int, int, int, dict[str, int]]:
        with self.lock:
            return self.queries, self.answered, self.dropped, dict(self.endpoint_errors)


class DohProxy:
    def __init__(self, endpoints, threads: int, timeout: float, verbose: bool):
        self.endpoints = endpoints
        self.timeout = timeout
        # Total wall-clock a single query may spend across ALL endpoints.
        # Must stay below the caller's per-query timeout (dnsx:
        # DNSX_QUERY_TIMEOUT_DOH, default 15s) so the proxy always resolves or
        # drops a query before its client gives up on it.
        self.query_budget = float(os.environ.get("DOH_QUERY_BUDGET", "12"))
        self.verbose = verbose
        self.threads = threads
        self.stats = Stats()
        self.pool = ThreadPoolExecutor(max_workers=threads, thread_name_prefix="doh")
        self._local = threading.local()
        self._pool = EndpointPool(
            endpoints,
            fail_threshold=int(os.environ.get("DOH_FAIL_THRESHOLD", "3")),
            cooldown=float(os.environ.get("DOH_COOLDOWN", "60")),
        )
        self._stop = threading.Event()

    # ── HTTP plumbing ───────────────────────────────────────────────────────
    def _session(self) -> requests.Session:
        """One Session (and therefore one connection pool) per worker thread."""
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            adapter = HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
            self._local.session = s
        return s

    def resolve(self, wire: bytes) -> bytes | None:
        """Forward one wire-format query. Returns the wire response or None."""
        last_error = "no-endpoint"
        # One overall deadline for the whole query, independent of how many
        # endpoints are configured. Without it the worst case is
        # len(endpoints) × per-request timeout, so growing the endpoint list
        # (which the default list does, for failover coverage) would silently
        # push a failing query past dnsx's own per-query budget
        # (DNSX_QUERY_TIMEOUT_DOH). dnsx would then abandon a query the proxy
        # is still working on and record a "timeout" on a host that was about
        # to be answered — the exact mislabelling the timeout budget exists to
        # prevent. Bounding the query, not the endpoint count, keeps the
        # invariant true for any list length.
        deadline = time.monotonic() + self.query_budget
        # Healthy endpoints first, demoted ones last. Every endpoint gets one
        # attempt: a single blocked endpoint must not fail a query while a
        # working one is available.
        for endpoint in self._pool.candidates():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                last_error = "query budget exhausted"
                break
            try:
                response = self._session().post(
                    endpoint,
                    data=wire,
                    headers={
                        "content-type": "application/dns-message",
                        "accept": "application/dns-message",
                    },
                    timeout=min(self.timeout, remaining),
                )
                if response.status_code != 200:
                    last_error = f"HTTP {response.status_code}"
                    self.stats.endpoint_error(last_error)
                    self._pool.note_fail(endpoint)
                    continue
                if not response.content:
                    last_error = "empty response"
                    self.stats.endpoint_error(last_error)
                    self._pool.note_fail(endpoint)
                    continue
                self._pool.note_ok(endpoint)
                return response.content
            except Exception as exc:  # noqa: BLE001 — any transport error rotates
                last_error = type(exc).__name__
                self.stats.endpoint_error(last_error)
                self._pool.note_fail(endpoint)
        if self.verbose:
            print(f"[doh-proxy] dropped query: {last_error}", file=sys.stderr, flush=True)
        return None

    # ── UDP server ──────────────────────────────────────────────────────────
    def _handle(self, sock: socket.socket, wire: bytes, addr) -> None:
        try:
            response = self.resolve(wire)
            if response is None:
                self.stats.bump("dropped")
                return
            if len(response) > MAX_UDP_RESPONSE:
                # Preserve the DNS message but signal truncation, as an
                # authoritative server would, instead of emitting a datagram
                # larger than the client's read buffer.
                response = bytearray(response)
                if len(response) > 2:
                    response[2] |= _TRUNCATED_FLAG
                response = bytes(response[:MAX_UDP_RESPONSE])
            sock.sendto(response, addr)
            self.stats.bump("answered")
        except (OSError, ValueError):
            # A dead client or a closed socket is not worth failing the run for.
            self.stats.bump("dropped")

    def serve(self, host: str, port: int, port_file: str | None) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # A large receive buffer keeps a burst of dnsx queries from being
        # dropped by the kernel before a worker picks them up.
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        sock.bind((host, port))
        bound_port = sock.getsockname()[1]

        # Probe before advertising the port: a caller that sees the port file
        # must be able to assume the proxy has already found a working path.
        # Demoting the dead endpoints up front also stops the first batch of
        # real queries from each burning a full timeout against a black hole.
        reachable = probe_endpoints(self.endpoints, min(self.timeout, 8.0))
        usable = [u for u in self.endpoints if reachable.get(u)]
        for url, ok in reachable.items():
            if not ok:
                self._pool.demote(url)
        if not usable:
            print(
                "[doh-proxy] WARNING: no DoH endpoint answered the startup probe — "
                "every query will be dropped. Check that TCP/443 to a DoH endpoint "
                "is permitted from this network.",
                file=sys.stderr, flush=True,
            )
        else:
            print(
                f"[doh-proxy] endpoint probe: {len(usable)}/{len(self.endpoints)} "
                f"reachable — {', '.join(usable)}",
                file=sys.stderr, flush=True,
            )

        if port_file:
            # Write atomically: the caller polls this file, and a partial read
            # would look like a malformed port number.
            tmp = f"{port_file}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(f"{bound_port}\n")
            os.replace(tmp, port_file)

        print(
            f"[doh-proxy] listening on {host}:{bound_port} "
            f"({len(self.endpoints)} endpoint(s), {self.threads} threads)",
            file=sys.stderr,
            flush=True,
        )

        def _shutdown(_signum, _frame):
            self._stop.set()
            try:
                sock.close()
            except OSError:
                pass

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        last_report = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    wire, addr = sock.recvfrom(65535)
                except OSError:
                    break  # socket closed by the signal handler
                if not wire:
                    continue
                self.stats.bump("queries")
                self.pool.submit(self._handle, sock, wire, addr)

                now = time.monotonic()
                if now - last_report >= 30:
                    self._report()
                    last_report = now
        finally:
            self._report()
            self.pool.shutdown(wait=False, cancel_futures=True)
            try:
                sock.close()
            except OSError:
                pass
        return 0

    def _report(self) -> None:
        queries, answered, dropped, errors = self.stats.snapshot()
        if queries == 0:
            return
        detail = ""
        if errors:
            worst = sorted(errors.items(), key=lambda kv: -kv[1])[:3]
            detail = "  errors=" + ", ".join(f"{k}×{v}" for k, v in worst)
        print(
            f"[doh-proxy] queries={queries} answered={answered} dropped={dropped}{detail}",
            file=sys.stderr,
            flush=True,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local UDP→DoH DNS forwarder")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0,
                        help="UDP port to bind (0 = pick a free one)")
    parser.add_argument("--port-file", default=None,
                        help="write the bound port here once listening")
    parser.add_argument("--endpoints", default=",".join(DEFAULT_ENDPOINTS),
                        help="comma-separated DoH endpoint URLs")
    parser.add_argument("--threads", type=int, default=64)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--probe", action="store_true",
                        help="probe each endpoint and exit 0 if any answered")
    args = parser.parse_args(argv)

    endpoints = [e.strip() for e in args.endpoints.split(",") if e.strip()]
    if not endpoints:
        print("[doh-proxy] no endpoints configured", file=sys.stderr)
        return 2

    if args.probe:
        reachable = probe_endpoints(endpoints, min(args.timeout, 8.0))
        for url in endpoints:
            print(f"{'OK  ' if reachable.get(url) else 'DEAD'} {url}")
        return 0 if any(reachable.values()) else 1

    proxy = DohProxy(endpoints, threads=max(1, args.threads),
                     timeout=args.timeout, verbose=args.verbose)
    try:
        return proxy.serve(args.host, args.port, args.port_file)
    except OSError as exc:
        print(f"[doh-proxy] cannot bind {args.host}:{args.port}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
