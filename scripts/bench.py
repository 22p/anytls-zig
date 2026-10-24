#!/usr/bin/env python3
"""Loopback benchmark for anytls-zig against the reference anytls-go stack.

Measures, for the Zig client and optionally the Go reference client:
  * bulk throughput (best of N runs) and the client's CPU cost per GiB
  * request latency over one multiplexed, keep-alive stream
  * cold-connect latency (TLS + auth + stream setup) for the Zig client
  * client RSS after warm-up

Everything runs on loopback. Numbers are comparative, not absolute WAN
figures. Requires: openssl, an anytls-go server binary, and the clients.
"""

import argparse
import http.server
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ORIGIN_PORT = 18080
SERVER_PORT = 18443
PROXY_PORT = 11080
SIZE = 64 * 1024 * 1024
CHUNK = b"x" * (1024 * 1024)


def run(cmd, **kw):
    return subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        # Disable Nagle and write the whole response with sendall: otherwise
        # headers and body are separate segments and delayed ACK adds ~40 ms
        # to every small request, masking the proxy latency we want to measure.
        conn = self.connection
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        if self.path.startswith("/small"):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            return

        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n"
            % self.server.payload_size)
        left = self.server.payload_size
        while left > 0:
            n = min(left, len(CHUNK))
            conn.sendall(CHUNK[:n])
            left -= n


def start_origin(size):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    srv.daemon_threads = True
    srv.payload_size = size
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def wait_port(port, timeout=6.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), 0.3)
            s.close()
            return True
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"port {port} did not open")


def socks_connect(proxy_port, host="127.0.0.1", port=ORIGIN_PORT):
    s = socket.create_connection(("127.0.0.1", proxy_port), 5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        raise RuntimeError("socks method negotiation failed")
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack(">H", port))
    rep = s.recv(10)
    if len(rep) < 2 or rep[1] != 0:
        raise RuntimeError(f"socks connect failed: {rep!r}")
    return s


def open_http(proxy_port):
    if proxy_port is None:
        s = socket.create_connection(("127.0.0.1", ORIGIN_PORT), 5)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s
    return socks_connect(proxy_port)


def read_headers(s):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = s.recv(65536)
        if not d:
            raise EOFError("connection closed during headers")
        buf += d
    head, rest = buf.split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    return length, rest


def drain(s, length, have):
    got = len(have)
    while got < length:
        d = s.recv(min(1 << 20, length - got))
        if not d:
            raise EOFError("short body")
        got += len(d)
    return got


def bulk(proxy_port, size, runs):
    best = 0.0
    for _ in range(runs):
        s = open_http(proxy_port)
        t0 = time.perf_counter()
        s.sendall(b"GET /big HTTP/1.1\r\nHost: bench\r\n\r\n")
        length, rest = read_headers(s)
        drain(s, length, rest)
        dt = time.perf_counter() - t0
        s.close()
        best = max(best, size / dt / 1e6)
    return best


def latency(proxy_port, count=300):
    s = open_http(proxy_port)
    samples = []
    for _ in range(count):
        t0 = time.perf_counter()
        s.sendall(b"GET /small HTTP/1.1\r\nHost: bench\r\n\r\n")
        length, rest = read_headers(s)
        drain(s, length, rest)
        samples.append((time.perf_counter() - t0) * 1000.0)
    s.close()
    samples.sort()
    n = len(samples)
    return {
        "mean_ms": sum(samples) / n,
        "p50_ms": samples[n // 2],
        "p95_ms": samples[int(n * 0.95) - 1],
    }


def cold_connect(binary, base_port, ca, work, count=3):
    """First request after a fresh client start: TLS handshake + auth + SYN."""
    out = []
    for i in range(count):
        port = base_port + i
        p = start_client(binary, port, ca, [],
                         os.path.join(work, f"cold-{i}.log"))
        try:
            s = open_http(port)
            t0 = time.perf_counter()
            s.sendall(b"GET /small HTTP/1.1\r\nHost: bench\r\n\r\n")
            length, rest = read_headers(s)
            drain(s, length, rest)
            out.append((time.perf_counter() - t0) * 1000.0)
            s.close()
        finally:
            p.kill()
            p.wait()
    return sum(out) / len(out)


def proc_cpu(pid):
    with open(f"/proc/{pid}/stat") as f:
        parts = f.read().split()
    ticks = int(parts[13]) + int(parts[14])
    return ticks / os.sysconf("SC_CLK_TCK")


def proc_rss(pid):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def start_client(binary, port, ca, extra, log):
    cmd = [binary, "-l", f"127.0.0.1:{port}", "-s", f"127.0.0.1:{SERVER_PORT}",
           "-p", "bench-pass", "--sni", "localhost",
           "--ca", ca, "--log-level", "error"] + extra
    f = open(log, "wb")
    p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
    wait_port(port)
    return p


def measure(name, pid, proxy_port, size, runs):
    time.sleep(0.3)
    cpu0 = proc_cpu(pid)
    t0 = time.perf_counter()
    speed = bulk(proxy_port, size, runs)
    wall = time.perf_counter() - t0
    cpu = proc_cpu(pid) - cpu0
    rss = proc_rss(pid)
    lat = latency(proxy_port)
    return {
        "name": name,
        "throughput_mbps": speed,
        "cpu_s": cpu,
        "cpu_per_gib_s": cpu / ((size * runs) / (1024.0 ** 3)) if size > 0 else 0,
        "cpu_pct": 100.0 * cpu / wall if wall > 0 else 0,
        "rss_kb": rss,
        "latency": lat,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", default="./zig-out/bin/anytls-zig")
    ap.add_argument("--go-client", default="")
    ap.add_argument("--server", default=os.environ.get("ANYTLS_SERVER", ""))
    ap.add_argument("--size-mb", type=int, default=64)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    for c in (args.client, args.server):
        if not c or not os.access(c, os.X_OK):
            sys.exit(f"not executable: {c!r}")
    if args.go_client and not os.access(args.go_client, os.X_OK):
        sys.exit(f"not executable: {args.go_client!r}")

    size = args.size_mb * 1024 * 1024
    work = tempfile.mkdtemp(prefix="anytls-bench.")
    procs = []
    try:
        certs = os.path.join(work, "certs")
        os.makedirs(certs)
        ca = os.path.join(certs, "ca.pem")
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(certs, "ca.key"), "-out", ca, "-days", "2",
             "-subj", "/CN=anytls-bench CA"])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
             "-keyout", os.path.join(certs, "srv.key"),
             "-out", os.path.join(certs, "srv.csr"), "-subj", "/CN=localhost"])
        ext = os.path.join(certs, "ext.cnf")
        with open(ext, "w") as f:
            f.write("subjectAltName=DNS:localhost\n"
                    "extendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
        run(["openssl", "x509", "-req", "-in", os.path.join(certs, "srv.csr"),
             "-CA", ca, "-CAkey", os.path.join(certs, "ca.key"),
             "-CAcreateserial", "-out", os.path.join(certs, "srv.pem"),
             "-days", "2", "-extfile", ext])

        start_origin(size)
        env = dict(os.environ,
                   TLS_CERT=os.path.join(certs, "srv.pem"),
                   TLS_KEY=os.path.join(certs, "srv.key"))
        srv_log = open(os.path.join(work, "server.log"), "wb")
        srv = subprocess.Popen([args.server, "-l", f"127.0.0.1:{SERVER_PORT}",
                                "-p", "bench-pass"], stdout=srv_log,
                               stderr=subprocess.STDOUT, env=env)
        procs.append(srv)
        wait_port(SERVER_PORT)

        results = []
        zig = start_client(args.client, PROXY_PORT, ca, ["--min-idle", "2"],
                           os.path.join(work, "zig.log"))
        procs.append(zig)
        results.append(measure("zig", zig.pid, PROXY_PORT, size, args.runs))
        zig.kill()
        zig.wait()

        if args.go_client:
            goport = PROXY_PORT + 1
            genv = dict(os.environ, LOG_LEVEL="error")
            glog = open(os.path.join(work, "go.log"), "wb")
            go = subprocess.Popen([args.go_client, "-l", f"127.0.0.1:{goport}",
                                   "-s", f"127.0.0.1:{SERVER_PORT}",
                                   "-p", "bench-pass"],
                                  stdout=glog, stderr=subprocess.STDOUT, env=genv)
            procs.append(go)
            wait_port(goport)
            results.append(measure("go", go.pid, goport, size, args.runs))
            go.kill()
            go.wait()

        # Cold connect: restart the client so the first request pays for a
        # full TLS handshake, authentication and stream setup.
        cold_ms = cold_connect(args.client, PROXY_PORT + 2, ca, work, 3)

        direct = bulk(None, size, args.runs)
        direct_lat = latency(None)

        print()
        print(f"anytls-zig benchmark  (payload {args.size_mb} MiB, runs {args.runs}, loopback)")
        print()
        print("| Variant | Throughput | Client CPU | CPU per GiB | CPU % | RSS |")
        print("|---|---:|---:|---:|---:|---:|")
        print(f"| direct (no proxy) | {direct:.1f} MB/s | - | - | - | - |")
        for r in results:
            print(f"| {r['name']} | {r['throughput_mbps']:.1f} MB/s | "
                  f"{r['cpu_s']:.2f} s | {r['cpu_per_gib_s']:.2f} s/GiB | "
                  f"{r['cpu_pct']:.0f}% | {r['rss_kb']} KB |")
        print()
        print("| Variant | mean | p50 | p95 |")
        print("|---|---:|---:|---:|")
        print(f"| direct | {direct_lat['mean_ms']:.3f} ms | {direct_lat['p50_ms']:.3f} ms | {direct_lat['p95_ms']:.3f} ms |")
        for r in results:
            l = r["latency"]
            print(f"| {r['name']} | {l['mean_ms']:.3f} ms | {l['p50_ms']:.3f} ms | {l['p95_ms']:.3f} ms |")
        print()
        print(f"Cold connect (TLS + auth + stream, zig): {cold_ms:.1f} ms")

        out = {
            "environment": {
                "payload_mib": args.size_mb,
                "runs": args.runs,
                "kernel": os.uname().release,
                "machine": os.uname().machine,
                "cpus": os.cpu_count(),
            },
            "direct": {"throughput_mbps": direct, "latency": direct_lat},
            "clients": results,
            "cold_connect_ms": cold_ms,
        }
        if args.json:
            with open(args.json, "w") as f:
                json.dump(out, f, indent=2)
            print(f"json: {args.json}")
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
