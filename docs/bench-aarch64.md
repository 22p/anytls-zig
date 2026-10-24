# aarch64 performance

Loopback measurements of the Zig client and the reference Go client, both
talking to an unmodified `anytls-go 0.0.13` server. The point is to quantify the
client's cost (CPU, latency, memory) and the `ReleaseSmall` size/speed
trade-off, not to predict WAN throughput.

## Environment

| Item | Value |
|---|---|
| Host | aarch64 Linux, 2 vCPU, kernel 7.2.7 |
| Crypto extensions | `aes`, `pmull`, `sha1`, `sha2`, `crc32` present |
| Zig | 0.15.1 (native aarch64 toolchain) |
| Server | anytls-go 0.0.13, TLS 1.3, RSA-2048 certificate from a local CA |
| Reference client | anytls-go 0.0.13 client (Go 1.26) |
| Origin | Python threaded HTTP server on loopback, 128 MiB body |
| Runs | 3, best throughput; 300 keep-alive requests for latency |
| Date | 2026-10-24 |

Reproduce:

```sh
zig build -Doptimize=ReleaseSmall -Dtarget=aarch64-linux-musl
python3 scripts/bench.py \
    --client zig-out/bin/anytls-zig \
    --go-client /path/to/anytls-go-client \
    --server /path/to/anytls-go-server \
    --size-mb 128 --runs 3
```

`scripts/bench.py` creates its own CA, certificate, origin and server; nothing
outside the repository is modified.

## Results

### Throughput and CPU

| Client build | Binary | Throughput | Client CPU | CPU per GiB | CPU util. | RSS |
|---|---:|---:|---:|---:|---:|---:|
| direct, no proxy | – | 4 986 MB/s | – | – | – | – |
| Zig `ReleaseSmall`, baseline CPU | 372 168 B | 106.4 MB/s | 3.53 s | 9.41 s/GiB | 89% | 1 376 KB |
| Zig `ReleaseSmall`, `+aes+sha2` | 356 408 B | 159.5 MB/s | 2.27 s | 6.05 s/GiB | 86% | 1 336 KB |
| Zig `ReleaseFast`, `+aes+sha2` | 709 936 B | 376.4 MB/s | 0.70 s | 1.87 s/GiB | 63% | 1 672 KB |
| Go reference client | 9 255 470 B | 422.6 MB/s | 0.56 s | 1.49 s/GiB | 57% | 22 056 KB |

CPU is the client process only (`utime + stime`), measured around the three
128 MiB transfers; CPU per GiB is normalised to that total.

### Latency (2-byte responses, one keep-alive stream)

| Variant | mean | p50 | p95 |
|---|---:|---:|---:|
| direct | 0.089 ms | 0.083 ms | 0.119 ms |
| Zig `ReleaseSmall` baseline | 0.227 ms | 0.221 ms | 0.267 ms |
| Zig `ReleaseSmall` `+aes` | 0.211 ms | 0.205 ms | 0.252 ms |
| Zig `ReleaseFast` `+aes` | 0.226 ms | 0.189 ms | 0.364 ms |
| Go reference | 0.274 ms | 0.238 ms | 0.487 ms |

Cold connect (fresh client process, first request: TCP + TLS 1.3 handshake +
auth + stream open): **0.7–0.9 ms**. A pooled session adds only the SOCKS and
frame cost, which is why warm requests sit ~0.12–0.14 ms above direct.

## Analysis

* **`ReleaseSmall` is the throughput bottleneck.** Zig's GHASH implementation
  skips the 4-/8-block aggregated reduction paths in `ReleaseSmall` to save
  code. AES-GCM therefore costs ~9.4 s of CPU per GiB and caps one stream at
  ~106 MB/s. This is a size/speed trade-off inside the standard library, not an
  AnyTLS framing cost.
* **`+aes+sha2` helps but does not remove it.** The AES and PMULL paths are
  used (verified by disassembly), but GHASH still runs the compact schedule:
  1.5× faster, ~6.0 s/GiB.
* **`ReleaseFast` matches the Go client within ~10%** (376 vs 423 MB/s) while
  using 1.7 MB RSS instead of 22 MB. Latency is equal or slightly better.
* **A gigabit uplink needs the faster build.** 106 MB/s ≈ 850 Mbit/s, i.e.
  the `ReleaseSmall` baseline is marginal for 1 GbE. `+aes+sha2` at 160 MB/s or
  `ReleaseFast` at 376 MB/s leave headroom.
* **The proxy adds ~0.13 ms of request latency**, dominated by the extra
  loopback round trip and SOCKS handshake, not by framing.

## Caveats

* Loopback only: no WAN RTT, no packet loss, no Wi-Fi. Absolute numbers are not
  transferable; ratios are.
* The host is a 2-vCPU VM; origin and both endpoints share it.
* The MIPS/MT7621 target has **no AES instructions** and was not measured
  (no hardware). Expect software-crypto throughput well below the baseline
  numbers above. Test on the device with `scripts/bench.py --client ...` (the
  script itself only runs on the host, so use `iperf3`/`curl` on the router for
  an on-device figure).
* The Go client was built for this host (aarch64) with its runtime's CPU
  feature detection; that is the fairest comparison for an aarch64 OpenWrt
  target.
