# x86-64 performance

Three x86-64 builds are compared, mirroring the aarch64 matrix: `ReleaseSmall`
(generic), `ReleaseSmall` with hardware crypto enabled, and `ReleaseFast` with
hardware crypto enabled.

Loopback measurements of the Zig client and the reference Go client, both
talking to an `anytls-go 0.0.13` server. The point is to quantify the client's
cost (CPU, latency, memory) and the `ReleaseSmall` size/speed trade-off, not to
predict WAN throughput.

These numbers are from the Zig **0.17.0** port (see *Toolchain comparison* for
what changed against 0.15.1). CI ships both `ReleaseSmall` and `ReleaseFast`
for aarch64/armv7/MIPS and only `ReleaseFast` for x86-64, built with
`-Dcpu=baseline+aes+pclmul+avx` (AES-NI + PCLMULQDQ + AVX, i.e. 2011 or newer);
the other two rows are kept here as measurement history.

## Environment

| Item | Value |
|---|---|
| Host | x86-64 Linux (AMD Ryzen 9 5900HX), 8 cores / 16 threads, kernel 7.2.7 |
| Crypto extensions | `aes`, `pclmulqdq`, `avx`, `avx2`, `vaes`, `vpclmulqdq`, `sha_ni` |
| Zig | 0.17.0 (native x86_64 toolchain) |
| Server | anytls-go 0.0.13, TLS 1.3, RSA-2048 certificate from a local CA |
| Reference client | anytls-go 0.0.13 client (Go 1.26.10) |
| Origin | Python threaded HTTP server on loopback, 128 MiB body |
| Runs | 3, best throughput; 300 keep-alive requests for latency |
| Date | 2026-10-24 |

Reproduce:

```sh
zig build -Doptimize=small -Dtarget=x86_64-linux-musl \
    -Dcpu=baseline+aes+pclmul+avx
python3 scripts/bench.py \
    --client zig-out/bin/anytls-zig \
    --go-client /path/to/anytls-go-client \
    --server /path/to/anytls-go-server \
    --size-mb 128 --runs 3
```

The CPU flag matters: Zig's standard library selects AES-NI only when both
`aes` **and** `avx` are enabled, and the PCLMULQDQ GHASH path only when both
`pclmul` **and** `avx` are enabled. `-Dcpu=baseline+aes+pclmul+sha` — the
literal translation of the aarch64 `+aes+sha2` flag, since x86 spells SHA-NI
`sha` — builds a binary byte-identical to the baseline one, so `+avx` is what
actually turns the hardware paths on. `vaesenc`/`pclmul` are present in both
hardware-crypto builds (checked with `objdump -d`).

`scripts/bench.py` creates its own CA, certificate, origin and server; nothing
outside the repository is modified. The stock 0.0.13 server ignores
`TLS_CERT`/`TLS_KEY` and serves an ephemeral empty-CN certificate, which a
verifying client rejects; the server used here is 0.0.13 with a small local
patch that loads the generated CA certificate from those variables, so
certificate and hostname verification stay enabled. No protocol code differs.

## Results

### Throughput and CPU

| Client build | Binary | Throughput | Client CPU | CPU per GiB | CPU util. | RSS |
|---|---:|---:|---:|---:|---:|---:|
| direct, no proxy | – | 2 204 MB/s | – | – | – | – |
| Zig `ReleaseSmall`, baseline CPU | 540 736 B | 168.9 MB/s | 2.57 s | 6.85 s/GiB | 106% | 1 756 KB |
| Zig `ReleaseSmall`, `+aes+pclmul+avx` | 517 160 B | 194.6 MB/s | 2.25 s | 6.00 s/GiB | 106% | 1 776 KB |
| Zig `ReleaseFast`, `+aes+pclmul+avx` | 1 003 288 B | 702.5 MB/s | 0.68 s | 1.81 s/GiB | 108% | 2 224 KB |
| Go reference client | 9 860 753 B | 824.5 MB/s | 0.84 s | 2.24 s/GiB | 155% | 11 572 KB |

CPU is the client process only (`utime + stime`), measured around the three
128 MiB transfers; CPU per GiB is normalised to that total. Both clients run
helper threads, so utilisation above 100% is expected.

### Latency (2-byte responses, one keep-alive stream)

| Variant | mean | p50 | p95 |
|---|---:|---:|---:|
| direct | 0.061 ms | 0.058 ms | 0.078 ms |
| Zig `ReleaseSmall` baseline | 0.195 ms | 0.197 ms | 0.261 ms |
| Zig `ReleaseSmall` `+aes` | 0.177 ms | 0.153 ms | 0.235 ms |
| Zig `ReleaseFast` `+aes` | 0.163 ms | 0.161 ms | 0.202 ms |
| Go reference | 0.155 ms | 0.150 ms | 0.184 ms |

Cold connect (fresh client process, first request: TCP + TLS 1.3 handshake +
auth + stream open): **0.9 ms**. A pooled session adds only the SOCKS and frame
cost.

## Analysis

* **`ReleaseFast` is at parity with the 0.15.1 build** and is slightly faster
  than the Go client in throughput per core: 702 MB/s at 1.81 s of CPU per GiB
  versus 824 MB/s at 2.24 s/GiB for Go (the Go number includes its runtime
  threads). Zig uses 2.2 MB RSS against 11.6 MB.
* **`ReleaseSmall` lost most of its hardware-crypto gain in 0.17.** The
  `+aes+pclmul+avx` build reaches only 195 MB/s (6.0 s/GiB), versus 409 MB/s
  (3.4 s/GiB) with 0.15.1 on the same machine. `ReleaseSafe` with the same CPU
  features measures 579 MB/s / 1.81 s/GiB, so the AES and PCLMULQDQ
  instructions are still emitted — the regression is in `ReleaseSmall`
  code generation for the crypto path, not a missing CPU feature.
  A standalone AES-128-GCM benchmark (128 MiB in 16 KiB records, same CPU
  flags) isolates it to Zig's standard library:

  | AES-GCM mode | 0.15.1 | 0.17.0 |
  |---|---:|---:|
  | `ReleaseSmall` | 689 MB/s | 254 MB/s |
  | `ReleaseSafe` | 1 184 MB/s | 728 MB/s |
  | `ReleaseFast` | 1 379 MB/s | 794 MB/s |

  The source of `std/crypto/ghash_polyval.zig` and `aes/aesni.zig` is
  effectively unchanged between the releases, so this is an LLVM/optimizer
  regression rather than an application change. There is no per-module
  optimisation switch in Zig, so the workaround is to build with
  `ReleaseFast`; that is what CI publishes.
* **The generic `ReleaseSmall` build is ~20% slower than 0.15.1** (169 vs
  217 MB/s), which is the same size/speed trade-off, just moved further toward
  size.
* **Latency is unchanged**: warm requests cost ~0.10–0.14 ms over direct;
  TLS/auth/stream setup is under 1 ms.
* **For x86-64 on 0.17, use `ReleaseFast`.** `ReleaseSmall` is only worth it
  when binary size dominates and ~170 MB/s (~1.4 Gbit/s) is enough; the
  `ReleaseSmall` `+aes` build is no longer a useful middle ground.

## Toolchain comparison (0.15.1 → 0.17.0)

Throughput normalised to the Go client measured in the *same* session, which
cancels most of the host's run-to-run variance:

| Build | 0.15.1 (Zig / Go) | 0.17.0 (Zig / Go) |
|---|---:|---:|
| `ReleaseSmall`, baseline CPU | 0.26 (217 / 821 MB/s) | 0.21 (169 / 796 MB/s) |
| `ReleaseSmall`, `+aes` | 0.46 (380 / 822 MB/s) | 0.24 (195 / 808 MB/s) |
| `ReleaseFast`, `+aes` | 0.85–0.96 (676–749 / 782–792 MB/s) | 0.85 (702 / 824 MB/s) |

## Porting notes (0.17.0)

* Sockets moved to `std.Io`: the SOCKS side uses `std.Io.net.Stream` and the
  new `std.Io.Reader`/`Writer`, and every lock/condition is an `std.Io.Mutex`
  or `std.Io.Condition`, so the `Io` handle is threaded through the client.
* `std.posix` no longer exposes `socket`/`bind`/`listen`/`accept`, and
  `IpAddress.listen` always sets SO_REUSEPORT (a second instance would silently
  share the port). The listener therefore goes through libc directly and keeps
  SO_REUSEADDR only.
* `std.Io.net`'s threaded backend does not implement connect with a timeout
  (`netConnectIpPosix` is a TODO), so the TLS dial uses a raw socket with
  SO_SNDTIMEO and wraps the descriptor in an `Io.net.Stream`. Connect timeout
  behaviour is unchanged (`--connect-timeout 2` fails in 2.0 s).
* `std.Io.net.Stream.read` does not compile on 0.17.0 (it destructures a
  struct), so the relay issues the `net_read` operation directly.

## Caveats

* Loopback only: no WAN RTT, no packet loss, no Wi-Fi. Absolute numbers are not
  transferable; ratios are.
* The host is a desktop-class 8-core/16-thread CPU, not a router SoC; origin
  and both endpoints share it. `direct` throughput drifted between 1.6 and
  3.1 GB/s across sessions, which is why the toolchain comparison is
  normalised against Go.
* Throughput is best-of-3 within a session, and two sessions were run per
  build. Treat differences under ~10% as noise.
* The Go client was built for this host with Go 1.26.10 and its runtime's CPU
  feature detection; that is the fairest comparison for an x86-64 target.
* The MIPS/MT7621 target has **no AES instructions** and was not measured (no
  hardware); the software-AES baseline above is the closest available proxy,
  but different cores will be slower.
