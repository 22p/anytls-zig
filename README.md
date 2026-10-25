# anytls-zig

A small AnyTLS client in Zig for OpenWrt and embedded Linux. SOCKS5/HTTP in,
AnyTLS protocol v2 out, TLS 1.3, no Go/JVM/runtime, no garbage collector,
single statically linked ELF. Options come from CLI flags, a TOML file, or
UCI/LuCI on OpenWrt.

```
SOCKS5/HTTP client ──► stream (mux) ──► session ──► TLS 1.3 ──► AnyTLS server ──► target
```

[中文文档](README.zh-CN.md)

## Compatibility basis

The wire format follows the reference implementation
[`anytls/anytls-go`](https://github.com/anytls/anytls-go) at version
`anytls/0.0.13` (protocol version 2) and its `docs/protocol.md`:

| Item | Format |
|---|---|
| Auth | `sha256(password)` 32 B, padding0 length `u16 BE`, padding0 bytes |
| Frame | `cmd u8` + `streamId u32 BE` + `dataLen u16 BE` + data |
| Commands | `0 waste, 1 SYN, 2 PSH, 3 FIN, 4 Settings, 5 Alert, 6 UpdatePaddingScheme, 7 SYNACK, 8 HeartRequest, 9 HeartResponse, 10 ServerSettings` |
| Settings | `v=2\nclient=anytls-zig/0.1.0\npadding-md5=<md5 of scheme>` |
| Target | SOCKS5 address: `ATYP | addr | port BE` |
| Padding | Default scheme `stop=8 ...` byte-identical to the reference; `padding-md5` for the default scheme is `75cff2ad89aadf5e257059ee571ebe11` |

Implemented behaviour that matches the reference client:

* session multiplexing with idle-session reuse (newest session first, 30 s idle
  timeout, 5 warm sessions by default);
* padding packets 0–7, including split writes and `cmdWaste` fillers and the
  `c` check marker;
* `cmdSettings` is sent together with the first `SYN` and the target address in
  one TLS write (packet 1), exactly like the reference;
* `cmdSYNACK` errors close the stream, and a missing SYNACK on a v2 session
  closes the stuck session after 3 s;
* `cmdHeartRequest` is answered with `cmdHeartResponse`;
* `cmdUpdatePaddingScheme` updates the scheme used by **new** sessions
  (snapshot per session, as documented in the protocol);
* `cmdFIN` is sent on local write shutdown, and remote `FIN` produces EOF
  without an answer, as specified.

## TLS

TLS is provided by Zig's standard library (`std.crypto.tls.Client`), i.e. an
in-process TLS 1.3 implementation, not a C library:

* TLS 1.3 is negotiated with modern servers (verified: `tls_1_3`), TLS 1.2 is
  only offered as fallback;
* the server certificate chain is validated against a CA bundle and the
  hostname/SNI is verified (`CertificateHostMismatch` on mismatch);
* the CA bundle comes from `--ca` or the system paths
  (`/etc/ssl/certs/ca-certificates.crt`, …); on OpenWrt install `ca-bundle`;
* `--insecure` is the only way to disable verification and is logged as a
  warning.

wolfSSL and Mbed TLS were evaluated as alternatives. They need a separate C
build, add roughly 100–200 KB of code, and would still require the same
AnyTLS framing; Zig's client already performs full chain and hostname
verification, so a C TLS dependency would only add size and build fragility.
`src/tls.zig` is a narrow wrapper (dial/read/write/close), so swapping in
wolfSSL later is a contained change if a server ever needs a certificate
algorithm std does not support.

## Resource model

* Allocator: `std.heap.c_allocator` (musl malloc, thread safe); no GC.
* Per session: ~101 KB of heap (four 16 645-byte TLS buffers, a 20 KB
  frame/padding scratch and a 16 KB PSH read buffer). Sessions are pooled, not
  per request.
* Per stream: a 16 KB bounded ring buffer, with backpressure to the session
  reader (no unbounded buffering).
* Threads: one session reader (128 KB stack), one handler per local connection
  (512 KB, runs the TLS handshake and local→remote direction), one pump per
  stream (96 KB), one janitor (64 KB). Stacks are address-space reservations;
  RSS grows with actual use.
* Every allocation has one owner; streams use a reference count
  (creator + map + relay threads), sessions use a reference count
  (map + reader + streams) and the socket is closed only when the last
  reference is gone, so a late writer cannot hit a recycled descriptor.

## Build

Requires Zig **0.15.1**.

`zig build` defaults to a **static musl** binary for the host. This matches the
deployment target, and avoids Zig 0.15.1's native-glibc thread startup, which
panics on some hosts. Override with `-Dtarget=`/`-Dcpu=` as below.

Native (for testing):

```sh
zig build -Doptimize=Debug
./zig-out/bin/anytls-zig --help
```

Static cross-build:

```sh
zig build -Doptimize=ReleaseSmall -Dtarget=aarch64-linux-musl
zig build -Doptimize=ReleaseSmall -Dtarget=arm-linux-musleabihf -Dcpu=cortex_a7-neon
zig build -Doptimize=ReleaseSmall -Dtarget=mipsel-linux-musleabi -Dcpu=mips32r2

file zig-out/bin/anytls-zig
readelf -h -l zig-out/bin/anytls-zig   # no INTERP, no NEEDED
```

Notes:

* Pick the triple that matches the target ABI (`aarch64-linux-musl`,
  `arm-linux-musleabihf`, `mipsel-linux-musleabi`, …). A hard-float userspace
  needs `…eabihf`; a soft-float one needs `…eabi`. `-Dcpu` selects the baseline
  (`cortex_a7`, `mips32r2`, …) and can be omitted.
* The first build for a new target compiles musl from source and can take
  several minutes on a small host; later builds are cached.
* Equivalent direct command:
  `zig build-exe src/main.zig -lc -OReleaseSmall -target <triple> -fstrip`
* The 32-bit ARM build targets ARMv7-A with VFPv4 but without NEON
  (`-Dcpu=cortex_a7-neon`), so it runs on any ARMv7 hard-float target. It is
  packaged under both `arm_cortex-a7` and `arm_cortex-a7_neon-vfpv4`.
* CI publishes two builds per architecture — `ReleaseSmall` (no suffix) and
  `ReleaseFast` (`-fast`) — except x86-64, which ships only `ReleaseFast`.
  Sizes (Zig 0.15.2, stripped):

  | Architecture | `ReleaseSmall` | `ReleaseFast` |
  |---|---:|---:|
  | aarch64 (fast: `+aes+sha2`) | 372 KB | 712 KB |
  | armv7 | 581 KB | 997 KB |
  | mips / mipsel | 841 KB | 1.68 MB |
  | x86-64 (fast: `+aes+pclmul+avx`) | – | 788 KB |

  Use the small build on flash-constrained routers; under QEMU the fast build
  is roughly 1.2× (MIPS) to 1.5× (ARMv7) quicker, and on x86-64 it is about
  3× quicker than the small build. Measurements:
  [docs/bench-aarch64.md](docs/bench-aarch64.md).
* `scripts/make-apk.sh` wraps a built binary into an OpenWrt apk; the CI
  workflow builds apks for all targets.
* `scripts/make-luci-apk.sh` builds the arch-independent `luci-app-anytls-zig`
  apk, compiling `po/zh_Hans` into `.lmo` (byte-identical to LuCI's `po2lmo`).
* Both packaging scripts need apk-tools 3 (`apk mkpkg`): set
  `APK=/path/to/apk.static` or have `apk` in `PATH`. They produce ADB v3
  packages, the format used by OpenWrt snapshots and 25.x.

## Configuration

Options are resolved as **CLI > TOML file > built-in defaults**.

### TOML file

```sh
anytls-zig -c /etc/anytls-zig/config.toml
```

The format is a deliberately small TOML subset: comments, `[server]`,
`[listen]`, `[session]`, `[log]` tables, basic/literal strings, integers and
booleans. Unknown keys and type errors are rejected with a file:line message.
A complete example is [config/anytls-zig.toml](config/anytls-zig.toml):

```toml
[listen]
address = "127.0.0.1:1080"

[server]
address = "example.com:443"
sni = "example.com"
password = "your-password"
ca = "/etc/ssl/certs/ca-certificates.crt"
insecure = false
connect_timeout = 10

[session]
min_idle = 5
idle_timeout = 30
max_streams = 128
half_close_wait = 3

[log]
level = "info"
```

### Command line

```
anytls-zig -l 127.0.0.1:1080 \
           -s example.com:443 \
           --sni example.com \
           -p 'your-password' \
           --ca /etc/ssl/certs/ca-certificates.crt
```

or a URI:

```
anytls-zig -s 'anytls://password@example.com:443?sni=example.com'
```

Options: `-l/--listen`, `-s/--server`, `-p/--password`, `--sni`, `--ca`,
`--insecure`, `-m/--min-idle`,
`--idle-timeout`, `--connect-timeout`, `--max-streams`, `--half-close-wait`,
`--log-level`, `-V`, `-h`.

The password is hashed with SHA-256 at startup and only the hash is kept. It is
never logged. `ANYTLS_PASSWORD` keeps it out of the process arguments; when the
password comes from the TOML or UCI file, keep that file readable by root only.

## OpenWrt deployment

1. Install the client, either as a package built by CI:

```sh
apk add --allow-untrusted anytls-zig_<version>_<arch>.apk
```

   `<arch>` is the value of `cat /etc/apk/arch` (for example `arm_cortex-a7`,
   `arm_cortex-a7_neon-vfpv4`, `mipsel_24kc`). Note that `apk --print-arch` can
   print the binary's built-in default and differ from `/etc/apk/arch`; the
   file is authoritative for package selection.

   For the web UI install the arch-independent LuCI package as well:

```sh
apk add --allow-untrusted luci-app-anytls-zig_<version>_noarch.apk
```

   Both are ADB v3 packages for apk-tools 3 (OpenWrt snapshots / 25.x).
   OpenWrt 24.10 and older use opkg; there, install the binary directly or
   build an .ipk with the OpenWrt SDK from `openwrt/` and `openwrt/luci/`.
   The packages are unsigned: sign them with the key trusted by the image, or
   use `--allow-untrusted`. Alternatively copy `zig-out/bin/anytls-zig` to
   `/usr/bin/anytls-zig` and the files from `openwrt/files/` into place.

2. Install the CA bundle: `opkg install ca-bundle` (or `apk add ca-bundle`).
3. Set the password and protect the file:

```sh
uci set anytls-zig.main.password='your-password'
uci commit anytls-zig
chmod 600 /etc/config/anytls-zig
```

4. Start the service:

```sh
/etc/init.d/anytls-zig enable
/etc/init.d/anytls-zig start
logread -e anytls-zig
```

5. Point LAN clients at `192.168.1.1:1080` (SOCKS5 or HTTP proxy), or use it as
   an upstream for a transparent-proxy tool. The default `127.0.0.1:1080` is
   loopback only.

The package Makefile in `openwrt/` expects the repository to be placed at
`package/anytls-zig/` and `ZIG=/path/to/zig`; Zig is not part of the OpenWrt
buildroot, so the compiler must be supplied by the build host. Set
`ZIG_TARGET`/`ZIG_CPU` for the target (see the comment at the top of the
Makefile).

### LuCI

`openwrt/luci/luci-app-anytls-zig/` is a LuCI application for the UCI config
above:

* place it at `feeds/luci/applications/luci-app-anytls-zig/` (or
  `package/luci-app-anytls-zig/` and adjust the `luci.mk` include),
* select `luci-app-anytls-zig` in `make menuconfig` (depends on `anytls-zig`),
* the page appears under **Services → AnyTLS Zig** in English and Simplified
  Chinese (LuCI language code `zh-cn`, translated from `po/zh_Hans`).

CI builds this as `luci-app-anytls-zig_<version>_noarch.apk`; the translation is
compiled to `/usr/lib/lua/luci/i18n/anytls-zig.zh-cn.lmo` at package time, so no
extra i18n package is needed. LuCI finds catalogs by the runtime language code
(`zh-cn`), which is why the file is not named `zh_Hans.lmo`.

The form covers the listen address, server/SNI, password, CA bundle,
verification switch, timeouts, pool sizes, stream limit, PAC options and log
level. The password is stored in `/etc/config/anytls-zig`; keep that file mode
600. `scripts/check-luci-i18n.py` verifies that every UI string has a
translation.

### PAC file

Enable `pac_enabled` and the service generates `/www/anytls-zig.pac`, served by
uhttpd at `http://<LAN-IP>/anytls-zig.pac`. The proxy line is built from the LAN
address and the proxy port in `listen`; set `listen` to `0.0.0.0:1080` so LAN
clients can reach it (a concrete listen host is used verbatim). The URL is also
written to `/tmp/anytls-zig.pac.url`.

Local/private hosts and the domains in
`/usr/share/anytls-zig/china-domains.txt` go DIRECT (a curated list of common
Chinese sites, editable), plus anything in the `pac_bypass` list; everything
else uses the proxy (SOCKS5 first, then HTTP) with a DIRECT fallback. The file
is regenerated on service start/reload.

```sh
uci set anytls-zig.main.listen='0.0.0.0:1080'
uci set anytls-zig.main.pac_enabled='1'
uci add_list anytls-zig.main.pac_bypass='example.cn'
uci commit anytls-zig
/etc/init.d/anytls-zig restart
```

The built-in list is a sample rather than a complete China list; one suffix per
line. Edits to the installed file may be overwritten by package upgrades, so put
permanent additions in `pac_bypass`.

The PAC URL is shown in LuCI (built from the address you opened LuCI with). If
it returns 404, check that the service is running (`logread -e anytls-zig`) and
that `/www/anytls-zig.pac` exists; the generator lives at
`/usr/libexec/anytls-zig/pac`. Note that v0.1.4 apks accidentally omitted the
generator and the domain list; make sure the installed package ships both files.

## Size

Measured on the 32-bit MIPS build (`mipsel-linux-musleabi`, `-mcpu=mips32r2`),
static musl, `strip` enabled:

| Build | ELF size |
|---|---|
| Debug, symbols kept | 7 897 848 B |
| Debug, stripped | 3 674 932 B |
| ReleaseSafe, stripped | 1 580 324 B |
| ReleaseFast, stripped | 1 688 276 B |
| **ReleaseSmall, stripped, no unwind tables** | **844 492 B** |
| ReleaseSmall, aarch64-linux-musl (for reference) | 372 168 B |
| ReleaseSmall, aarch64 + `aes+sha2` | 356 408 B |
| ReleaseSmall, armv7 hard-float (`arm-linux-musleabihf`, `cortex_a7`) | 516 580 B |

That binary is `ELF32 LSB, MIPS32r2, o32, soft-float, static`, with no
`INTERP` and no dynamic section. Section split: `.text` 749 556 B, `.rodata`
50 644 B, `.pdr` 42 720 B (kept so panic traces remain readable on MIPS;
non-allocated), `.bss` 5 KB. `-fno-unwind-tables` saves ~25 KB; `ReleaseSmall`
is roughly half the size of `ReleaseSafe`/`ReleaseFast`.

Runtime memory (aarch64 release build, measured via `/proc/<pid>/status`):
420 KB RSS idle with two threads; ~2.9 MB RSS with 10 concurrent sessions and
10 active streams (≈240 KB per connection, mostly TLS buffers and thread
stacks); back to ~500 KB after the streams close and idle sessions expire.
`bss` is only 5 KB because per-session buffers are allocated on demand.

## Tests performed

All tests used the reference server `anytls-go 0.0.13` (built from source) with
a locally generated CA and a `localhost` certificate, and a local HTTP origin.

| Test | Result |
|---|---|
| Unit tests: frame codec, SOCKS address encoding, UDP/UoT framing, HTTP request parsing/rewrite, default scheme MD5 (`75cff2ad…`), padding parsing/size generation, settings, bounded pipe, TOML parser, option precedence, shipped example config | 21/21 pass |
| TOML config end-to-end: config-only startup, CLI override, password in TOML, duplicate key/unknown key/type/table diagnostics | pass |
| LuCI catalog coverage (`scripts/check-luci-i18n.py`) | 37/37 strings translated |
| TLS 1.3 + chain + SNI | `tls_1_3` negotiated; `CertificateHostMismatch` with wrong SNI |
| SOCKS5 CONNECT, IPv4 target | 200 / correct body |
| HTTP CONNECT tunnel | 200 / correct body |
| Plain HTTP (absolute-form) via the proxy | 200 / correct body |
| SOCKS5 UDP ASSOCIATE (UoT v2): DNS via `1.1.1.1:53`, 16 KiB echo, two destinations on one association | correct responses, 16 KiB payload intact, oversized datagrams dropped without killing the association |
| Domain target (resolved by server) | 200 / correct body |
| 10 MB transfer | SHA-256 identical to source |
| 8 concurrent requests | all bodies identical, multiplexed on one session (streams 2–8) |
| 45 s keep-alive on one stream with 2 s idle timeout | 9/9 responses, session not reaped while active |
| Thread/stream cleanup after clients disconnect | 18 → 2 threads, RSS 1.0 MB → 492 KB after idle expiry |
| Session reuse / idle pool | 3 requests → 1 session; idle session closed after timeout |
| Wrong password | fails fast (server closes), client stays up |
| Server killed mid-life, then restarted | first request fails cleanly, next request reconnects |
| Connect timeout to blackhole (`--connect-timeout 2`) | fails in 2.0 s |
| Half-close (client `shutdown(WR)` after upload) | bounded teardown after grace; same result as the reference Go client |
| Duplicate instance on same port | `AddressInUse` (no silent SO_REUSEPORT sharing) |
| Credential leakage in logs | password absent from all logs |
| Cross-compile `mipsel-linux-musleabi` / `mips-linux-musleabi` / `arm-linux-musleabihf` / `aarch64-linux-musl` / `x86_64-linux-musl` | ELF32 LSB/MSB MIPS32r2 o32 soft-float, ARM EABI5 hard-float, ELF64 aarch64/x86-64; all static with no dynamic section |
| OpenWrt apk (`scripts/make-apk.sh`) | ADB v3; installed with apk-tools 3.0.8 into a chroot, correct modes/dependency, 7 build variants / 8 packages |
| LuCI apk (`scripts/make-luci-apk.sh`) | ADB v3, `noarch`, installs with `luci-base` + `anytls-zig`; `.lmo` byte-identical to LuCI `po2lmo` |
| aarch64 throughput / latency / CPU / RSS | [docs/bench-aarch64.md](docs/bench-aarch64.md): 106–376 MB/s, 0.21–0.23 ms, 1.3–1.7 MB RSS |

**Not executed:** running the cross-built binaries on real router hardware, or
under QEMU. No device or user-mode QEMU was available in the test environment,
so runtime behaviour on the target architectures is unverified; only the
ELF/ABI properties and the host-architecture code paths were exercised. Perform
a smoke test on the device (`/etc/init.d/anytls-zig start`, `curl --socks5 …`)
before rollout.

## Known limitations / deliberate scopes

* Mixed inbound: SOCKS5 (CONNECT + UDP ASSOCIATE) and an HTTP proxy (CONNECT
  tunnels and plain absolute-form requests) share the listen port; the protocol
  is chosen per connection from the first byte. SOCKS4 is not supported. UDP is
  tunnelled with sing-box udp-over-tcp v2 (`sp.v2.udp-over-tcp.arpa`), so the
  server must support UoT (anytls-go 0.0.13 does). Datagrams above 16 KiB are
  dropped locally: the reference UoT reader uses a 16 KiB buffer. Plain HTTP
  keep-alive reuses the first request's target for later requests on the same
  connection.
* The TOML reader supports a small subset (no arrays, inline tables, multiline
  strings or dotted keys) and rejects unknown keys rather than ignoring them.
* LuCI edits UCI only; the TOML file is a separate mechanism for CLI/systemd
  style deployments and is not managed by the web UI.
* No `--disable-reuse`; sessions are always multiplexed and pooled.
* Padding scheme limits: 16 packets, 16 entries per packet, 4 KB scheme text,
  padding frames clamped to 4 KB. Larger server schemes keep working but their
  largest padding sizes are clamped (traffic shape only, never framing).
* A session uses one `paddingScheme` snapshot for its lifetime; updates apply
  to new sessions as the protocol document specifies.
* Half-closed connections wait `--half-close-wait` seconds (default 3) for the
  peer's FIN. anytls-go closes the stream without sending FIN, so waiting
  forever would leak connections; the value trades a bounded linger against
  targets that answer slowly after the client's EOF.
* `cmdSYNACK` failure closes only the affected stream; a SYNACK timeout closes
  the session (as the reference does).
