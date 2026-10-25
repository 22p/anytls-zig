//! anytls-zig: minimal AnyTLS (protocol v2) client for OpenWrt / MIPS.
//! Mixed SOCKS5 + HTTP inbound -> AnyTLS stream -> TLS 1.3 -> remote server.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const anytls = @import("anytls.zig");
const inbound = @import("inbound.zig");
const proto = @import("protocol.zig");
const config = @import("config.zig");
const toml = @import("toml.zig");
const log = @import("log.zig");

const version = "0.1.9";

var stop_flag = std.atomic.Value(bool).init(false);

fn onSignal(_: c_int) callconv(.c) void {
    stop_flag.store(true, .release);
}

fn installSignalHandlers() void {
    var act: posix.Sigaction = std.mem.zeroes(posix.Sigaction);
    act.handler = .{ .handler = onSignal };
    act.flags = 0;
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);

    var ign: posix.Sigaction = std.mem.zeroes(posix.Sigaction);
    ign.handler = .{ .handler = posix.SIG.IGN };
    ign.flags = 0;
    posix.sigaction(posix.SIG.PIPE, &ign, null);
}

const usage =
    \\anytls-zig {s} - AnyTLS (protocol v2) client
    \\
    \\Usage: anytls-zig -s <host:port> -p <password> [options]
    \\       anytls-zig -c /etc/anytls-zig/config.toml [options]
    \\       anytls-zig -s 'anytls://password@host:port?sni=example.com' [options]
    \\
    \\  -l, --listen <addr:port>   mixed SOCKS5/HTTP listen address (default 127.0.0.1:1080)
    \\  -s, --server <host:port>   AnyTLS server, optionally an anytls:// URI
    \\  -c, --config <file>        read options from a TOML file (CLI wins)
    \\  -p, --password <pw>        password (or ANYTLS_PASSWORD to keep it out of argv)
    \\      --sni <name>           TLS server name (default: server host)
    \\      --ca <path>            CA bundle (default: system bundle)
    \\      --insecure             disable certificate and hostname verification
    \\  -m, --min-idle <n>         idle sessions to keep warm (default 5)
    \\      --idle-timeout <sec>   idle session timeout (default 30)
    \\      --connect-timeout <s>  connect + TLS handshake timeout (default 10)
    \\      --max-streams <n>      concurrent streams per session (default 128)
    \\      --half-close-wait <s>  grace after local FIN before teardown (default 3)
    \\      --log-level <level>    error|warn|info|debug (default info)
    \\  -V, --version
    \\  -h, --help
    \\
;

fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    std.process.exit(1);
}

fn fatalConfig(path: []const u8, diag: *const toml.Diag, err: anyerror) noreturn {
    if (diag.line > 0 and diag.key.len > 0) {
        log.err("{s}:{d}: {s} ({s})", .{ path, diag.line, diag.msg, diag.key });
    } else if (diag.line > 0) {
        log.err("{s}:{d}: {s}", .{ path, diag.line, diag.msg });
    } else if (diag.key.len > 0) {
        log.err("{s}: {s} ({s})", .{ path, diag.msg, diag.key });
    } else {
        log.err("{s}: {s}", .{ path, if (diag.msg.len > 0) diag.msg else @errorName(err) });
    }
    std.process.exit(1);
}

pub fn main() void {
    const alloc = std.heap.c_allocator;
    installSignalHandlers();

    const argv = std.process.argsAlloc(alloc) catch fatal("cannot read arguments", .{});

    var cli: config.Overrides = .{};
    var config_path: ?[]const u8 = null;
    parseArgs(argv, &cli, &config_path) catch |e| switch (e) {
        error.Help => {
            std.debug.print(usage, .{version});
            return;
        },
        error.Version => {
            std.debug.print("anytls-zig {s}\n", .{version});
            return;
        },
        else => fatal("invalid arguments (try --help): {s}", .{@errorName(e)}),
    };

    var from_file: config.Overrides = .{};
    if (config_path) |path| {
        const text = std.fs.cwd().readFileAlloc(alloc, path, 256 * 1024) catch |e|
            fatal("cannot read config {s}: {s}", .{ path, @errorName(e) });
        var diag: toml.Diag = .{};
        // The table's arena is intentionally kept for the process lifetime:
        // option strings point into it and the config is read once.
        const table = toml.parse(alloc, text, &diag) catch |e| fatalConfig(path, &diag, e);
        from_file = config.overridesFromTable(&table, &diag) catch |e| fatalConfig(path, &diag, e);
    }

    const cfg = config.merge(cli, from_file);
    log.setLevel(cfg.level);

    if (cfg.server.len == 0) fatal("missing server address (-s/--server or [server] address)", .{});
    const hp = proto.splitHostPort(cfg.server, 443) catch fatal("bad server address: {s}", .{cfg.server});

    var pw: []const u8 = undefined;
    switch (cfg.password) {
        .none => pw = std.process.getEnvVarOwned(alloc, "ANYTLS_PASSWORD") catch
            fatal("missing password (-p, [server] password or ANYTLS_PASSWORD)", .{}),
        .literal => |p| pw = p,
    }
    if (pw.len == 0) fatal("empty password", .{});
    if (pw.len > 4096) fatal("password too long", .{});

    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(pw, &hash, .{});
    // Best-effort scrub of our copy (argv itself remains visible in /proc).
    @memset(@constCast(pw), 0);

    const sni = cfg.sni orelse hp.host;

    var bundle: ?*std.crypto.Certificate.Bundle = null;
    if (!cfg.insecure) {
        const b = alloc.create(std.crypto.Certificate.Bundle) catch fatal("out of memory", .{});
        b.* = .{};
        if (cfg.ca) |p| {
            loadCa(alloc, b, p) catch fatal("cannot load CA bundle: {s}", .{p});
        } else {
            const defaults = [_][]const u8{
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/ssl/cert.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            };
            var loaded = false;
            for (defaults) |p| {
                if (loadCa(alloc, b, p)) |_| {
                    loaded = true;
                    break;
                } else |_| {}
            }
            if (!loaded or b.map.count() == 0) {
                fatal("no system CA bundle found (install ca-bundle or use --ca)", .{});
            }
        }
        bundle = b;
    } else {
        log.warn("TLS verification disabled (--insecure); do not use in production", .{});
    }

    const listen_hp = proto.splitHostPort(cfg.listen, 1080) catch fatal("bad listen address: {s}", .{cfg.listen});
    const listen_addr = resolveOne(alloc, listen_hp.host, listen_hp.port) catch
        fatal("cannot resolve listen address: {s}", .{cfg.listen});
    const listen_fd = makeListener(listen_addr, 128) catch |e|
        fatal("cannot listen on {s}: {s}", .{ cfg.listen, @errorName(e) });
    defer posix.close(listen_fd);

    const client = anytls.Client.init(alloc, .{
        .host = hp.host,
        .port = hp.port,
        .sni = sni,
        .password_sha256 = hash,
        .ca = bundle,
        .insecure = cfg.insecure,
        .connect_timeout_ms = cfg.connect_timeout_s * 1000,
        .idle_timeout_ms = cfg.idle_timeout_s * 1000,
        .min_idle = cfg.min_idle,
        .max_streams_per_session = cfg.max_streams,
    }) catch |e| fatal("client init failed: {s}", .{@errorName(e)});

    log.info("anytls-zig {s} (protocol v2, TLS 1.3)", .{version});
    log.info("socks5/http {s} -> {s}:{d} sni={s} verify={s}", .{
        cfg.listen,
        hp.host,
        hp.port,
        sni,
        if (cfg.insecure) "off" else "on",
    });

    while (!stop_flag.load(.acquire)) {
        var fds = [_]posix.pollfd{.{
            .fd = listen_fd,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        _ = posix.poll(&fds, 500) catch |e| fatal("poll failed: {s}", .{@errorName(e)});
        if (fds[0].revents == 0) continue;

        const fd = posix.accept(listen_fd, null, null, posix.SOCK.CLOEXEC) catch |e| {
            if (stop_flag.load(.acquire)) break;
            log.warn("accept failed: {s}", .{@errorName(e)});
            continue;
        };
        log.debug("accepted connection", .{});
        const t = std.Thread.spawn(
            .{ .stack_size = 512 * 1024 },
            inbound.handle,
            .{ client, fd, cfg.half_close_wait_s * std.time.ns_per_s },
        ) catch |e| {
            log.err("cannot spawn connection thread: {s}", .{@errorName(e)});
            posix.close(fd);
            continue;
        };
        t.detach();
    }

    log.info("shutting down", .{});
    client.deinit();
}

fn makeListener(addr: net.Address, backlog: u31) !posix.socket_t {
    const fd = try posix.socket(
        addr.any.family,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        posix.IPPROTO.TCP,
    );
    errdefer posix.close(fd);
    // SO_REUSEADDR only: SO_REUSEPORT would let a second instance silently
    // share the proxy port instead of failing to bind.
    const one: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};
    try posix.bind(fd, &addr.any, addr.getOsSockLen());
    try posix.listen(fd, backlog);
    return fd;
}

fn loadCa(alloc: std.mem.Allocator, bundle: *std.crypto.Certificate.Bundle, path: []const u8) !void {
    var abs_buf: [std.fs.max_path_bytes]u8 = undefined;
    const abs = std.fs.cwd().realpath(path, &abs_buf) catch return error.FileNotFound;
    try bundle.addCertsFromFilePathAbsolute(alloc, abs);
}

fn resolveOne(alloc: std.mem.Allocator, host: []const u8, port: u16) !net.Address {
    if (host.len == 0 or std.mem.eql(u8, host, "*")) {
        return net.Address.parseIp("0.0.0.0", port);
    }
    if (net.Address.parseIp(host, port)) |a| return a else |_| {}
    const list = try net.getAddressList(alloc, host, port);
    defer list.deinit();
    if (list.addrs.len == 0) return error.UnknownHostName;
    return list.addrs[0];
}

fn parseArgs(
    argv: []const []const u8,
    out: *config.Overrides,
    config_path: *?[]const u8,
) !void {
    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        var name = argv[i];
        var inline_val: ?[]const u8 = null;
        if (std.mem.startsWith(u8, name, "--")) {
            if (std.mem.indexOfScalar(u8, name, '=')) |eqpos| {
                inline_val = name[eqpos + 1 ..];
                name = name[0..eqpos];
            }
        } else if (std.mem.startsWith(u8, name, "-") and name.len > 2 and name[2] == '=') {
            inline_val = name[3..];
            name = name[0..2];
        }

        if (strEq(name, "-h") or strEq(name, "--help")) return error.Help;
        if (strEq(name, "-V") or strEq(name, "--version")) return error.Version;
        if (strEq(name, "--insecure")) {
            out.insecure = true;
            continue;
        }

        const value = inline_val orelse blk: {
            i += 1;
            if (i >= argv.len) return error.MissingValue;
            break :blk argv[i];
        };

        if (strEq(name, "-l") or strEq(name, "--listen")) {
            out.listen = value;
        } else if (strEq(name, "-s") or strEq(name, "--server")) {
            out.server = value;
        } else if (strEq(name, "-c") or strEq(name, "--config")) {
            config_path.* = value;
        } else if (strEq(name, "-p") or strEq(name, "--password")) {
            out.password = value;
        } else if (strEq(name, "--sni")) {
            out.sni = value;
        } else if (strEq(name, "--ca")) {
            out.ca = value;
        } else if (strEq(name, "-m") or strEq(name, "--min-idle")) {
            out.min_idle = @min(try std.fmt.parseInt(usize, value, 10), 64);
        } else if (strEq(name, "--idle-timeout")) {
            out.idle_timeout_s = std.math.clamp(try std.fmt.parseInt(i64, value, 10), 5, 86_400);
        } else if (strEq(name, "--connect-timeout")) {
            out.connect_timeout_s = std.math.clamp(try std.fmt.parseInt(u32, value, 10), 1, 300);
        } else if (strEq(name, "--max-streams")) {
            out.max_streams = std.math.clamp(try std.fmt.parseInt(usize, value, 10), 1, 4096);
        } else if (strEq(name, "--half-close-wait")) {
            out.half_close_wait_s = @min(try std.fmt.parseInt(u64, value, 10), 3600);
        } else if (strEq(name, "--log-level")) {
            out.level = log.Level.parse(value) orelse return error.BadLogLevel;
        } else {
            return error.UnknownOption;
        }
    }

    if (out.server) |srv| {
        if (std.mem.startsWith(u8, srv, "anytls://")) try parseUri(srv, out);
    }
}

/// anytls://password@host:port?sni=name
fn parseUri(uri: []const u8, out: *config.Overrides) !void {
    const body = uri["anytls://".len..];

    var query: []const u8 = "";
    var authority = body;
    if (std.mem.indexOfScalar(u8, body, '?')) |q| {
        authority = body[0..q];
        query = body[q + 1 ..];
    }
    if (std.mem.indexOfScalar(u8, authority, '#')) |h| authority = authority[0..h];

    if (std.mem.lastIndexOfScalar(u8, authority, '@')) |at| {
        const userinfo = authority[0..at];
        out.password = try percentDecode(std.heap.c_allocator, userinfo);
        out.server = authority[at + 1 ..];
    }

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "sni=")) {
            out.sni = try percentDecode(std.heap.c_allocator, kv["sni=".len..]);
        }
    }
}

fn percentDecode(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    var out = try alloc.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                out[n] = s[i];
                n += 1;
                i += 1;
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                out[n] = s[i];
                n += 1;
                i += 1;
                continue;
            };
            out[n] = (hi << 4) | lo;
            n += 1;
            i += 3;
        } else {
            out[n] = s[i];
            n += 1;
            i += 1;
        }
    }
    return out[0..n];
}

fn strEq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
