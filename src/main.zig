//! anytls-zig: minimal AnyTLS (protocol v2) client for OpenWrt / MIPS.
//! SOCKS5 inbound -> AnyTLS stream -> TLS 1.3 -> remote server.

const std = @import("std");
const posix = std.posix;
const IpAddress = std.Io.net.IpAddress;
const sockaddr = @import("sockaddr.zig");
const anytls = @import("anytls.zig");
const socks5 = @import("socks5.zig");
const config = @import("config.zig");
const toml = @import("toml.zig");
const log = @import("log.zig");

const version = "0.1.0";

var stop_flag = std.atomic.Value(bool).init(false);

fn onSignal(_: posix.SIG) callconv(.c) void {
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
    \\  -l, --listen <addr:port>   SOCKS5 listen address (default 127.0.0.1:1080)
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

pub fn main(init: std.process.Init) void {
    const alloc = std.heap.c_allocator;
    const io = init.io;
    installSignalHandlers();

    var argv_buf: [64][]const u8 = undefined;
    var argc: usize = 0;
    var arg_it = init.minimal.args.iterate();
    while (arg_it.next()) |arg| {
        if (argc == argv_buf.len) break;
        argv_buf[argc] = arg;
        argc += 1;
    }
    const argv = argv_buf[0..argc];

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
        const text = std.Io.Dir.cwd().readFileAlloc(io, path, alloc, .limited(256 * 1024)) catch |e|
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
    const hp = splitHostPort(cfg.server, 443) catch fatal("bad server address: {s}", .{cfg.server});

    var pw: []const u8 = undefined;
    switch (cfg.password) {
        .none => pw = init.environ_map.get("ANYTLS_PASSWORD") orelse
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
        b.* = .empty;
        if (cfg.ca) |p| {
            loadCa(io, alloc, b, p) catch fatal("cannot load CA bundle: {s}", .{p});
        } else {
            const defaults = [_][]const u8{
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/ssl/cert.pem",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
            };
            var loaded = false;
            for (defaults) |p| {
                if (loadCa(io, alloc, b, p)) |_| {
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

    const listen_hp = splitHostPort(cfg.listen, 1080) catch fatal("bad listen address: {s}", .{cfg.listen});
    const listen_addr = resolveOne(io, alloc, listen_hp.host, listen_hp.port) catch
        fatal("cannot resolve listen address: {s}", .{cfg.listen});
    const listen_fd = makeListener(listen_addr, 128) catch |e|
        fatal("cannot listen on {s}: {s}", .{ cfg.listen, @errorName(e) });
    defer _ = std.c.close(listen_fd);

    const client = anytls.Client.init(alloc, .{
        .io = io,
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
    log.info("socks5 {s} -> {s}:{d} sni={s} verify={s}", .{
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

        const rc = std.c.accept(listen_fd, null, null);
        if (rc < 0) {
            if (stop_flag.load(.acquire)) break;
            if (sockaddr.errno() == .INTR) continue;
            log.warn("accept failed: errno {d}", .{@backingInt(sockaddr.errno())});
            continue;
        }
        const conn = sockaddr.makeStream(@intCast(rc), listen_addr);
        log.debug("accepted connection", .{});
        const t = std.Thread.spawn(
            .{ .stack_size = 512 * 1024 },
            socks5.handle,
            .{ client, io, conn, cfg.half_close_wait_s * std.time.ns_per_s },
        ) catch |e| {
            log.err("cannot spawn connection thread: {s}", .{@errorName(e)});
            conn.close(io);
            continue;
        };
        t.detach();
    }

    log.info("shutting down", .{});
    client.deinit();
}

fn makeListener(addr: IpAddress, backlog: u31) !posix.socket_t {
    const rc = std.c.socket(sockaddr.family(addr), posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (rc < 0) return error.SocketFailed;
    const fd: posix.socket_t = @intCast(rc);
    errdefer _ = std.c.close(fd);

    // SO_REUSEADDR only: SO_REUSEPORT would let a second instance silently
    // share the SOCKS port instead of failing to bind.
    const one: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

    var storage: posix.sockaddr.storage = undefined;
    const len = sockaddr.toSockaddr(addr, &storage);
    if (std.c.bind(fd, @ptrCast(&storage), len) != 0) {
        return switch (sockaddr.errno()) {
            .ADDRINUSE => error.AddressInUse,
            .ACCES => error.AccessDenied,
            else => error.BindFailed,
        };
    }
    if (std.c.listen(fd, backlog) != 0) return error.ListenFailed;
    return fd;
}

fn loadCa(io: std.Io, alloc: std.mem.Allocator, bundle: *std.crypto.Certificate.Bundle, path: []const u8) !void {
    const abs = std.Io.Dir.cwd().realPathFileAlloc(io, path, alloc) catch return error.FileNotFound;
    defer alloc.free(abs);
    try bundle.addCertsFromFilePathAbsolute(alloc, io, std.Io.Timestamp.now(io, .real), abs);
}

fn resolveOne(io: std.Io, alloc: std.mem.Allocator, host: []const u8, port: u16) !IpAddress {
    _ = alloc;
    if (host.len == 0 or std.mem.eql(u8, host, "*")) {
        return .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = port } };
    }
    if (IpAddress.parse(host, port)) |a| return a else |_| {}

    // Not an IP literal: ask the system resolver.
    const host_name = std.Io.net.HostName.init(host) catch return error.UnknownHostName;
    var results: [8]std.Io.net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&results);
    try host_name.lookup(io, &queue, .{ .port = port });
    while (queue.getOne(io)) |item| {
        switch (item) {
            .address => |a| return a,
            .canonical_name => {},
        }
    } else |_| {}
    return error.UnknownHostName;
}

const HostPort = struct { host: []const u8, port: u16 };

fn splitHostPort(s_in: []const u8, default_port: u16) !HostPort {
    if (s_in.len == 0) return error.BadAddress;
    if (s_in[0] == '[') {
        const close = std.mem.indexOfScalar(u8, s_in, ']') orelse return error.BadAddress;
        const host = s_in[1..close];
        const rest = s_in[close + 1 ..];
        if (rest.len < 2 or rest[0] != ':') return error.BadAddress;
        const port = try std.fmt.parseInt(u16, rest[1..], 10);
        return .{ .host = host, .port = port };
    }
    const idx = std.mem.lastIndexOfScalar(u8, s_in, ':') orelse
        return .{ .host = s_in, .port = default_port };
    const host = s_in[0..idx];
    if (host.len == 0) return error.BadAddress;
    const port = try std.fmt.parseInt(u16, s_in[idx + 1 ..], 10);
    return .{ .host = host, .port = port };
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
