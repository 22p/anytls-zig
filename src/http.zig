//! HTTP proxy inbound for the mixed listen port: HTTP CONNECT tunnels and
//! plain absolute-form HTTP requests. The dispatcher peeks the first byte of
//! each connection — 0x05 is SOCKS5, anything else lands here.

const std = @import("std");
const posix = std.posix;
const net = std.net;
const anytls = @import("anytls.zig");
const proto = @import("protocol.zig");
const relay = @import("relay.zig");
const log = @import("log.zig");

const handshake_timeout_ms: u32 = 30_000;
const max_header = 16 * 1024;

const Head = struct {
    /// Everything read from the socket: headers plus any early tunnel data.
    full: []const u8,
    /// Offset of the request line's CRLF.
    line_end: usize,
    /// Offset just past the blank line that ends the headers.
    end: usize,
    method: []const u8,
    target: []const u8,
    version: []const u8,
};

pub fn handle(client: *anytls.Client, fd: posix.socket_t, half_close_wait_ns: u64) void {
    defer posix.close(fd);
    log.debug("http: connection accepted", .{});

    setRecvTimeout(fd, handshake_timeout_ms);

    var buf: [max_header]u8 = undefined;
    const head = readHead(fd, &buf) catch |e| {
        log.debug("http: request parse failed: {s}", .{@errorName(e)});
        if (e == error.BadRequest or e == error.HeaderTooLarge) {
            respondError(fd, "400 Bad Request");
        }
        return;
    };
    setRecvTimeout(fd, 0);

    if (std.mem.eql(u8, head.method, "CONNECT")) {
        serveConnect(client, fd, head, half_close_wait_ns);
        return;
    }
    servePlain(client, fd, head, half_close_wait_ns);
}

fn serveConnect(
    client: *anytls.Client,
    fd: posix.socket_t,
    head: Head,
    half_close_wait_ns: u64,
) void {
    const hp = proto.splitHostPort(head.target, 443) catch {
        respondError(fd, "400 Bad Request");
        return;
    };

    const stream = client.openStream(parseTarget(hp.host), hp.port) catch |e| {
        log.warn("http: open stream failed: {s}", .{@errorName(e)});
        respondError(fd, "502 Bad Gateway");
        return;
    };
    defer anytls.streamFinished(stream);

    writeAll(fd, "HTTP/1.1 200 Connection established\r\n\r\n") catch return;

    // The client may pipeline tunnel data behind the request headers.
    const early = head.full[head.end..];
    if (early.len > 0) {
        streamWriteAll(stream, early) catch |e| {
            log.debug("http: early data write failed: {s}", .{@errorName(e)});
            return;
        };
    }

    var show_buf: [96]u8 = undefined;
    log.info("http: CONNECT {s} -> session {d} stream {d}", .{
        formatHostPort(&show_buf, hp.host, hp.port), stream.sessionSeq(), stream.id,
    });
    relay.run(stream, fd, half_close_wait_ns);
}

fn servePlain(
    client: *anytls.Client,
    fd: posix.socket_t,
    head: Head,
    half_close_wait_ns: u64,
) void {
    if (std.mem.startsWith(u8, head.target, "https://")) {
        // Only CONNECT can carry TLS to https:// origins.
        respondError(fd, "405 Method Not Allowed");
        return;
    }

    var hp: proto.HostPort = undefined;
    var path: []const u8 = undefined;
    if (std.mem.startsWith(u8, head.target, "http://")) {
        const uri = parseAbsoluteUri(head.target) catch {
            respondError(fd, "400 Bad Request");
            return;
        };
        hp = uri.hp;
        path = uri.path;
    } else if (head.target.len > 0 and head.target[0] == '/') {
        hp = hostFromHeaders(head) orelse {
            respondError(fd, "400 Bad Request");
            return;
        };
        path = head.target;
    } else {
        respondError(fd, "400 Bad Request");
        return;
    }

    var out_buf: [max_header]u8 = undefined;
    const out = buildForwardRequest(&out_buf, head, path) catch {
        respondError(fd, "400 Bad Request");
        return;
    };

    const stream = client.openStream(parseTarget(hp.host), hp.port) catch |e| {
        log.warn("http: open stream failed: {s}", .{@errorName(e)});
        respondError(fd, "502 Bad Gateway");
        return;
    };
    defer anytls.streamFinished(stream);

    // The origin's response goes back to the client unmodified.
    streamWriteAll(stream, out) catch |e| {
        log.debug("http: request write failed: {s}", .{@errorName(e)});
        return;
    };
    const early = head.full[head.end..];
    if (early.len > 0) {
        streamWriteAll(stream, early) catch |e| {
            log.debug("http: body write failed: {s}", .{@errorName(e)});
            return;
        };
    }

    var show_buf: [96]u8 = undefined;
    log.info("http: {s} {s} -> session {d} stream {d}", .{
        head.method, formatHostPort(&show_buf, hp.host, hp.port), stream.sessionSeq(), stream.id,
    });
    relay.run(stream, fd, half_close_wait_ns);
}

fn readHead(fd: posix.socket_t, buf: *[max_header]u8) !Head {
    var n: usize = 0;
    while (true) {
        if (std.mem.indexOf(u8, buf[0..n], "\r\n\r\n")) |e| {
            return parseHead(buf[0..n], e + 4);
        }
        if (n == buf.len) return error.HeaderTooLarge;
        const got = posix.recv(fd, buf[n..], 0) catch return error.RecvFailed;
        if (got == 0) return error.EndOfStream;
        n += got;
    }
}

pub fn parseHead(full: []const u8, end: usize) !Head {
    const line_end = std.mem.indexOf(u8, full[0..end], "\r\n") orelse return error.BadRequest;
    var it = std.mem.tokenizeScalar(u8, full[0..line_end], ' ');
    const method = it.next() orelse return error.BadRequest;
    const target = it.next() orelse return error.BadRequest;
    const version = it.next() orelse return error.BadRequest;
    if (!std.mem.startsWith(u8, version, "HTTP/")) return error.BadRequest;
    return .{
        .full = full,
        .line_end = line_end,
        .end = end,
        .method = method,
        .target = target,
        .version = version,
    };
}

const AbsoluteUri = struct {
    hp: proto.HostPort,
    /// Path + query as they must appear in the origin-form request target.
    path: []const u8,
};

pub fn parseAbsoluteUri(t: []const u8) !AbsoluteUri {
    const rest = t["http://".len..];
    const auth_end = std.mem.indexOfAny(u8, rest, "/?") orelse rest.len;
    const hp = try proto.splitHostPort(rest[0..auth_end], 80);
    return .{ .hp = hp, .path = rest[auth_end..] };
}

pub fn hostFromHeaders(head: Head) ?proto.HostPort {
    var lines = std.mem.splitScalar(u8, head.full[head.line_end + 2 .. head.end], '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), "host")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return proto.splitHostPort(value, 80) catch null;
    }
    return null;
}

/// Rewrite the request line to origin-form and drop hop-by-hop proxy headers.
pub fn buildForwardRequest(out: []u8, head: Head, path: []const u8) ![]const u8 {
    var n: usize = 0;
    // Absolute URIs without a path still need "/" in origin-form; a bare
    // query string needs the leading slash prepended.
    const req_line = if (path.len == 0)
        std.fmt.bufPrint(out, "{s} / {s}\r\n", .{ head.method, head.version })
    else if (path[0] == '?')
        std.fmt.bufPrint(out, "{s} /{s} {s}\r\n", .{ head.method, path, head.version })
    else
        std.fmt.bufPrint(out, "{s} {s} {s}\r\n", .{ head.method, path, head.version });
    n += (req_line catch return error.NoSpace).len;

    var lines = std.mem.splitScalar(u8, head.full[head.line_end + 2 .. head.end], '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, "\r");
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " ");
        if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) continue;
        if (std.ascii.eqlIgnoreCase(name, "proxy-authorization")) continue;
        if (n + line.len + 2 > out.len) return error.NoSpace;
        @memcpy(out[n..][0..line.len], line);
        n += line.len;
        out[n] = '\r';
        out[n + 1] = '\n';
        n += 2;
    }
    if (n + 2 > out.len) return error.NoSpace;
    out[n] = '\r';
    out[n + 1] = '\n';
    n += 2;
    return out[0..n];
}

fn parseTarget(host: []const u8) proto.Target {
    if (net.Address.parseIp4(host, 0)) |a| {
        var ip: [4]u8 = undefined;
        @memcpy(&ip, std.mem.asBytes(&a.in.sa.addr));
        return .{ .ip4 = ip };
    } else |_| {}
    if (net.Address.parseIp6(host, 0)) |a| {
        return .{ .ip6 = a.in6.sa.addr };
    } else |_| {}
    return .{ .domain = host };
}

fn formatHostPort(buf: []u8, host: []const u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:{d}", .{ host, port }) catch "http";
}

fn respondError(fd: posix.socket_t, status: []const u8) void {
    var buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(
        &buf,
        "HTTP/1.1 {s}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        .{status},
    ) catch return;
    writeAll(fd, msg) catch {};
}

fn streamWriteAll(stream: *anytls.Stream, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = @min(data.len - off, proto.max_data_chunk);
        try stream.write(data[off..][0..n]);
        off += n;
    }
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var i: usize = 0;
    while (i < data.len) {
        const n = try posix.send(fd, data[i..], posix.MSG.NOSIGNAL);
        i += n;
    }
}

fn setRecvTimeout(fd: posix.socket_t, ms: u32) void {
    const tv = posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
}
