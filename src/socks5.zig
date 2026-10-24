//! SOCKS5 CONNECT inbound (no auth), mirroring the reference client's local
//! entry point. Target names are forwarded to the server unresolved, so DNS
//! happens on the proxy side unless the client sends a literal address.

const std = @import("std");
const net = std.Io.net;
const posix = std.posix;
const anytls = @import("anytls.zig");
const proto = @import("protocol.zig");
const log = @import("log.zig");

const handshake_timeout_ms: u32 = 30_000;

pub fn handle(client: *anytls.Client, io: std.Io, conn: net.Stream, half_close_wait_ns: u64) void {
    var sock = conn;
    defer sock.close(io);
    log.debug("socks: connection accepted", .{});

    setRecvTimeout(sock.socket.handle, handshake_timeout_ms);

    var addr_buf: [262]u8 = undefined;
    const req = handshake(io, &sock, &addr_buf) catch |e| {
        log.debug("socks: handshake failed: {s}", .{@errorName(e)});
        return;
    };
    setRecvTimeout(sock.socket.handle, 0);

    if (req.cmd != 1) {
        reply(io, &sock, 0x07);
        return;
    }

    const stream = client.openStream(req.target, req.port) catch |e| {
        log.warn("socks: open stream failed: {s}", .{@errorName(e)});
        reply(io, &sock, 0x01);
        return;
    };

    // Second reference for the stream->local pump.
    stream.acquire();
    var relay: Relay = .{ .io = io };
    const thread = std.Thread.spawn(
        .{ .stack_size = 96 * 1024 },
        pumpToLocal,
        .{ stream, io, &sock, &relay },
    ) catch |e| {
        log.err("socks: cannot start relay thread: {s}", .{@errorName(e)});
        stream.release();
        reply(io, &sock, 0x01);
        anytls.streamFinished(stream);
        return;
    };

    reply(io, &sock, 0x00);
    var show_buf: [96]u8 = undefined;
    log.info("socks: {s} -> session {d} stream {d}", .{
        formatTarget(&show_buf, req.target, req.port), stream.sessionSeq(), stream.id,
    });

    pumpToRemote(stream, io, &sock);

    if (!relay.wait(half_close_wait_ns)) {
        // Peer never sent its FIN. anytls-go servers close the stream on our
        // FIN without replying, so waiting forever would leak the thread.
        log.debug("socks: half-close grace expired, tearing down", .{});
        sock.shutdown(io, .both) catch {};
        if (!relay.wait(2 * std.time.ns_per_s)) {
            // The pump is still blocked reading the stream; aborting the
            // pipe wakes it. Must happen before join().
            stream.closeNow();
        }
    }
    thread.join();
    anytls.streamFinished(stream);
}

const Request = struct {
    cmd: u8,
    target: proto.Target,
    port: u16,
};

fn handshake(io: std.Io, sock: *net.Stream, addr_buf: *[262]u8) !Request {
    var hdr: [2]u8 = undefined;
    try readExact(io, sock, &hdr);
    if (hdr[0] != 5) return error.NotSocks5;
    const nmethods = hdr[1];
    if (nmethods == 0) return error.BadGreeting;

    var methods: [255]u8 = undefined;
    try readExact(io, sock, methods[0..nmethods]);
    var ok = false;
    for (methods[0..nmethods]) |m| {
        if (m == 0) ok = true;
    }
    if (!ok) {
        try writeAll(io, sock, &.{ 5, 0xff });
        return error.NoAcceptableAuth;
    }
    try writeAll(io, sock, &.{ 5, 0 });

    var req_hdr: [4]u8 = undefined;
    try readExact(io, sock, &req_hdr);
    if (req_hdr[0] != 5 or req_hdr[2] != 0) return error.BadRequest;

    var target: proto.Target = undefined;
    switch (req_hdr[3]) {
        1 => {
            var a: [4]u8 = undefined;
            try readExact(io, sock, &a);
            target = .{ .ip4 = a };
        },
        3 => {
            var l: [1]u8 = undefined;
            try readExact(io, sock, &l);
            if (l[0] == 0) return error.BadRequest;
            const n = l[0];
            try readExact(io, sock, addr_buf[0..n]);
            target = .{ .domain = addr_buf[0..n] };
        },
        4 => {
            var a: [16]u8 = undefined;
            try readExact(io, sock, &a);
            target = .{ .ip6 = a };
        },
        else => {
            reply(io, sock, 0x08);
            return error.BadAddressType;
        },
    }

    var p: [2]u8 = undefined;
    try readExact(io, sock, &p);
    return .{
        .cmd = req_hdr[1],
        .target = target,
        .port = std.mem.readInt(u16, &p, .big),
    };
}

fn formatTarget(buf: []u8, t: proto.Target, port: u16) []const u8 {
    return switch (t) {
        .domain => |d| std.fmt.bufPrint(buf, "{s}:{d}", .{ d, port }) catch d,
        .ip4 => |a| std.fmt.bufPrint(buf, "{f}", .{net.Ip4Address{ .bytes = a, .port = port }}) catch "ipv4",
        .ip6 => |a| std.fmt.bufPrint(buf, "{f}", .{net.Ip6Address{ .bytes = a, .port = port }}) catch "ipv6",
    };
}

fn reply(io: std.Io, sock: *net.Stream, code: u8) void {
    writeAll(io, sock, &.{ 5, code, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
}

const Relay = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    done: bool = false,

    fn finish(self: *Relay) void {
        self.mutex.lockUncancelable(self.io);
        self.done = true;
        self.cond.broadcast(self.io);
        self.mutex.unlock(self.io);
    }

    fn wait(self: *Relay, timeout_ns: u64) bool {
        self.mutex.lockUncancelable(self.io);
        if (!self.done) {
            self.cond.waitTimeout(self.io, &self.mutex, .{
                .duration = .{
                    .raw = .fromNanoseconds(@intCast(timeout_ns)),
                    .clock = .boot,
                },
            }) catch {};
        }
        const d = self.done;
        self.mutex.unlock(self.io);
        return d;
    }
};

fn pumpToLocal(stream: *anytls.Stream, io: std.Io, sock: *net.Stream, relay: *Relay) void {
    defer relay.finish();
    defer stream.release();

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) orelse break;
        if (n == 0) continue;
        streamWrite(sock, io, buf[0..n]) catch {
            sock.shutdown(io, .both) catch {};
            return;
        };
    }
    if (stream.wasAborted()) {
        sock.shutdown(io, .both) catch {};
    } else {
        // Remote half-closed: propagate EOF to the local application, but keep
        // reading from it so it can still send (TCP half close).
        sock.shutdown(io, .send) catch {};
    }
}

fn pumpToRemote(stream: *anytls.Stream, io: std.Io, sock: *net.Stream) void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        var iov: [1][]u8 = .{&buf};
        const n = streamRead(sock, io, &iov) catch break;
        if (n == 0) break;
        stream.write(buf[0..n]) catch break;
    }
    stream.sendFin();
}

/// std.Io.net.Stream.read does not compile on 0.17.0 (it destructures a
/// struct), so issue the operation directly.
fn streamRead(sock: *const net.Stream, io: std.Io, iov: [][]u8) !usize {
    const result = try io.operate(.{ .net_read = .{
        .socket_handle = sock.socket.handle,
        .data = iov,
    } });
    const r = try result.net_read;
    return r.data_len;
}

fn readExact(io: std.Io, sock: *net.Stream, out: []u8) !void {
    var i: usize = 0;
    while (i < out.len) {
        var iov: [1][]u8 = .{out[i..]};
        const n = try streamRead(sock, io, &iov);
        if (n == 0) return error.EndOfStream;
        i += n;
    }
}

fn writeAll(io: std.Io, sock: *net.Stream, data: []const u8) !void {
    try streamWrite(sock, io, data);
}

fn streamWrite(sock: *const net.Stream, io: std.Io, data: []const u8) !void {
    var iov: [1][]const u8 = .{data};
    var off: usize = 0;
    while (off < data.len) {
        iov[0] = data[off..];
        const result = try io.operate(.{ .net_write = .{
            .socket_handle = sock.socket.handle,
            .data = &iov,
        } });
        const n = try result.net_write;
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

fn setRecvTimeout(fd: posix.socket_t, ms: u32) void {
    const tv = posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
}
