//! SOCKS5 CONNECT and UDP ASSOCIATE inbound (no auth), mirroring the reference
//! client's local entry point. Target names are forwarded to the server
//! unresolved, so DNS happens on the proxy side unless the client sends a
//! literal address. UDP associations are carried over TCP with UoT v2.

const std = @import("std");
const net = std.net;
const posix = std.posix;
const anytls = @import("anytls.zig");
const proto = @import("protocol.zig");
const udp = @import("udp.zig");
const log = @import("log.zig");

const handshake_timeout_ms: u32 = 30_000;

pub fn handle(client: *anytls.Client, fd: posix.socket_t, half_close_wait_ns: u64) void {
    defer posix.close(fd);
    log.debug("socks: connection accepted", .{});

    setRecvTimeout(fd, handshake_timeout_ms);

    var addr_buf: [262]u8 = undefined;
    const req = handshake(fd, &addr_buf) catch |e| {
        var peer_buf: [72]u8 = undefined;
        log.debug("socks: handshake failed: {s} (peer {s})", .{
            @errorName(e), peerString(&peer_buf, fd),
        });
        return;
    };
    setRecvTimeout(fd, 0);

    if (req.cmd == 3) {
        udp.run(client, fd);
        return;
    }
    if (req.cmd != 1) {
        reply(fd, 0x07);
        return;
    }

    const stream = client.openStream(req.target, req.port) catch |e| {
        log.warn("socks: open stream failed: {s}", .{@errorName(e)});
        reply(fd, 0x01);
        return;
    };

    // Second reference for the stream->local pump.
    stream.acquire();
    var relay: Relay = .{};
    const thread = std.Thread.spawn(
        .{ .stack_size = 96 * 1024 },
        pumpToLocal,
        .{ stream, fd, &relay },
    ) catch |e| {
        log.err("socks: cannot start relay thread: {s}", .{@errorName(e)});
        stream.release();
        reply(fd, 0x01);
        anytls.streamFinished(stream);
        return;
    };

    reply(fd, 0x00);
    var show_buf: [96]u8 = undefined;
    log.info("socks: {s} -> session {d} stream {d}", .{
        formatTarget(&show_buf, req.target, req.port), stream.sessionSeq(), stream.id,
    });

    pumpToRemote(stream, fd);

    if (!relay.wait(half_close_wait_ns)) {
        // Peer never sent its FIN. anytls-go servers close the stream on our
        // FIN without replying, so waiting forever would leak the thread.
        log.debug("socks: half-close grace expired, tearing down", .{});
        posix.shutdown(fd, .both) catch {};
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

fn handshake(fd: posix.socket_t, addr_buf: *[262]u8) !Request {
    var hdr: [2]u8 = undefined;
    try readExact(fd, &hdr);
    if (hdr[0] != 5) {
        // Show the offending greeting so a wrong proxy type (HTTP "GET"/
        // "CONNECT", SOCKS4 0x04, TLS 0x16 ...) is identifiable in the log.
        log.debug("socks: greeting is not socks5, first bytes: {x:0>2} {x:0>2}", .{ hdr[0], hdr[1] });
        return error.NotSocks5;
    }
    const nmethods = hdr[1];
    if (nmethods == 0) return error.BadGreeting;

    var methods: [255]u8 = undefined;
    try readExact(fd, methods[0..nmethods]);
    var ok = false;
    for (methods[0..nmethods]) |m| {
        if (m == 0) ok = true;
    }
    if (!ok) {
        try writeAll(fd, &.{ 5, 0xff });
        return error.NoAcceptableAuth;
    }
    try writeAll(fd, &.{ 5, 0 });

    var req_hdr: [4]u8 = undefined;
    try readExact(fd, &req_hdr);
    if (req_hdr[0] != 5 or req_hdr[2] != 0) return error.BadRequest;

    var target: proto.Target = undefined;
    switch (req_hdr[3]) {
        1 => {
            var a: [4]u8 = undefined;
            try readExact(fd, &a);
            target = .{ .ip4 = a };
        },
        3 => {
            var l: [1]u8 = undefined;
            try readExact(fd, &l);
            if (l[0] == 0) return error.BadRequest;
            const n = l[0];
            try readExact(fd, addr_buf[0..n]);
            target = .{ .domain = addr_buf[0..n] };
        },
        4 => {
            var a: [16]u8 = undefined;
            try readExact(fd, &a);
            target = .{ .ip6 = a };
        },
        else => {
            reply(fd, 0x08);
            return error.BadAddressType;
        },
    }

    var p: [2]u8 = undefined;
    try readExact(fd, &p);
    return .{
        .cmd = req_hdr[1],
        .target = target,
        .port = std.mem.readInt(u16, &p, .big),
    };
}

fn formatTarget(buf: []u8, t: proto.Target, port: u16) []const u8 {
    return switch (t) {
        .domain => |d| std.fmt.bufPrint(buf, "{s}:{d}", .{ d, port }) catch d,
        .ip4 => |a| std.fmt.bufPrint(buf, "{f}", .{net.Address.initIp4(a, port)}) catch "ipv4",
        .ip6 => |a| std.fmt.bufPrint(buf, "{f}", .{net.Address.initIp6(a, port, 0, 0)}) catch "ipv6",
    };
}

fn peerString(buf: []u8, fd: posix.socket_t) []const u8 {
    var sa: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getpeername(fd, @ptrCast(&sa), &len) catch return "?";
    const addr = net.Address.initPosix(@ptrCast(&sa));
    return std.fmt.bufPrint(buf, "{f}", .{addr}) catch "?";
}

fn reply(fd: posix.socket_t, code: u8) void {
    writeAll(fd, &.{ 5, code, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
}

const Relay = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    done: bool = false,

    fn finish(self: *Relay) void {
        self.mutex.lock();
        self.done = true;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    fn wait(self: *Relay, timeout_ns: u64) bool {
        self.mutex.lock();
        if (!self.done) {
            self.cond.timedWait(&self.mutex, timeout_ns) catch {};
        }
        const d = self.done;
        self.mutex.unlock();
        return d;
    }
};

fn pumpToLocal(stream: *anytls.Stream, fd: posix.socket_t, relay: *Relay) void {
    defer relay.finish();
    defer stream.release();

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) orelse break;
        if (n == 0) continue;
        writeAll(fd, buf[0..n]) catch {
            posix.shutdown(fd, .both) catch {};
            return;
        };
    }
    if (stream.wasAborted()) {
        posix.shutdown(fd, .both) catch {};
    } else {
        // Remote half-closed: propagate EOF to the local application, but keep
        // reading from it so it can still send (TCP half close).
        posix.shutdown(fd, .send) catch {};
    }
}

fn pumpToRemote(stream: *anytls.Stream, fd: posix.socket_t) void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        stream.write(buf[0..n]) catch break;
    }
    stream.sendFin();
}

fn readExact(fd: posix.socket_t, out: []u8) !void {
    var i: usize = 0;
    while (i < out.len) {
        const n = try posix.recv(fd, out[i..], 0);
        if (n == 0) return error.EndOfStream;
        i += n;
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
