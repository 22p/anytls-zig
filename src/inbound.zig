//! Mixed inbound: one listen port for both SOCKS5 and HTTP proxy clients.
//! The protocol is chosen by peeking the first byte of the connection — 0x05
//! is the SOCKS5 version field, an ASCII letter starts an HTTP method.
//! Anything else (SOCKS4, TLS, scanners) is dropped without waiting.

const std = @import("std");
const posix = std.posix;
const anytls = @import("anytls.zig");
const socks5 = @import("socks5.zig");
const http = @import("http.zig");
const log = @import("log.zig");

const handshake_timeout_ms: u32 = 30_000;

pub fn handle(client: *anytls.Client, fd: posix.socket_t, half_close_wait_ns: u64) void {
    // Set before the peek: a client that connects and goes silent must not
    // hold this thread past the handshake budget.
    setRecvTimeout(fd, handshake_timeout_ms);

    var first: [1]u8 = undefined;
    const n = posix.recv(fd, &first, posix.MSG.PEEK) catch |e| {
        log.debug("inbound: peek failed: {s}", .{@errorName(e)});
        posix.close(fd);
        return;
    };
    if (n == 0) {
        posix.close(fd);
        return;
    }

    if (first[0] == 5) {
        socks5.handle(client, fd, half_close_wait_ns);
    } else if (std.ascii.isAlphabetic(first[0])) {
        http.handle(client, fd, half_close_wait_ns);
    } else {
        log.debug("inbound: unrecognized first byte 0x{x:0>2}, closing", .{first[0]});
        posix.close(fd);
    }
}

fn setRecvTimeout(fd: posix.socket_t, ms: u32) void {
    const tv = posix.timeval{
        .sec = @intCast(ms / 1000),
        .usec = @intCast((ms % 1000) * 1000),
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
}
