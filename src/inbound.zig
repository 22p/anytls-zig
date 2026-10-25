//! Mixed inbound: one listen port for both SOCKS5 and HTTP proxy clients.
//! The protocol is chosen by peeking the first byte of the connection —
//! 0x05 is the SOCKS5 version field, anything else is treated as HTTP.

const std = @import("std");
const posix = std.posix;
const anytls = @import("anytls.zig");
const socks5 = @import("socks5.zig");
const http = @import("http.zig");

pub fn handle(client: *anytls.Client, fd: posix.socket_t, half_close_wait_ns: u64) void {
    var first: [1]u8 = undefined;
    const n = posix.recv(fd, &first, posix.MSG.PEEK) catch {
        posix.close(fd);
        return;
    };
    if (n == 0) {
        posix.close(fd);
        return;
    }
    if (first[0] == 5) {
        socks5.handle(client, fd, half_close_wait_ns);
    } else {
        http.handle(client, fd, half_close_wait_ns);
    }
}
