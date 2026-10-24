//! IpAddress -> sockaddr conversion for the raw-socket paths.
//!
//! Zig 0.17 no longer exposes `std.posix.socket/bind/listen`, and the Io-net
//! listener always turns on SO_REUSEPORT, which this project deliberately
//! avoids (a second instance must fail to bind, not share the port). Both the
//! listener and the TLS connect path therefore go through libc, and share the
//! address conversion here.

const std = @import("std");
const posix = std.posix;
const IpAddress = std.Io.net.IpAddress;

pub fn family(addr: IpAddress) u32 {
    return switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
}

pub fn toSockaddr(addr: IpAddress, storage: *posix.sockaddr.storage) posix.socklen_t {
    return switch (addr) {
        .ip4 => |a| blk: {
            const sin: *posix.sockaddr.in = @ptrCast(storage);
            sin.* = .{
                .family = posix.AF.INET,
                .port = std.mem.nativeToBig(u16, a.port),
                .addr = @bitCast(a.bytes),
            };
            break :blk @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |a| blk: {
            const sin6: *posix.sockaddr.in6 = @ptrCast(storage);
            sin6.* = .{
                .family = posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, a.port),
                .flowinfo = a.flow,
                .addr = a.bytes,
                .scope_id = a.interface.index,
            };
            break :blk @sizeOf(posix.sockaddr.in6);
        },
    };
}

/// Errno of the last failed libc call.
pub fn errno() std.os.linux.E {
    return @fromBackingInt(@intCast(std.c._errno().*));
}

pub fn makeStream(fd: posix.socket_t, addr: IpAddress) std.Io.net.Stream {
    return .{ .socket = .{ .handle = fd, .address = addr } };
}
