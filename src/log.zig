//! Minimal leveled logger. Credentials are never passed here: only the
//! SHA-256 of the password is retained by the client, so logs cannot leak it.

const std = @import("std");

pub const Level = enum(u8) {
    err = 0,
    warn = 1,
    info = 2,
    debug = 3,

    pub fn parse(s: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(s, "error") or std.ascii.eqlIgnoreCase(s, "err")) return .err;
        if (std.ascii.eqlIgnoreCase(s, "warn") or std.ascii.eqlIgnoreCase(s, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(s, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(s, "debug")) return .debug;
        return null;
    }
};

var current: Level = .info;

pub fn setLevel(l: Level) void {
    current = l;
}

pub fn enabled(l: Level) bool {
    return @backingInt(l) <= @backingInt(current);
}

fn emit(comptime lvl: Level, comptime fmt: []const u8, args: anytype) void {
    if (!enabled(lvl)) return;
    const tag = switch (lvl) {
        .err => "ERR ",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DBG ",
    };
    // std.debug.print holds its own lock, so concurrent lines stay intact.
    std.debug.print("[{s}] " ++ fmt ++ "\n", .{tag} ++ args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    emit(.err, fmt, args);
}
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    emit(.warn, fmt, args);
}
pub fn info(comptime fmt: []const u8, args: anytype) void {
    emit(.info, fmt, args);
}
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    emit(.debug, fmt, args);
}
