//! Option merging: CLI > TOML file > built-in defaults.
//!
//! The same field set is used by all three sources so precedence stays
//! explicit; a TOML file is only read when -c/--config is given.

const std = @import("std");
const toml = @import("toml.zig");
const log = @import("log.zig");

pub const Overrides = struct {
    listen: ?[]const u8 = null,
    server: ?[]const u8 = null,
    password: ?[]const u8 = null,
    sni: ?[]const u8 = null,
    ca: ?[]const u8 = null,
    insecure: ?bool = null,
    min_idle: ?usize = null,
    idle_timeout_s: ?i64 = null,
    connect_timeout_s: ?u32 = null,
    max_streams: ?usize = null,
    half_close_wait_s: ?u64 = null,
    level: ?log.Level = null,
};

pub const Password = union(enum) {
    none,
    literal: []const u8,
};

pub const Config = struct {
    listen: []const u8 = "127.0.0.1:1080",
    server: []const u8 = "",
    password: Password = .none,
    sni: ?[]const u8 = null,
    ca: ?[]const u8 = null,
    insecure: bool = false,
    min_idle: usize = 5,
    idle_timeout_s: i64 = 30,
    connect_timeout_s: u32 = 10,
    max_streams: usize = 128,
    half_close_wait_s: u64 = 3,
    level: log.Level = .info,
};

pub fn merge(cli: Overrides, file: Overrides) Config {
    const cfg: Config = .{
        .listen = cli.listen orelse file.listen orelse "127.0.0.1:1080",
        .server = cli.server orelse file.server orelse "",
        .sni = cli.sni orelse file.sni,
        .ca = cli.ca orelse file.ca,
        .insecure = cli.insecure orelse file.insecure orelse false,
        .min_idle = cli.min_idle orelse file.min_idle orelse 5,
        .idle_timeout_s = cli.idle_timeout_s orelse file.idle_timeout_s orelse 30,
        .connect_timeout_s = cli.connect_timeout_s orelse file.connect_timeout_s orelse 10,
        .max_streams = cli.max_streams orelse file.max_streams orelse 128,
        .half_close_wait_s = cli.half_close_wait_s orelse file.half_close_wait_s orelse 3,
        .level = cli.level orelse file.level orelse .info,
    };

    var out = cfg;
    // Password precedence: CLI -p, then the TOML file, then the environment
    // (handled by the caller if still none).
    if (file.password) |p| out.password = .{ .literal = p };
    if (cli.password) |p| out.password = .{ .literal = p };
    return out;
}

pub fn overridesFromTable(t: *const toml.Table, diag: *toml.Diag) !Overrides {
    var ov: Overrides = .{};
    var it = t.map.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const val = entry.value_ptr.*;

        if (std.mem.eql(u8, key, "listen.address")) {
            ov.listen = try wantString(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.address")) {
            ov.server = try wantString(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.sni")) {
            ov.sni = try wantString(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.password")) {
            ov.password = try wantString(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.ca")) {
            ov.ca = try wantString(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.insecure")) {
            ov.insecure = try wantBool(val, key, diag);
        } else if (std.mem.eql(u8, key, "server.connect_timeout")) {
            ov.connect_timeout_s = @intCast(try wantInt(val, key, diag, 1, 300));
        } else if (std.mem.eql(u8, key, "session.min_idle")) {
            ov.min_idle = @intCast(try wantInt(val, key, diag, 0, 64));
        } else if (std.mem.eql(u8, key, "session.idle_timeout")) {
            ov.idle_timeout_s = try wantInt(val, key, diag, 5, 86_400);
        } else if (std.mem.eql(u8, key, "session.max_streams")) {
            ov.max_streams = @intCast(try wantInt(val, key, diag, 1, 4096));
        } else if (std.mem.eql(u8, key, "session.half_close_wait")) {
            ov.half_close_wait_s = @intCast(try wantInt(val, key, diag, 0, 3600));
        } else if (std.mem.eql(u8, key, "log.level")) {
            const s = try wantString(val, key, diag);
            ov.level = log.Level.parse(s) orelse {
                diag.key = key;
                diag.msg = "expected error|warn|info|debug";
                return error.InvalidValue;
            };
        } else {
            diag.key = key;
            diag.msg = "unknown key";
            return error.UnknownKey;
        }
    }

    return ov;
}

fn wantString(v: toml.Value, key: []const u8, diag: *toml.Diag) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => {
            diag.key = key;
            diag.msg = "expected a string";
            return error.InvalidValue;
        },
    };
}

fn wantBool(v: toml.Value, key: []const u8, diag: *toml.Diag) !bool {
    return switch (v) {
        .boolean => |b| b,
        else => {
            diag.key = key;
            diag.msg = "expected true or false";
            return error.InvalidValue;
        },
    };
}

fn wantInt(v: toml.Value, key: []const u8, diag: *toml.Diag, min: i64, max: i64) !i64 {
    const n = switch (v) {
        .integer => |i| i,
        else => {
            diag.key = key;
            diag.msg = "expected an integer";
            return error.InvalidValue;
        },
    };
    if (n < min or n > max) {
        diag.key = key;
        diag.msg = "value out of range";
        return error.InvalidValue;
    }
    return n;
}
