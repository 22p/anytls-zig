//! AnyTLS wire protocol primitives.
//!
//! Wire format is taken from anytls-go (protocol version 2) and
//! docs/protocol.md of the reference implementation, not guessed:
//!   header  = cmd(1) | streamId(4, BE) | dataLen(2, BE)
//!   auth    = sha256(password)(32) | padding0 len(2, BE) | padding0
//!   settings= "v=2\nclient=<name>\npadding-md5=<hex>"
//!   target  = SOCKS5 address (ATYP | addr | port BE)

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Command = enum(u8) {
    waste = 0,
    syn = 1,
    psh = 2,
    fin = 3,
    settings = 4,
    alert = 5,
    update_padding_scheme = 6,
    synack = 7,
    heart_request = 8,
    heart_response = 9,
    server_settings = 10,
};

pub const header_len = 7;

/// Maximum PSH payload this implementation sends in one frame.
pub const max_data_chunk = 16 * 1024;

pub const protocol_version: u8 = 2;
pub const client_name = "anytls-zig/0.1.10";

pub fn encodeHeader(h: *[header_len]u8, cmd: Command, sid: u32, data_len: usize) void {
    std.debug.assert(data_len <= std.math.maxInt(u16));
    h[0] = @intFromEnum(cmd);
    std.mem.writeInt(u32, h[1..5], sid, .big);
    std.mem.writeInt(u16, h[5..7], @intCast(data_len), .big);
}

pub const Header = struct {
    cmd: u8,
    sid: u32,
    len: u16,
};

pub fn decodeHeader(h: [header_len]u8) Header {
    return .{
        .cmd = h[0],
        .sid = std.mem.readInt(u32, h[1..5], .big),
        .len = std.mem.readInt(u16, h[5..7], .big),
    };
}

pub const Target = union(enum) {
    ip4: [4]u8,
    ip6: [16]u8,
    domain: []const u8,
};

/// SOCKS5 address encoding, as used by AnyTLS to name the proxy target.
pub fn encodeTarget(buf: []u8, target: Target, port: u16) ![]u8 {
    var n: usize = 0;
    switch (target) {
        .ip4 => |a| {
            if (buf.len < 7) return error.NoSpace;
            buf[0] = 1;
            @memcpy(buf[1..5], &a);
            n = 5;
        },
        .ip6 => |a| {
            if (buf.len < 19) return error.NoSpace;
            buf[0] = 4;
            @memcpy(buf[1..17], &a);
            n = 17;
        },
        .domain => |d| {
            if (d.len == 0 or d.len > 255) return error.InvalidAddress;
            if (buf.len < 2 + d.len + 2) return error.NoSpace;
            buf[0] = 3;
            buf[1] = @intCast(d.len);
            @memcpy(buf[2 .. 2 + d.len], d);
            n = 2 + d.len;
        },
    }
    std.mem.writeInt(u16, buf[n..][0..2], port, .big);
    return buf[0 .. n + 2];
}

pub const HostPort = struct { host: []const u8, port: u16 };

/// Split `host:port`, `[v6]:port`, or a bare `host` (using default_port).
pub fn splitHostPort(s_in: []const u8, default_port: u16) !HostPort {
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

// ---------------------------------------------------------------------------
// Padding scheme
// ---------------------------------------------------------------------------

/// Value used in the flattened size list to denote the "c" (check) marker.
pub const check_mark: u32 = std.math.maxInt(u32);

pub const max_pkts = 16;
pub const max_entries = 16;
pub const max_scheme_bytes = 4096;

/// Default scheme, byte-for-byte identical to anytls-go's defaultPaddingScheme.
pub const default_scheme_raw =
    \\stop=8
    \\0=30-30
    \\1=100-400
    \\2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
    \\3=9-9,500-1000
    \\4=500-1000
    \\5=500-1000
    \\6=500-1000
    \\7=500-1000
;

pub const PadEntry = union(enum) {
    range: struct { min: u32, max: u32 },
    check,
};

pub const Scheme = struct {
    raw: []u8,
    md5: [16]u8,
    stop: u32,
    counts: [max_pkts]u8,
    entries: [max_pkts][max_entries]PadEntry,

    pub fn parse(alloc: Allocator, raw_in: []const u8) !*Scheme {
        if (raw_in.len == 0 or raw_in.len > max_scheme_bytes) return error.InvalidScheme;

        const self = try alloc.create(Scheme);
        errdefer alloc.destroy(self);
        const raw = try alloc.dupe(u8, raw_in);
        errdefer alloc.free(raw);

        self.* = .{
            .raw = raw,
            .md5 = undefined,
            .stop = 0,
            .counts = std.mem.zeroes([max_pkts]u8),
            .entries = undefined,
        };
        std.crypto.hash.Md5.hash(raw, &self.md5, .{});

        var saw_stop = false;
        var lines = std.mem.splitScalar(u8, raw, '\n');
        while (lines.next()) |line_raw| {
            const line = std.mem.trimRight(u8, line_raw, "\r");
            if (line.len == 0) continue;
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = line[0..eq];
            const val = line[eq + 1 ..];

            if (std.mem.eql(u8, key, "stop")) {
                self.stop = std.fmt.parseInt(u32, val, 10) catch return error.InvalidScheme;
                saw_stop = true;
                continue;
            }

            const pkt_u32 = std.fmt.parseInt(u32, key, 10) catch continue;
            if (pkt_u32 >= max_pkts) continue; // out of our supported range; ignored
            const pkt: usize = @intCast(pkt_u32);

            var count: u8 = 0;
            var items = std.mem.splitScalar(u8, val, ',');
            while (items.next()) |item| {
                if (item.len == 0) continue;
                if (std.mem.eql(u8, item, "c")) {
                    if (count >= max_entries) break;
                    self.entries[pkt][count] = .check;
                    count += 1;
                    continue;
                }
                const dash = std.mem.indexOfScalar(u8, item, '-') orelse continue;
                const a = std.fmt.parseInt(u32, item[0..dash], 10) catch continue;
                const b = std.fmt.parseInt(u32, item[dash + 1 ..], 10) catch continue;
                if (a == 0 or b == 0) continue;
                const lo = @min(a, b);
                const hi = @max(a, b);
                if (count >= max_entries) break;
                self.entries[pkt][count] = .{ .range = .{ .min = lo, .max = hi } };
                count += 1;
            }
            self.counts[pkt] = count;
        }
        if (!saw_stop) return error.InvalidScheme;
        return self;
    }

    pub fn destroy(self: *Scheme, alloc: Allocator) void {
        alloc.free(self.raw);
        alloc.destroy(self);
    }

    /// Flattened per-packet size list, `check_mark` for "c".
    pub fn sizesFor(self: *const Scheme, pkt_in: u32, out: *[max_entries]u32) []u32 {
        if (pkt_in >= max_pkts) return out[0..0];
        const pkt: usize = @intCast(pkt_in);
        const count = self.counts[pkt];
        for (0..count) |i| {
            out[i] = switch (self.entries[pkt][i]) {
                .check => check_mark,
                .range => |r| if (r.min == r.max)
                    r.min
                else
                    r.min + std.crypto.random.intRangeLessThan(u32, 0, r.max - r.min),
            };
        }
        return out[0..count];
    }

    /// padding0 length for the auth packet: first size of packet 0.
    pub fn authPadLen(self: *const Scheme) u16 {
        var out: [max_entries]u32 = undefined;
        const sizes = self.sizesFor(0, &out);
        for (sizes) |s| {
            if (s != check_mark) return @intCast(@min(s, 4096));
        }
        return 0;
    }

    pub fn md5Hex(self: *const Scheme, out: *[32]u8) void {
        hexLower(&self.md5, out);
    }
};

pub fn hexLower(bytes: []const u8, out: []u8) void {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0xf];
    }
}

pub fn buildSettings(out: []u8, scheme: *const Scheme) []u8 {
    var hex: [32]u8 = undefined;
    scheme.md5Hex(&hex);
    return std.fmt.bufPrint(out, "v={d}\nclient={s}\npadding-md5={s}", .{
        protocol_version, client_name, hex,
    }) catch unreachable;
}

/// Extract an integer value for `key` from a "k=v\nk=v" blob (server settings).
pub fn parseKVInt(data: []const u8, key: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line_raw| {
        const line = std.mem.trimRight(u8, line_raw, "\r");
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (!std.mem.eql(u8, line[0..eq], key)) continue;
        return std.fmt.parseInt(u32, line[eq + 1 ..], 10) catch null;
    }
    return null;
}
