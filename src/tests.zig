const std = @import("std");
const testing = std.testing;
const proto = @import("protocol.zig");
const Pipe = @import("pipe.zig").Pipe;
const toml = @import("toml.zig");
const config = @import("config.zig");
const log = @import("log.zig");

test "frame header roundtrip" {
    var h: [proto.header_len]u8 = undefined;
    proto.encodeHeader(&h, .psh, 0x01020304, 0x0506);
    try testing.expectEqualSlices(u8, &.{ 2, 1, 2, 3, 4, 5, 6 }, &h);
    const d = proto.decodeHeader(h);
    try testing.expectEqual(@as(u8, 2), d.cmd);
    try testing.expectEqual(@as(u32, 0x01020304), d.sid);
    try testing.expectEqual(@as(u16, 0x0506), d.len);
}

test "target encoding matches SOCKS5 address format" {
    var buf: [64]u8 = undefined;

    const v4 = try proto.encodeTarget(&buf, .{ .ip4 = .{ 1, 2, 3, 4 } }, 443);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 2, 3, 4, 1, 187 }, v4);

    const dom = try proto.encodeTarget(&buf, .{ .domain = "example.com" }, 80);
    try testing.expectEqual(@as(u8, 3), dom[0]);
    try testing.expectEqual(@as(u8, 11), dom[1]);
    try testing.expectEqualSlices(u8, "example.com", dom[2..13]);
    try testing.expectEqualSlices(u8, &.{ 0, 80 }, dom[13..15]);

    const v6 = try proto.encodeTarget(&buf, .{ .ip6 = @splat(0) }, 1);
    try testing.expectEqual(@as(usize, 19), v6.len);
    try testing.expectEqual(@as(u8, 4), v6[0]);
}

test "default padding scheme matches anytls-go md5 and structure" {
    const s = try proto.Scheme.parse(testing.allocator, proto.default_scheme_raw);
    defer s.destroy(testing.allocator);

    var hex: [32]u8 = undefined;
    s.md5Hex(&hex);
    try testing.expectEqualStrings("75cff2ad89aadf5e257059ee571ebe11", &hex);
    try testing.expectEqual(@as(u32, 8), s.stop);
    var prng = std.Random.DefaultPrng.init(0x12345678);
    const rng = prng.random();
    try testing.expectEqual(@as(u16, 30), s.authPadLen(rng));

    var out: [proto.max_entries]u32 = undefined;
    const p1 = s.sizesFor(rng, 1, &out);
    try testing.expectEqual(@as(usize, 1), p1.len);
    try testing.expect(p1[0] >= 100 and p1[0] < 400);

    const p2 = s.sizesFor(rng, 2, &out);
    try testing.expectEqual(@as(usize, 9), p2.len);
    try testing.expectEqual(proto.check_mark, p2[1]);
    try testing.expect(p2[0] >= 400 and p2[0] < 500);

    const p3 = s.sizesFor(rng, 3, &out);
    try testing.expectEqual(@as(u32, 9), p3[0]);
}

test "invalid padding schemes are rejected" {
    try testing.expectError(error.InvalidScheme, proto.Scheme.parse(testing.allocator, "0=10-20"));
    try testing.expectError(error.InvalidScheme, proto.Scheme.parse(testing.allocator, "stop=abc"));
    try testing.expectError(error.InvalidScheme, proto.Scheme.parse(testing.allocator, ""));
}

test "custom scheme ignores unknown keys and bad ranges" {
    const s = try proto.Scheme.parse(testing.allocator, "stop=3\nfoo=bar\n0=100-100\n1=50-60,c,abc,70-70\n2=x-y");
    defer s.destroy(testing.allocator);
    var out: [proto.max_entries]u32 = undefined;
    var prng2 = std.Random.DefaultPrng.init(0xabcdef);
    const s1 = s.sizesFor(prng2.random(), 1, &out);
    try testing.expectEqual(@as(usize, 3), s1.len);
    try testing.expectEqual(@as(u32, proto.check_mark), s1[1]);
    try testing.expectEqual(@as(u32, 70), s1[2]);
    try testing.expectEqual(@as(usize, 0), s.sizesFor(prng2.random(), 2, &out).len);
}

test "settings blob carries protocol version and scheme md5" {
    const s = try proto.Scheme.parse(testing.allocator, proto.default_scheme_raw);
    defer s.destroy(testing.allocator);
    var buf: [160]u8 = undefined;
    const b = proto.buildSettings(&buf, s);
    try testing.expect(std.mem.startsWith(u8, b, "v=2\n"));
    try testing.expect(std.mem.endsWith(u8, b, "padding-md5=75cff2ad89aadf5e257059ee571ebe11"));
    try testing.expect(proto.parseKVInt(b, "v") == 2);
}

test "server key/value parsing" {
    try testing.expectEqual(@as(?u32, 2), proto.parseKVInt("v=2\n", "v"));
    try testing.expectEqual(@as(?u32, null), proto.parseKVInt("v=abc", "v"));
    try testing.expectEqual(@as(?u32, null), proto.parseKVInt("", "v"));
}

test "bounded pipe preserves order and reports EOF" {
    var p = try Pipe.init(testing.allocator, testing.io, 8);
    defer p.deinit(testing.allocator);

    try p.write("abcdefgh");
    var a: [3]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), p.read(&a).?);
    try testing.expectEqualSlices(u8, "abc", &a);

    p.setEof();
    var b: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), p.read(&b).?);
    try testing.expectEqualSlices(u8, "defgh", b[0..5]);
    try testing.expectEqual(@as(?usize, null), p.read(&b));
}

test "pipe abort discards data and wakes readers" {
    var p = try Pipe.init(testing.allocator, testing.io, 8);
    defer p.deinit(testing.allocator);
    try p.write("xyz");
    p.abort();
    var b: [8]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), p.read(&b));
    try testing.expect(p.wasAborted());
}

test "toml: tables, strings, integers, booleans and comments" {
    const text =
        \\# sample
        \\[server]
        \\address = "example.com:443"   # trailing comment
        \\sni = 'example.com'
        \\insecure = false
        \\connect_timeout = 10
        \\
        \\[log]
        \\level = "debug"
    ;
    var diag: toml.Diag = .{};
    const t = try toml.parse(testing.allocator, text, &diag);
    defer @constCast(&t).deinit();

    try testing.expectEqualStrings("example.com:443", t.get("server", "address").?.string);
    try testing.expectEqualStrings("example.com", t.get("server", "sni").?.string);
    try testing.expectEqual(false, t.get("server", "insecure").?.boolean);
    try testing.expectEqual(@as(i64, 10), t.get("server", "connect_timeout").?.integer);
    try testing.expectEqualStrings("debug", t.get("log", "level").?.string);
}

test "toml: escapes and underscores in integers" {
    var diag: toml.Diag = .{};
    const t = try toml.parse(testing.allocator, "x = \"a\\tb\\u4e2d\"\ny = 1_000\n", &diag);
    defer @constCast(&t).deinit();
    try testing.expectEqualStrings("a\tb中", t.get("", "x").?.string);
    try testing.expectEqual(@as(i64, 1000), t.get("", "y").?.integer);
}

test "toml: rejects unsupported and malformed input" {
    var diag: toml.Diag = .{};
    try testing.expectError(error.Syntax, toml.parse(testing.allocator, "a = [1, 2]\n", &diag));
    try testing.expectError(error.Syntax, toml.parse(testing.allocator, "a = \"unterminated\n", &diag));
    try testing.expectError(error.Syntax, toml.parse(testing.allocator, "[server\na = 1\n", &diag));
    try testing.expectError(error.Syntax, toml.parse(testing.allocator, "a = 1 trailing\n", &diag));
}

test "toml: duplicate keys are rejected" {
    var diag: toml.Diag = .{};
    try testing.expectError(error.DuplicateKey, toml.parse(testing.allocator, "a = 1\na = 2\n", &diag));
}

test "config: table mapping and precedence" {
    const text =
        \\[listen]
        \\address = "0.0.0.0:1080"
        \\[server]
        \\address = "example.com:443"
        \\password = "s3cret"
        \\connect_timeout = 7
        \\[session]
        \\min_idle = 2
        \\[log]
        \\level = "warn"
    ;
    var diag: toml.Diag = .{};
    const t = try toml.parse(testing.allocator, text, &diag);
    defer @constCast(&t).deinit();
    const file = try config.overridesFromTable(&t, &diag);

    var cli: config.Overrides = .{};
    cli.listen = "127.0.0.1:9050";
    cli.level = .debug;
    const cfg = config.merge(cli, file);
    try testing.expectEqualStrings("127.0.0.1:9050", cfg.listen);
    try testing.expectEqualStrings("example.com:443", cfg.server);
    try testing.expectEqual(@as(u32, 7), cfg.connect_timeout_s);
    try testing.expectEqual(@as(usize, 2), cfg.min_idle);
    try testing.expectEqual(log.Level.debug, cfg.level);
    try testing.expectEqualStrings("s3cret", cfg.password.literal);
}

test "config: unknown key and bad types are reported" {
    var diag: toml.Diag = .{};
    const t1 = try toml.parse(testing.allocator, "[server]\naddress = 5\n", &diag);
    defer @constCast(&t1).deinit();
    try testing.expectError(error.InvalidValue, config.overridesFromTable(&t1, &diag));

    var diag2: toml.Diag = .{};
    const t2 = try toml.parse(testing.allocator, "[server]\nnope = \"x\"\n", &diag2);
    defer @constCast(&t2).deinit();
    try testing.expectError(error.UnknownKey, config.overridesFromTable(&t2, &diag2));
    try testing.expectEqualStrings("server.nope", diag2.key);
}

test "shipped example config parses and maps" {
    const text = try std.Io.Dir.cwd().readFileAlloc(testing.io, "config/anytls-zig.toml", testing.allocator, .limited(64 * 1024));
    defer testing.allocator.free(text);
    var diag: toml.Diag = .{};
    const t = try toml.parse(testing.allocator, text, &diag);
    defer @constCast(&t).deinit();
    const ov = try config.overridesFromTable(&t, &diag);
    try testing.expectEqualStrings("example.com:443", ov.server.?);
    try testing.expectEqualStrings("127.0.0.1:1080", ov.listen.?);
    try testing.expectEqualStrings("change-me", ov.password.?);
    try testing.expectEqual(@as(usize, 5), ov.min_idle.?);
    try testing.expectEqual(log.Level.info, ov.level.?);
}
