const std = @import("std");
const testing = std.testing;
const proto = @import("protocol.zig");
const Pipe = @import("pipe.zig").Pipe;
const toml = @import("toml.zig");
const config = @import("config.zig");
const log = @import("log.zig");
const udp = @import("udp.zig");
const http = @import("http.zig");

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

    const v6 = try proto.encodeTarget(&buf, .{ .ip6 = [_]u8{0} ** 16 }, 1);
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
    try testing.expectEqual(@as(u16, 30), s.authPadLen());

    var out: [proto.max_entries]u32 = undefined;
    const p1 = s.sizesFor(1, &out);
    try testing.expectEqual(@as(usize, 1), p1.len);
    try testing.expect(p1[0] >= 100 and p1[0] < 400);

    const p2 = s.sizesFor(2, &out);
    try testing.expectEqual(@as(usize, 9), p2.len);
    try testing.expectEqual(proto.check_mark, p2[1]);
    try testing.expect(p2[0] >= 400 and p2[0] < 500);

    const p3 = s.sizesFor(3, &out);
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
    const s1 = s.sizesFor(1, &out);
    try testing.expectEqual(@as(usize, 3), s1.len);
    try testing.expectEqual(@as(u32, proto.check_mark), s1[1]);
    try testing.expectEqual(@as(u32, 70), s1[2]);
    try testing.expectEqual(@as(usize, 0), s.sizesFor(2, &out).len);
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
    var p = try Pipe.init(testing.allocator, 8);
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
    var p = try Pipe.init(testing.allocator, 8);
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
    const text = try std.fs.cwd().readFileAlloc(testing.allocator, "config/anytls-zig.toml", 64 * 1024);
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

test "socks5 udp packet parse and rebuild" {
    // RSV RSV FRAG ATYP=1 1.2.3.4 :53 "hi"
    const pkt = [_]u8{ 0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 'h', 'i' };
    const p = try udp.parseUdpPacket(&pkt);
    try testing.expectEqual(@as(u8, 1), p.key.atyp);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, p.key.addr[0..4]);
    try testing.expectEqual(@as(u16, 53), p.key.port);
    try testing.expectEqualStrings("hi", p.payload);

    var hdr: [64]u8 = undefined;
    const out = udp.buildSocksUdpHeader(&hdr, p.key);
    try testing.expectEqualSlices(u8, pkt[0..10], out);

    try testing.expectError(error.Fragmented, udp.parseUdpPacket(&.{ 0, 0, 1, 1, 1, 2, 3, 4, 0, 53 }));
    try testing.expectError(error.ShortPacket, udp.parseUdpPacket(&.{ 0, 0, 0, 1, 1, 2, 3 }));
}

test "uot request encodes address families for udp-over-tcp v2" {
    var buf: [300]u8 = undefined;

    var v4_key: udp.Key = .{ .atyp = 1, .port = 53 };
    v4_key.addr[0..4].* = .{ 9, 8, 7, 6 };
    const v4 = udp.buildUotRequest(&buf, v4_key);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 9, 8, 7, 6, 0, 53 }, v4);

    var dom_key: udp.Key = .{ .atyp = 3, .dlen = 11, .port = 5353 };
    @memcpy(dom_key.addr[0..11], "dns.example");
    const dom = udp.buildUotRequest(&buf, dom_key);
    try testing.expectEqual(@as(u8, 1), dom[0]);
    try testing.expectEqual(@as(u8, 0x03), dom[1]);
    try testing.expectEqual(@as(u8, 11), dom[2]);
    try testing.expectEqualStrings("dns.example", dom[3..14]);
    try testing.expectEqual(@as(u16, 5353), std.mem.readInt(u16, dom[14..16], .big));
}

test "http request head parsing" {
    const req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const head = try http.parseHead(req, req.len);
    try testing.expectEqualStrings("CONNECT", head.method);
    try testing.expectEqualStrings("example.com:443", head.target);
    try testing.expectEqualStrings("HTTP/1.1", head.version);
    try testing.expectEqual(@as(usize, req.len), head.end);

    const bad = "GET / HTTP/1.1";
    try testing.expectError(error.BadRequest, http.parseHead(bad, bad.len));
}

test "http absolute uri and forward rewrite" {
    const req = "GET http://example.com:8080/a/b?q=1 HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Proxy-Connection: keep-alive\r\n" ++
        "Proxy-Authorization: Basic xx\r\n" ++
        "User-Agent: t\r\n\r\n" ++
        "BODY";
    const end = std.mem.indexOf(u8, req, "\r\n\r\n").? + 4;
    const head = try http.parseHead(req, end);
    try testing.expectEqualStrings("BODY", head.full[head.end..]);

    const uri = try http.parseAbsoluteUri(head.target);
    try testing.expectEqualStrings("example.com", uri.hp.host);
    try testing.expectEqual(@as(u16, 8080), uri.hp.port);
    try testing.expectEqualStrings("/a/b?q=1", uri.path);

    var out: [512]u8 = undefined;
    const fwd = try http.buildForwardRequest(&out, head, uri.path);
    try testing.expectEqualStrings(
        "GET /a/b?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n",
        fwd,
    );
}

test "http bare query gets a slash and origin-form uses Host" {
    const q = "GET http://ex.test?q=1 HTTP/1.1\r\nHost: ex.test\r\n\r\n";
    const qend = q.len;
    const qhead = try http.parseHead(q, qend);
    const uri = try http.parseAbsoluteUri(qhead.target);
    try testing.expectEqualStrings("?q=1", uri.path);
    var out: [256]u8 = undefined;
    const fwd = try http.buildForwardRequest(&out, qhead, uri.path);
    try testing.expectEqualStrings("GET /?q=1 HTTP/1.1\r\nHost: ex.test\r\n\r\n", fwd);

    const o = "GET /path HTTP/1.1\r\nHost: h.test:8080\r\n\r\n";
    const ohead = try http.parseHead(o, o.len);
    const hp = http.hostFromHeaders(ohead).?;
    try testing.expectEqualStrings("h.test", hp.host);
    try testing.expectEqual(@as(u16, 8080), hp.port);
}

test "socks5 udp packet accepts a long domain name" {
    const name = "very-long.example-domain-name.test";
    var pkt: [300]u8 = undefined;
    pkt[0] = 0;
    pkt[1] = 0;
    pkt[2] = 0;
    pkt[3] = 3;
    pkt[4] = name.len;
    @memcpy(pkt[5..][0..name.len], name);
    const port_off = 5 + name.len;
    std.mem.writeInt(u16, pkt[port_off..][0..2], 53, .big);
    pkt[port_off + 2] = 'h';
    pkt[port_off + 3] = 'i';
    const p = try udp.parseUdpPacket(pkt[0 .. port_off + 4]);
    try testing.expectEqual(@as(u8, 3), p.key.atyp);
    try testing.expectEqual(@as(u8, name.len), p.key.dlen);
    try testing.expectEqualStrings(name, p.key.addr[0..p.key.dlen]);
    try testing.expectEqualStrings("hi", p.payload);
}

test "socks5 udp header fits the longest domain" {
    var key: udp.Key = .{ .atyp = 3, .dlen = 255, .port = 53 };
    @memset(key.addr[0..255], 'a');
    var out: [300]u8 = undefined;
    const hdr = udp.buildSocksUdpHeader(out[0..udp.header_max], key);
    try testing.expectEqual(@as(usize, 262), hdr.len);
}
