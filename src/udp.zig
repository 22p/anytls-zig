//! SOCKS5 UDP ASSOCIATE relay over AnyTLS.
//!
//! AnyTLS has no native datagram transport, so UDP is carried the way the
//! reference client does: one AnyTLS stream per destination, opened to the
//! magic target `sp.v2.udp-over-tcp.arpa` and speaking sing-box
//! udp-over-tcp v2 (isConnect mode). Each datagram on that stream is a
//! 2-byte big-endian length followed by the payload.

const std = @import("std");
const posix = std.posix;
const anytls = @import("anytls.zig");
const proto = @import("protocol.zig");
const log = @import("log.zig");

const uot_magic = "sp.v2.udp-over-tcp.arpa";
const max_destinations = 64;
const idle_timeout_ms: i64 = 5 * 60 * 1000;
const max_datagram = 65535;
/// sing-box's UoT reader allocates buf.UDPBufferSize (16 KiB standard, 8 KiB on
/// low-memory builds); larger datagrams make the server close the stream.
const max_uot_payload = 16 * 1024;
const header_max = 3 + 1 + 255 + 2;

/// Destination key: SOCKS5 address type (1/3/4), address bytes, port.
pub const Key = struct {
    atyp: u8 = 0,
    addr: [16]u8 = @splat(0),
    dlen: u8 = 0,
    port: u16 = 0,
};

const UotConn = struct {
    assoc: *Assoc,
    key: Key,
    stream: *anytls.Stream,
    thread: std.Thread = undefined,
    finished: std.atomic.Value(bool),
};

const Assoc = struct {
    client: *anytls.Client,
    alloc: std.mem.Allocator,
    udp_fd: posix.socket_t,
    peer_ip: [16]u8,
    peer_v6: bool,
    peer_mutex: std.Thread.Mutex = .{},
    peer_sa: posix.sockaddr.storage = undefined,
    peer_len: posix.socklen_t = 0,
    peer_set: bool = false,
    conns: std.AutoHashMapUnmanaged(Key, *UotConn) = .empty,

    fn handlePacket(self: *Assoc, data: []const u8, src: *const posix.sockaddr, src_len: posix.socklen_t) void {
        const src_ip = ipOf(src) orelse return;
        if (src_ip.v6 != self.peer_v6) return;
        if (!std.mem.eql(u8, src_ip.bytes[0..src_ip.len], self.peer_ip[0..src_ip.len])) return;

        self.peer_mutex.lock();
        const copy_len: usize = @min(@as(usize, src_len), @sizeOf(posix.sockaddr.storage));
        @memset(std.mem.asBytes(&self.peer_sa), 0);
        @memcpy(std.mem.asBytes(&self.peer_sa)[0..copy_len], std.mem.asBytes(src)[0..copy_len]);
        self.peer_len = src_len;
        self.peer_set = true;
        self.peer_mutex.unlock();

        const pkt = parseUdpPacket(data) catch return;
        if (pkt.payload.len > max_uot_payload) {
            log.debug("udp: datagram of {d} bytes exceeds UoT limit, dropping", .{pkt.payload.len});
            return;
        }

        if (self.conns.get(pkt.key)) |conn| {
            if (conn.finished.load(.acquire)) return;
            writeDatagram(conn, pkt.payload) catch conn.stream.closeNow();
            return;
        }
        if (self.conns.count() >= max_destinations) {
            log.debug("udp: too many destinations, dropping packet", .{});
            return;
        }
        self.openConn(pkt.key, pkt.payload) catch |e| {
            log.warn("udp: opening stream failed: {s}", .{@errorName(e)});
        };
    }

    fn openConn(self: *Assoc, key: Key, payload: []const u8) !void {
        const stream = try self.client.openStream(.{ .domain = uot_magic }, 0);
        errdefer anytls.streamFinished(stream);

        var req_buf: [1 + 1 + 1 + 255 + 2]u8 = undefined;
        try streamWriteAll(stream, buildUotRequest(&req_buf, key));

        const conn = try self.alloc.create(UotConn);
        conn.* = .{
            .assoc = self,
            .key = key,
            .stream = stream,
            .finished = std.atomic.Value(bool).init(false),
        };

        conn.thread = std.Thread.spawn(
            .{ .stack_size = 128 * 1024 },
            replyLoop,
            .{conn},
        ) catch |e| {
            self.alloc.destroy(conn);
            return e;
        };

        self.conns.put(self.alloc, key, conn) catch |e| {
            // The thread owns no other references yet; stop it and unwind.
            conn.stream.closeNow();
            conn.thread.join();
            self.alloc.destroy(conn);
            return e;
        };

        var show_buf: [96]u8 = undefined;
        log.debug("udp: stream {d} -> {s}", .{ stream.id, formatKey(&key, &show_buf) });

        writeDatagram(conn, payload) catch |e| {
            conn.stream.closeNow();
            return e;
        };
    }

    /// Join and free connections whose reply thread has exited.
    fn reap(self: *Assoc) void {
        var dead: [max_destinations]Key = undefined;
        var n: usize = 0;
        var it = self.conns.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.finished.load(.acquire) and n < dead.len) {
                dead[n] = entry.key_ptr.*;
                n += 1;
            }
        }
        for (dead[0..n]) |key| {
            const kv = self.conns.fetchRemove(key) orelse continue;
            const conn = kv.value;
            conn.thread.join();
            anytls.streamFinished(conn.stream);
            self.alloc.destroy(conn);
        }
    }

    fn deinit(self: *Assoc) void {
        var conns: [max_destinations]*UotConn = undefined;
        var n: usize = 0;
        var it = self.conns.valueIterator();
        while (it.next()) |cp| {
            if (n < conns.len) {
                conns[n] = cp.*;
                n += 1;
            }
        }
        for (conns[0..n]) |conn| conn.stream.closeNow();
        for (conns[0..n]) |conn| {
            conn.thread.join();
            anytls.streamFinished(conn.stream);
            self.alloc.destroy(conn);
        }
        self.conns.deinit(self.alloc);
    }
};

pub fn run(client: *anytls.Client, tcp_fd: posix.socket_t) void {
    const alloc = client.alloc;

    var local: posix.sockaddr.storage = undefined;
    var llen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(tcp_fd, @ptrCast(&local), &llen) catch return;

    const family = local.family;
    if (family != posix.AF.INET and family != posix.AF.INET6) {
        replyError(tcp_fd, 0x08);
        return;
    }

    const udp_fd = posix.socket(family, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, posix.IPPROTO.UDP) catch |e| {
        log.warn("udp: cannot create socket: {s}", .{@errorName(e)});
        replyError(tcp_fd, 0x01);
        return;
    };
    defer posix.close(udp_fd);

    // Bind to the address the client reached us on, with an ephemeral port.
    var bind_sa = local;
    switch (family) {
        posix.AF.INET => {
            const in: *posix.sockaddr.in = @ptrCast(&bind_sa);
            in.port = 0;
        },
        posix.AF.INET6 => {
            const in6: *posix.sockaddr.in6 = @ptrCast(&bind_sa);
            in6.port = 0;
        },
        else => unreachable,
    }
    posix.bind(udp_fd, @ptrCast(&bind_sa), llen) catch |e| {
        log.warn("udp: bind failed: {s}", .{@errorName(e)});
        replyError(tcp_fd, 0x01);
        return;
    };

    var bound: posix.sockaddr.storage = undefined;
    var blen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(udp_fd, @ptrCast(&bound), &blen) catch return;
    writeAssociateReply(tcp_fd, @ptrCast(&bound)) catch return;

    var peer: posix.sockaddr.storage = undefined;
    var plen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getpeername(tcp_fd, @ptrCast(&peer), &plen) catch return;
    const peer_ip = ipOf(@ptrCast(&peer)) orelse return;

    var assoc: Assoc = .{
        .client = client,
        .alloc = alloc,
        .udp_fd = udp_fd,
        .peer_ip = peer_ip.bytes,
        .peer_v6 = peer_ip.v6,
    };
    defer assoc.deinit();

    var show_buf: [96]u8 = undefined;
    log.info("socks: UDP associate on {s}", .{formatSockaddr(&show_buf, @ptrCast(&bound))});

    var buf: [max_datagram]u8 = undefined;
    var last_ms = std.time.milliTimestamp();
    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = udp_fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = tcp_fd, .events = posix.POLL.IN, .revents = 0 },
        };
        _ = posix.poll(&fds, 500) catch break;

        if (fds[1].revents != 0) {
            // The TCP control connection ending terminates the association.
            var tmp: [64]u8 = undefined;
            const n = posix.recv(tcp_fd, &tmp, 0) catch 0;
            if (n == 0) break;
        }
        if (fds[0].revents != 0) {
            var src: posix.sockaddr.storage = undefined;
            var slen: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
            const n = posix.recvfrom(udp_fd, &buf, 0, @ptrCast(&src), &slen) catch 0;
            if (n > 0) {
                last_ms = std.time.milliTimestamp();
                assoc.handlePacket(buf[0..n], @ptrCast(&src), slen);
            }
        }
        assoc.reap();
        if (std.time.milliTimestamp() - last_ms > idle_timeout_ms) {
            log.debug("udp: association idle timeout", .{});
            break;
        }
    }
}

fn replyLoop(conn: *UotConn) void {
    defer conn.finished.store(true, .release);
    const assoc = conn.assoc;
    const buf = assoc.alloc.alloc(u8, header_max + max_datagram) catch return;
    defer assoc.alloc.free(buf);

    while (true) {
        if (!readExact(conn.stream, buf[0..2])) return;
        const n: usize = std.mem.readInt(u16, buf[0..2], .big);
        if (!readExact(conn.stream, buf[header_max..][0..n])) return;

        const hdr = buildSocksUdpHeader(buf[0..header_max], conn.key);
        if (hdr.len == 0) return;
        // Move the payload next to the header so one sendto() covers both.
        const payload = buf[header_max..][0..n];
        std.mem.copyForwards(u8, buf[hdr.len..][0..n], payload);

        assoc.peer_mutex.lock();
        const sa = assoc.peer_sa;
        const sa_len = assoc.peer_len;
        const have_peer = assoc.peer_set;
        assoc.peer_mutex.unlock();
        if (!have_peer) continue;

        _ = posix.sendto(assoc.udp_fd, buf[0..][0 .. hdr.len + n], posix.MSG.NOSIGNAL, @ptrCast(&sa), sa_len) catch {};
    }
}

fn writeDatagram(conn: *UotConn, payload: []const u8) !void {
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(payload.len), .big);
    try streamWriteAll(conn.stream, &len_buf);
    try streamWriteAll(conn.stream, payload);
}

fn streamWriteAll(stream: *anytls.Stream, data: []const u8) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = @min(data.len - off, proto.max_data_chunk);
        try stream.write(data[off..][0..n]);
        off += n;
    }
}

fn readExact(stream: *anytls.Stream, out: []u8) bool {
    var i: usize = 0;
    while (i < out.len) {
        const n = stream.read(out[i..]) orelse return false;
        if (n == 0) continue;
        i += n;
    }
    return true;
}

pub const Parsed = struct {
    key: Key,
    payload: []const u8,
};

pub fn parseUdpPacket(data: []const u8) !Parsed {
    if (data.len < 4) return error.ShortPacket;
    if (data[0] != 0 or data[1] != 0) return error.BadReserved;
    if (data[2] != 0) return error.Fragmented;

    var key: Key = .{};
    var off: usize = 4;
    switch (data[3]) {
        1 => {
            if (data.len < off + 4 + 2) return error.ShortPacket;
            key.atyp = 1;
            @memcpy(key.addr[0..4], data[off..][0..4]);
            off += 4;
        },
        4 => {
            if (data.len < off + 16 + 2) return error.ShortPacket;
            key.atyp = 4;
            @memcpy(key.addr[0..16], data[off..][0..16]);
            off += 16;
        },
        3 => {
            if (data.len < off + 1) return error.ShortPacket;
            const l = data[off];
            off += 1;
            if (l == 0 or data.len < off + l + 2) return error.ShortPacket;
            key.atyp = 3;
            key.dlen = l;
            @memcpy(key.addr[0..l], data[off..][0..l]);
            off += l;
        },
        else => return error.BadAddressType,
    }
    key.port = std.mem.readInt(u16, data[off..][0..2], .big);
    off += 2;
    return .{ .key = key, .payload = data[off..] };
}

pub fn buildUotRequest(out: []u8, key: Key) []u8 {
    // isConnect: this stream is bound to one destination. The request address
    // uses the standard SOCKS5 address family bytes (1/3/4), not the 0/1/2
    // mapping used for per-packet addresses in non-connect mode.
    out[0] = 1;
    var n: usize = 1;
    switch (key.atyp) {
        1 => {
            out[n] = 1;
            n += 1;
            @memcpy(out[n..][0..4], key.addr[0..4]);
            n += 4;
        },
        4 => {
            out[n] = 4;
            n += 1;
            @memcpy(out[n..][0..16], key.addr[0..16]);
            n += 16;
        },
        3 => {
            out[n] = 3;
            n += 1;
            out[n] = key.dlen;
            n += 1;
            @memcpy(out[n..][0..key.dlen], key.addr[0..key.dlen]);
            n += key.dlen;
        },
        else => return out[0..0],
    }
    std.mem.writeInt(u16, out[n..][0..2], key.port, .big);
    return out[0 .. n + 2];
}

pub fn buildSocksUdpHeader(out: []u8, key: Key) []u8 {
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    var n: usize = 3;
    switch (key.atyp) {
        1 => {
            out[3] = 1;
            @memcpy(out[4..8], key.addr[0..4]);
            n = 8;
        },
        4 => {
            out[3] = 4;
            @memcpy(out[4..20], key.addr[0..16]);
            n = 20;
        },
        3 => {
            out[3] = 3;
            out[4] = key.dlen;
            @memcpy(out[5..][0..key.dlen], key.addr[0..key.dlen]);
            n = 5 + key.dlen;
        },
        else => return out[0..0],
    }
    std.mem.writeInt(u16, out[n..][0..2], key.port, .big);
    return out[0 .. n + 2];
}

const IpInfo = struct {
    bytes: [16]u8,
    len: usize,
    v6: bool,
};

fn ipOf(sa: *const posix.sockaddr) ?IpInfo {
    switch (sa.family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
            var out: [16]u8 = @splat(0);
            @memcpy(out[0..4], std.mem.asBytes(&in.addr));
            return .{ .bytes = out, .len = 4, .v6 = false };
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            return .{ .bytes = in6.addr, .len = 16, .v6 = true };
        },
        else => return null,
    }
}

fn formatSockaddr(buf: []u8, sa: *const posix.sockaddr) []const u8 {
    switch (sa.family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
            const b = std.mem.asBytes(&in.addr);
            return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
                b[0], b[1], b[2], b[3], std.mem.bigToNative(u16, in.port),
            }) catch "udp";
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            return std.fmt.bufPrint(buf, "[udp6]:{d}", .{std.mem.bigToNative(u16, in6.port)}) catch "udp6";
        },
        else => return "udp",
    }
}

fn formatKey(key: *const Key, buf: []u8) []const u8 {
    switch (key.atyp) {
        1 => return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            key.addr[0], key.addr[1], key.addr[2], key.addr[3], key.port,
        }) catch "udp",
        4 => return std.fmt.bufPrint(buf, "[udp6]:{d}", .{key.port}) catch "udp6",
        3 => return std.fmt.bufPrint(buf, "{s}:{d}", .{ key.addr[0..key.dlen], key.port }) catch "udp",
        else => return "udp",
    }
}

fn writeAssociateReply(tcp_fd: posix.socket_t, sa: *const posix.sockaddr) !void {
    var out: [3 + 1 + 16 + 2]u8 = undefined;
    out[0] = 5;
    out[1] = 0;
    out[2] = 0;
    var n: usize = 3;
    switch (sa.family) {
        posix.AF.INET => {
            const in: *const posix.sockaddr.in = @ptrCast(@alignCast(sa));
            out[3] = 1;
            @memcpy(out[4..8], std.mem.asBytes(&in.addr));
            n = 8;
            std.mem.writeInt(u16, out[n..][0..2], std.mem.bigToNative(u16, in.port), .big);
            n += 2;
        },
        posix.AF.INET6 => {
            const in6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(sa));
            out[3] = 4;
            @memcpy(out[4..20], &in6.addr);
            n = 20;
            std.mem.writeInt(u16, out[n..][0..2], std.mem.bigToNative(u16, in6.port), .big);
            n += 2;
        },
        else => return error.BadAddressType,
    }
    try writeAll(tcp_fd, out[0..n]);
}

fn replyError(tcp_fd: posix.socket_t, code: u8) void {
    writeAll(tcp_fd, &.{ 5, code, 0, 1, 0, 0, 0, 0, 0, 0 }) catch {};
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var i: usize = 0;
    while (i < data.len) {
        const n = try posix.send(fd, data[i..], posix.MSG.NOSIGNAL);
        i += n;
    }
}
