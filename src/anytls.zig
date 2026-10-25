//! AnyTLS protocol v2 client: authentication, session multiplexing, padding,
//! stream lifecycle and idle-session pool. Behaviour mirrors anytls-go 0.0.13.

const std = @import("std");
const tlsm = @import("tls.zig");
const proto = @import("protocol.zig");
const Pipe = @import("pipe.zig").Pipe;
const log = @import("log.zig");

const Allocator = std.mem.Allocator;

pub const Config = struct {
    host: []const u8,
    port: u16,
    sni: []const u8,
    password_sha256: [32]u8,
    ca: ?*std.crypto.Certificate.Bundle = null,
    insecure: bool = false,
    connect_timeout_ms: u32 = 10_000,
    idle_timeout_ms: i64 = 30_000,
    min_idle: usize = 5,
    max_streams_per_session: usize = 128,
    syn_timeout_ms: i64 = 3_000,
};

pub const stream_buffer_size = 16 * 1024;

const max_pad = 4096;
const scratch_size = proto.header_len + proto.max_data_chunk + proto.header_len + max_pad;
const pool_size = 64;

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

pub const Stream = struct {
    session: *Session,
    id: u32,
    /// creator + session map (+ one per relay thread)
    refs: std.atomic.Value(u32),
    pipe: Pipe,
    fin_sent: std.atomic.Value(bool),
    closed: std.atomic.Value(bool),
    in_map: bool = true, // guarded by session.streams_mutex
    /// 0 = awaiting SYNACK, 1 = ok, 2 = failed
    synack: std.atomic.Value(u8),
    syn_deadline_ms: i64 = 0,

    fn create(session: *Session, id: u32) !*Stream {
        const alloc = session.client.alloc;
        const self = try alloc.create(Stream);
        errdefer alloc.destroy(self);
        self.* = .{
            .session = session,
            .id = id,
            .refs = std.atomic.Value(u32).init(1),
            .pipe = try Pipe.init(alloc, stream_buffer_size),
            .fin_sent = std.atomic.Value(bool).init(false),
            .closed = std.atomic.Value(bool).init(false),
            .synack = std.atomic.Value(u8).init(0),
        };
        session.acquire();
        return self;
    }

    pub fn acquire(self: *Stream) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *Stream) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        // Capture the allocator before dropping the session reference: that
        // release may destroy the session, after which self.session is gone.
        const alloc = self.session.client.alloc;
        self.pipe.deinit(alloc);
        self.session.release();
        alloc.destroy(self);
    }

    /// Returns null on EOF/abort.
    pub fn read(self: *Stream, buf: []u8) ?usize {
        return self.pipe.read(buf);
    }

    pub fn write(self: *Stream, data: []const u8) !void {
        return self.session.writeData(self.id, data);
    }

    pub fn wasAborted(self: *Stream) bool {
        return self.pipe.wasAborted();
    }

    pub fn sessionSeq(self: *Stream) u64 {
        return self.session.seq;
    }

    /// Half close: tell the server this direction is done, keep reading.
    pub fn sendFin(self: *Stream) void {
        if (self.fin_sent.swap(true, .acq_rel)) return;
        self.session.writeControl(.fin, self.id, &.{}) catch |e| {
            log.debug("stream {d}: FIN write failed: {s}", .{ self.id, @errorName(e) });
            return;
        };
        log.debug("stream {d}: FIN sent", .{self.id});
    }

    /// Full teardown: FIN if not sent, drop from session map, wake consumer.
    pub fn closeNow(self: *Stream) void {
        if (self.closed.swap(true, .acq_rel)) return;
        if (!self.fin_sent.swap(true, .acq_rel)) {
            self.session.writeControl(.fin, self.id, &.{}) catch {};
        }
        if (self.session.removeStream(self.id)) |st| st.release();
        self.pipe.abort();
    }
};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

const Session = struct {
    client: *Client,
    conn: *tlsm.Conn,
    seq: u64,
    scheme: *const proto.Scheme,
    refs: std.atomic.Value(u32),
    dead: std.atomic.Value(bool),
    write_mutex: std.Thread.Mutex = .{},
    open_mutex: std.Thread.Mutex = .{},
    streams_mutex: std.Thread.Mutex = .{},
    streams: std.AutoHashMapUnmanaged(u32, *Stream) = .empty,
    next_sid: u32 = 1,
    started: bool = false,
    pkt_counter: u32 = 0,
    send_padding: bool = true,
    peer_version: std.atomic.Value(u8) = std.atomic.Value(u8).init(1),
    read_buf: []u8,
    scratch: []u8,
    reader_thread: std.Thread = undefined,
    in_pool: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    fn create(client: *Client, conn: *tlsm.Conn, seq: u64, scheme: *const proto.Scheme) !*Session {
        const alloc = client.alloc;
        const self = try alloc.create(Session);
        errdefer alloc.destroy(self);
        const read_buf = try alloc.alloc(u8, proto.max_data_chunk);
        errdefer alloc.free(read_buf);
        const scratch = try alloc.alloc(u8, scratch_size);
        errdefer alloc.free(scratch);

        self.* = .{
            .client = client,
            .conn = conn,
            .seq = seq,
            .scheme = scheme,
            .refs = std.atomic.Value(u32).init(1),
            .dead = std.atomic.Value(bool).init(false),
            .read_buf = read_buf,
            .scratch = scratch,
        };
        return self;
    }

    fn acquire(self: *Session) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *Session) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.conn.destroy();
        self.client.alloc.free(self.read_buf);
        self.client.alloc.free(self.scratch);
        self.streams.deinit(self.client.alloc);
        self.client.alloc.destroy(self);
    }

    fn isDead(self: *Session) bool {
        return self.dead.load(.acquire);
    }

    fn close(self: *Session) void {
        if (self.dead.swap(true, .acq_rel)) return;
        self.acquire();
        defer self.release();
        self.client.removeIdle(self);
        self.conn.shutdown();
        self.client.removeSession(self);

        self.streams_mutex.lock();
        var old = self.streams;
        self.streams = .empty;
        self.active.store(0, .release);
        var it0 = old.iterator();
        while (it0.next()) |e| e.value_ptr.*.in_map = false;
        self.streams_mutex.unlock();

        var it = old.iterator();
        while (it.next()) |e| {
            const st = e.value_ptr.*;
            st.pipe.abort();
            st.release(); // session-map reference
        }
        old.deinit(self.client.alloc);
    }

    fn removeStream(self: *Session, sid: u32) ?*Stream {
        self.streams_mutex.lock();
        defer self.streams_mutex.unlock();
        if (self.streams.fetchRemove(sid)) |kv| {
            kv.value.in_map = false;
            _ = self.active.fetchSub(1, .monotonic);
            return kv.value;
        }
        return null;
    }

    fn streamRef(self: *Session, sid: u32) ?*Stream {
        self.streams_mutex.lock();
        defer self.streams_mutex.unlock();
        const st = self.streams.get(sid) orelse return null;
        // Safe: the map's own reference cannot be dropped while we hold the lock.
        _ = st.refs.fetchAdd(1, .monotonic);
        return st;
    }

    fn openStream(self: *Session, target: proto.Target, port: u16) !*Stream {
        self.open_mutex.lock();
        defer self.open_mutex.unlock();
        if (self.isDead()) return error.SessionClosed;

        self.streams_mutex.lock();
        const active = self.streams.count();
        self.streams_mutex.unlock();
        if (active >= self.client.cfg.max_streams_per_session) return error.SessionBusy;

        const sid = self.next_sid;
        if (sid == std.math.maxInt(u32)) return error.SessionBusy;

        const stream = try Stream.create(self, sid);
        errdefer stream.release();
        try self.insertStream(sid, stream);
        errdefer if (self.removeStream(sid)) |st| st.release();

        if (self.isDead()) return error.SessionClosed;
        self.next_sid = sid + 1;

        if (!self.started) {
            // Packet 1: settings + SYN + PSH(target). One TLS write, as in the
            // reference client, so the first padding packet is shaped correctly.
            var settings_buf: [160]u8 = undefined;
            const sd = proto.buildSettings(&settings_buf, self.scheme);

            var off: usize = 0;
            proto.encodeHeader(self.scratch[0..proto.header_len], .settings, 0, sd.len);
            @memcpy(self.scratch[proto.header_len..][0..sd.len], sd);
            off = proto.header_len + sd.len;

            proto.encodeHeader(self.scratch[off..][0..proto.header_len], .syn, sid, 0);
            off += proto.header_len;

            const addr = try proto.encodeTarget(self.scratch[off + proto.header_len ..], target, port);
            proto.encodeHeader(self.scratch[off..][0..proto.header_len], .psh, sid, addr.len);
            off += proto.header_len + addr.len;

            self.started = true;
            log.debug("session {d}: first packet settings+syn+addr ({d} bytes)", .{ self.seq, off });
            try self.writeFrame(off);
            log.debug("session {d}: first packet flushed", .{self.seq});
        } else {
            try self.writeControl(.syn, sid, &.{});
            var abuf: [262]u8 = undefined;
            const addr = try proto.encodeTarget(&abuf, target, port);
            try self.writeData(sid, addr);
        }

        if (self.peer_version.load(.acquire) >= 2 and sid >= 2) {
            stream.syn_deadline_ms = std.time.milliTimestamp() + self.client.cfg.syn_timeout_ms;
        }
        return stream;
    }

    fn insertStream(self: *Session, sid: u32, stream: *Stream) !void {
        self.streams_mutex.lock();
        defer self.streams_mutex.unlock();
        const gop = try self.streams.getOrPut(self.client.alloc, sid);
        if (gop.found_existing) return error.DuplicateStream;
        gop.value_ptr.* = stream;
        _ = stream.refs.fetchAdd(1, .monotonic); // map reference
        _ = self.active.fetchAdd(1, .monotonic);
    }

    fn writeFrame(self: *Session, total_len: usize) !void {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.isDead()) return error.SessionClosed;
        return self.flushFrameLocked(total_len);
    }

    fn writeControl(self: *Session, cmd: proto.Command, sid: u32, data: []const u8) !void {
        if (data.len > proto.max_data_chunk) return error.TooLarge;
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.isDead()) return error.SessionClosed;
        proto.encodeHeader(self.scratch[0..proto.header_len], cmd, sid, data.len);
        @memcpy(self.scratch[proto.header_len..][0..data.len], data);
        return self.flushFrameLocked(proto.header_len + data.len);
    }

    fn writeData(self: *Session, sid: u32, data: []const u8) !void {
        if (data.len == 0) return;
        if (data.len > proto.max_data_chunk) return error.TooLarge;
        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        if (self.isDead()) return error.SessionClosed;
        proto.encodeHeader(self.scratch[0..proto.header_len], .psh, sid, data.len);
        @memcpy(self.scratch[proto.header_len..][0..data.len], data);
        return self.flushFrameLocked(proto.header_len + data.len);
    }

    /// Padding algorithm ported from anytls-go Session.writeConn. `rem` is the
    /// plaintext length already staged at the start of `scratch`.
    fn flushFrameLocked(self: *Session, total_len: usize) !void {
        var off: usize = 0;
        var rem: usize = total_len;

        if (self.send_padding) {
            self.pkt_counter +%= 1;
            const pkt = self.pkt_counter;
            if (pkt < self.scheme.stop) {
                var sizes_buf: [proto.max_entries]u32 = undefined;
                const sizes = self.scheme.sizesFor(pkt, &sizes_buf);
                for (sizes) |l_raw| {
                    if (l_raw == proto.check_mark) {
                        if (rem == 0) break else continue;
                    }
                    const tail_room = self.scratch.len - off - rem - proto.header_len;
                    const l: usize = if (rem > 0)
                        @min(l_raw, rem + proto.header_len + tail_room)
                    else
                        @min(l_raw, self.scratch.len - proto.header_len);

                    if (rem > l) {
                        try self.conn.writeAll(self.scratch[off..][0..l]);
                        off += l;
                        rem -= l;
                    } else if (rem > 0) {
                        // The chosen size may be smaller than payload+header
                        // (e.g. pkt 3 = 9-9 while a FIN frame is 7 bytes);
                        // then the frame is sent unpadded, exactly as the
                        // reference client does. Signed math avoids underflow.
                        const padlen_signed = @as(isize, @intCast(l)) -
                            @as(isize, @intCast(rem)) - @as(isize, proto.header_len);
                        var write_len = rem;
                        if (padlen_signed > 0) {
                            const padlen: usize = @intCast(padlen_signed);
                            const frame = self.scratch[off + rem ..][0 .. proto.header_len + padlen];
                            proto.encodeHeader(frame[0..proto.header_len], .waste, 0, padlen);
                            @memset(frame[proto.header_len..], 0);
                            write_len = rem + frame.len;
                        }
                        try self.conn.writeAll(self.scratch[off..][0..write_len]);
                        off += write_len;
                        rem = 0;
                        // Keep iterating: the remaining sizes become pure
                        // padding, matching the reference writeConn loop.
                    } else {
                        const frame = self.scratch[0 .. proto.header_len + l];
                        proto.encodeHeader(frame[0..proto.header_len], .waste, 0, l);
                        @memset(frame[proto.header_len..], 0);
                        try self.conn.writeAll(frame);
                    }
                }
                if (rem == 0) return;
                try self.conn.writeAll(self.scratch[off..][0..rem]);
                return;
            }
            self.send_padding = false;
        }
        try self.conn.writeAll(self.scratch[off..][0..rem]);
    }

    fn discard(self: *Session, len: usize) !void {
        var left = len;
        while (left > 0) {
            const n = @min(left, self.read_buf.len);
            try self.conn.readExact(self.read_buf[0..n]);
            left -= n;
        }
    }

    fn readLoop(self: *Session) void {
        var hdr: [proto.header_len]u8 = undefined;
        while (true) {
            self.conn.readExact(&hdr) catch |e| {
                log.debug("session {d}: read end: {s}", .{ self.seq, @errorName(e) });
                return;
            };
            const h = proto.decodeHeader(hdr);
            const len: usize = h.len;

            switch (h.cmd) {
                @intFromEnum(proto.Command.psh) => {
                    var left = len;
                    while (left > 0) {
                        const n = @min(left, self.read_buf.len);
                        self.conn.readExact(self.read_buf[0..n]) catch return;
                        if (self.streamRef(h.sid)) |st| {
                            defer st.release();
                            st.pipe.write(self.read_buf[0..n]) catch {};
                        }
                        left -= n;
                    }
                },
                @intFromEnum(proto.Command.fin) => {
                    log.debug("session {d}: FIN for stream {d}", .{ self.seq, h.sid });
                    if (self.removeStream(h.sid)) |st| {
                        st.pipe.setEof();
                        st.release();
                    }
                },
                @intFromEnum(proto.Command.waste) => self.discard(len) catch return,
                @intFromEnum(proto.Command.synack) => {
                    if (len > 0) {
                        var buf: [256]u8 = undefined;
                        const n = @min(len, buf.len);
                        self.conn.readExact(buf[0..n]) catch return;
                        if (len > n) self.discard(len - n) catch return;
                        log.err("stream {d}: server rejected: {s}", .{ h.sid, buf[0..n] });
                        if (self.removeStream(h.sid)) |st| {
                            st.synack.store(2, .release);
                            st.pipe.abort();
                            st.release();
                        }
                    } else if (self.streamRef(h.sid)) |st| {
                        st.synack.store(1, .release);
                        st.release();
                    }
                },
                @intFromEnum(proto.Command.alert) => {
                    if (len > 0) {
                        var buf: [512]u8 = undefined;
                        const n = @min(len, buf.len);
                        self.conn.readExact(buf[0..n]) catch return;
                        if (len > n) self.discard(len - n) catch return;
                        log.err("server alert: {s}", .{buf[0..n]});
                    }
                    return;
                },
                @intFromEnum(proto.Command.update_padding_scheme) => {
                    var raw: [proto.max_scheme_bytes]u8 = undefined;
                    if (len == 0 or len > raw.len) {
                        self.discard(len) catch return;
                    } else {
                        self.conn.readExact(raw[0..len]) catch return;
                        self.client.updateScheme(raw[0..len]);
                    }
                },
                @intFromEnum(proto.Command.heart_request) => {
                    self.writeControl(.heart_response, h.sid, &.{}) catch return;
                },
                @intFromEnum(proto.Command.heart_response) => {
                    if (len > 0) self.discard(len) catch return;
                },
                @intFromEnum(proto.Command.server_settings) => {
                    var buf: [128]u8 = undefined;
                    const n = @min(len, buf.len);
                    if (n > 0) {
                        self.conn.readExact(buf[0..n]) catch return;
                        if (len > n) self.discard(len - n) catch return;
                        if (proto.parseKVInt(buf[0..n], "v")) |v| {
                            const pv: u8 = @intCast(@min(v, 255));
                            self.peer_version.store(pv, .release);
                            log.debug("session {d}: peer version {d}", .{ self.seq, pv });
                        }
                    }
                },
                else => self.discard(len) catch return,
            }
        }
    }

    fn readerMain(self: *Session) void {
        self.acquire();
        defer self.release();
        self.readLoop();
        self.close();
    }

    /// Called by the janitor: true when a v2 stream never got its SYNACK.
    fn hasStuckStream(self: *Session, now_ms: i64) bool {
        self.streams_mutex.lock();
        defer self.streams_mutex.unlock();
        var it = self.streams.valueIterator();
        while (it.next()) |stp| {
            const st = stp.*;
            if (st.id < 2) continue;
            if (st.synack.load(.acquire) != 0) continue;
            if (st.syn_deadline_ms == 0) continue;
            if (now_ms > st.syn_deadline_ms) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const PoolEntry = struct {
    session: *Session,
    since_ms: i64,
};

pub const Client = struct {
    alloc: Allocator,
    cfg: Config,
    scheme: std.atomic.Value(*const proto.Scheme),
    sessions_mutex: std.Thread.Mutex = .{},
    sessions: std.AutoHashMapUnmanaged(u64, *Session) = .empty,
    pool_mutex: std.Thread.Mutex = .{},
    pool: [pool_size]PoolEntry = undefined,
    pool_len: usize = 0,
    /// Session sequence numbers are 64-bit but incremented only under
    /// seq_mutex: 32-bit targets (MIPS32) have no 64-bit atomics.
    seq_counter: u64 = 0,
    seq_mutex: std.Thread.Mutex = .{},
    handshake_mutex: std.Thread.Mutex = .{},
    stop_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    janitor_thread: ?std.Thread = null,

    pub fn init(alloc: Allocator, cfg: Config) !*Client {
        const self = try alloc.create(Client);
        errdefer alloc.destroy(self);

        const scheme = try proto.Scheme.parse(alloc, proto.default_scheme_raw);
        self.* = .{
            .alloc = alloc,
            .cfg = cfg,
            .scheme = std.atomic.Value(*const proto.Scheme).init(scheme),
        };

        self.janitor_thread = try std.Thread.spawn(
            .{ .stack_size = 64 * 1024 },
            janitorMain,
            .{self},
        );
        return self;
    }

    /// Stops accepting work and tears down sessions. Freeing the client object
    /// itself is intentionally left to process exit: stream threads may still
    /// hold references while they unwind.
    pub fn deinit(self: *Client) void {
        self.stop();
        if (self.janitor_thread) |t| t.join();
        self.janitor_thread = null;
    }

    pub fn updateScheme(self: *Client, raw: []const u8) void {
        const parsed = proto.Scheme.parse(self.alloc, raw) catch {
            log.warn("server sent an invalid padding scheme; keeping current one", .{});
            return;
        };
        _ = self.scheme.swap(parsed, .acq_rel);
        // Old schemes are intentionally retained: live sessions may still
        // reference them. Updates are rare (bounded by server behaviour).
        log.info("padding scheme updated", .{});
    }

    pub fn openStream(self: *Client, target: proto.Target, port: u16) !*Stream {
        if (self.takeIdle()) |sess| {
            // takeIdle hands us a temporary reference; the stream takes its
            // own, so it is safe to drop ours on every path.
            defer sess.release();
            if (sess.openStream(target, port)) |st| {
                return st;
            } else |e| {
                if (e == error.SessionBusy) {
                    self.insertIdle(sess);
                } else {
                    sess.close();
                }
            }
        }
        const sess = try self.createSession();
        defer sess.release();
        return sess.openStream(target, port) catch |e| {
            sess.close();
            return e;
        };
    }

    fn createSession(self: *Client) !*Session {
        const cfg = &self.cfg;
        self.handshake_mutex.lock();
        const conn = tlsm.Conn.dial(
            self.alloc,
            cfg.host,
            cfg.port,
            cfg.sni,
            cfg.ca,
            cfg.insecure,
            cfg.connect_timeout_ms,
        ) catch |e| {
            self.handshake_mutex.unlock();
            return e;
        };
        self.handshake_mutex.unlock();
        errdefer conn.destroy();
        log.debug("tls established, sending auth", .{});

        const scheme = self.scheme.load(.acquire);
        const padlen = scheme.authPadLen();

        var auth: [34 + max_pad]u8 = undefined;
        @memcpy(auth[0..32], &cfg.password_sha256);
        std.mem.writeInt(u16, auth[32..34], padlen, .big);
        @memset(auth[34 .. 34 + padlen], 0);
        try conn.writeAll(auth[0 .. 34 + padlen]);
        log.debug("auth sent ({d} bytes)", .{34 + padlen});

        const seq = self.nextSeq();
        const sess = try Session.create(self, conn, seq, scheme);
        errdefer sess.release();

        // Map reference.
        self.sessions_mutex.lock();
        const gop = self.sessions.getOrPut(self.alloc, seq) catch |e| {
            self.sessions_mutex.unlock();
            return e;
        };
        if (gop.found_existing) {
            self.sessions_mutex.unlock();
            return error.DuplicateSession;
        }
        gop.value_ptr.* = sess;
        sess.acquire();
        self.sessions_mutex.unlock();

        sess.reader_thread = std.Thread.spawn(
            .{ .stack_size = 128 * 1024 },
            Session.readerMain,
            .{sess},
        ) catch |e| {
            sess.close();
            return e;
        };
        sess.reader_thread.detach();
        log.debug("session {d} reader started", .{seq});
        log.debug("session {d} established to {s}:{d}", .{ seq, cfg.host, cfg.port });
        return sess;
    }

    fn nextSeq(self: *Client) u64 {
        self.seq_mutex.lock();
        defer self.seq_mutex.unlock();
        self.seq_counter += 1;
        return self.seq_counter;
    }

    fn removeSession(self: *Client, s: *Session) void {
        self.sessions_mutex.lock();
        const removed = self.sessions.fetchRemove(s.seq);
        self.sessions_mutex.unlock();
        if (removed != null) s.release();
    }

    // -- idle pool ----------------------------------------------------------

    fn takeIdle(self: *Client) ?*Session {
        var dead: [pool_size]*Session = undefined;
        var dead_n: usize = 0;

        self.pool_mutex.lock();
        // Drop entries whose session died while pooled (their pool reference
        // is released below; otherwise both the entry and the session leak).
        var w: usize = 0;
        for (0..self.pool_len) |i| {
            const s = self.pool[i].session;
            if (s.isDead()) {
                s.in_pool.store(false, .release);
                dead[dead_n] = s;
                dead_n += 1;
                continue;
            }
            self.pool[w] = self.pool[i];
            w += 1;
        }
        self.pool_len = w;

        var best: ?usize = null;
        for (0..self.pool_len) |i| {
            const s = self.pool[i].session;
            if (best == null or s.seq > self.pool[best.?].session.seq) best = i;
        }
        const idx = best orelse {
            self.pool_mutex.unlock();
            for (dead[0..dead_n]) |s| s.release();
            return null;
        };
        const s = self.pool[idx].session;
        self.pool_len -= 1;
        self.pool[idx] = self.pool[self.pool_len];
        s.in_pool.store(false, .release);
        self.pool_mutex.unlock();

        for (dead[0..dead_n]) |d| d.release();
        // The pool's reference becomes the caller's temporary reference.
        return s;
    }

    fn insertIdle(self: *Client, s: *Session) void {
        var evicted: ?*Session = null;

        self.pool_mutex.lock();
        // Re-check under the lock: close() marks dead then calls removeIdle,
        // so an insert that lost the race must not add a new entry.
        if (s.isDead()) {
            self.pool_mutex.unlock();
            return;
        }
        if (s.in_pool.load(.acquire)) {
            for (0..self.pool_len) |i| {
                if (self.pool[i].session == s) {
                    self.pool[i].since_ms = std.time.milliTimestamp();
                    break;
                }
            }
            self.pool_mutex.unlock();
            return;
        }
        if (self.pool_len == pool_size) {
            var oldest: ?usize = null;
            for (0..self.pool_len) |i| {
                if (self.pool[i].session.active.load(.acquire) != 0) continue;
                if (oldest == null or self.pool[i].since_ms < self.pool[oldest.?].since_ms) oldest = i;
            }
            const victim = oldest orelse {
                // Every pooled session still carries traffic; keep it and do
                // not pool this one (it stays usable, just not reusable).
                self.pool_mutex.unlock();
                return;
            };
            evicted = self.pool[victim].session;
            evicted.?.in_pool.store(false, .release);
            self.pool_len -= 1;
            self.pool[victim] = self.pool[self.pool_len];
        }
        self.pool[self.pool_len] = .{ .session = s, .since_ms = std.time.milliTimestamp() };
        self.pool_len += 1;
        s.acquire(); // the pool owns a reference while the entry exists
        s.in_pool.store(true, .release);
        self.pool_mutex.unlock();

        if (evicted) |v| {
            v.close();
            v.release(); // pool reference
        }
    }

    fn removeIdle(self: *Client, s: *Session) void {
        self.pool_mutex.lock();
        var found: ?usize = null;
        for (0..self.pool_len) |i| {
            if (self.pool[i].session == s) {
                found = i;
                break;
            }
        }
        var removed = false;
        if (found) |idx| {
            self.pool_len -= 1;
            self.pool[idx] = self.pool[self.pool_len];
            removed = true;
        }
        s.in_pool.store(false, .release);
        self.pool_mutex.unlock();
        if (removed) s.release(); // pool reference
    }

    // -- janitor ------------------------------------------------------------

    fn janitorMain(self: *Client) void {
        while (!self.stop_flag.load(.acquire)) {
            std.Thread.sleep(1000 * std.time.ns_per_ms);
            if (self.stop_flag.load(.acquire)) return;
            self.janitorTick();
        }
    }

    fn janitorTick(self: *Client) void {
        const now = std.time.milliTimestamp();
        var to_close: [pool_size]*Session = undefined;
        var close_count: usize = 0;

        // Idle expiry, keeping `min_idle` newest sessions.
        self.pool_mutex.lock();
        var alive_idx: [pool_size]usize = undefined;
        var alive_n: usize = 0;
        for (0..self.pool_len) |i| {
            if (now - self.pool[i].since_ms <= self.cfg.idle_timeout_ms) {
                alive_idx[alive_n] = i;
                alive_n += 1;
            }
        }
        // Sort kept sessions by seq descending is overkill; keep newest by seq.
        var expired: [pool_size]usize = undefined;
        var exp_n: usize = 0;
        for (0..self.pool_len) |i| {
            if (now - self.pool[i].since_ms > self.cfg.idle_timeout_ms) {
                expired[exp_n] = i;
                exp_n += 1;
            }
        }
        var keep_extra = if (alive_n < self.cfg.min_idle) self.cfg.min_idle - alive_n else 0;
        // Keep the newest expired sessions up to min_idle.
        std.mem.sort(usize, expired[0..exp_n], self, struct {
            fn less(c: *Client, a: usize, b: usize) bool {
                return c.pool[a].session.seq > c.pool[b].session.seq;
            }
        }.less);
        var removed = [_]bool{false} ** pool_size;
        var removed_any = false;
        for (expired[0..exp_n]) |i| {
            if (self.pool[i].session.active.load(.acquire) != 0) {
                self.pool[i].since_ms = now;
                continue;
            }
            if (keep_extra > 0) {
                keep_extra -= 1;
                self.pool[i].since_ms = now;
                continue;
            }
            if (close_count < to_close.len) {
                to_close[close_count] = self.pool[i].session;
                close_count += 1;
            }
            removed[i] = true;
            removed_any = true;
        }
        if (removed_any) {
            var w: usize = 0;
            for (0..self.pool_len) |i| {
                if (removed[i]) {
                    self.pool[i].session.in_pool.store(false, .release);
                    continue;
                }
                self.pool[w] = self.pool[i];
                w += 1;
            }
            self.pool_len = w;
        }
        self.pool_mutex.unlock();

        for (to_close[0..close_count]) |s| {
            log.debug("idle session {d} closed", .{s.seq});
            s.close();
            s.release(); // pool reference
        }

        // Stuck v2 tunnel detection (no SYNACK within syn_timeout_ms).
        const snapshot = self.snapshotSessions() catch return;
        defer self.alloc.free(snapshot);
        for (snapshot) |s| {
            if (s.hasStuckStream(now)) {
                log.warn("session {d}: SYNACK timeout, closing", .{s.seq});
                s.close();
            }
            s.release();
        }
    }

    fn snapshotSessions(self: *Client) ![]*Session {
        self.sessions_mutex.lock();
        defer self.sessions_mutex.unlock();
        const n = self.sessions.count();
        if (n == 0) return self.alloc.alloc(*Session, 0);
        const out = try self.alloc.alloc(*Session, n);
        var i: usize = 0;
        var it = self.sessions.valueIterator();
        while (it.next()) |sp| : (i += 1) {
            out[i] = sp.*;
            out[i].acquire();
        }
        return out[0..i];
    }

    pub fn stop(self: *Client) void {
        self.stop_flag.store(true, .release);
        const snapshot = self.snapshotSessions() catch return;
        defer self.alloc.free(snapshot);
        for (snapshot) |s| {
            s.close();
            s.release();
        }
    }
};

/// Called by the SOCKS5 and HTTP inbounds when a stream finishes. Keeps the
/// session available for reuse (idle pool) as the reference client does.
pub fn streamFinished(s: *Stream) void {
    const sess = s.session;
    s.closeNow();
    if (!sess.isDead() and sess.refs.load(.acquire) > 0) sess.client.insertIdle(sess);
    s.release();
}
