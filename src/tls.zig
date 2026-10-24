//! TLS 1.3 transport (std.crypto.tls, no external C library).
//!
//! Chain validation and hostname verification are always enabled unless the
//! operator explicitly opts out with --insecure; the default is a CA bundle.

const std = @import("std");
const log = @import("log.zig");
const posix = std.posix;
const net = std.Io.net;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const tls = std.crypto.tls;
const sockaddr = @import("sockaddr.zig");

/// Guards the shared CA bundle during verification (std.crypto.tls wants a
/// lock it can hold while walking the chain).
var ca_lock: Io.RwLock = .init;

pub const Conn = struct {
    alloc: Allocator,
    io: Io,
    stream: net.Stream,
    socket_reader: net.Stream.Reader,
    socket_writer: net.Stream.Writer,
    client: tls.Client,
    bufs: []u8,
    socket_read_buf: []u8,
    tls_read_buf: []u8,
    cipher_buf: []u8,
    plain_buf: []u8,
    write_lock: Io.Mutex = .init,
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn dial(
        alloc: Allocator,
        io: Io,
        host: []const u8,
        port: u16,
        sni: []const u8,
        ca: ?*std.crypto.Certificate.Bundle,
        insecure: bool,
        timeout_ms: u32,
    ) !*Conn {
        if (!insecure and ca == null) return error.CaBundleRequired;
        const stream = try connectTcp(io, host, port, timeout_ms);
        errdefer stream.close(io);

        const fd = stream.socket.handle;
        setSocketTimeout(fd, timeout_ms);
        errdefer setSocketTimeout(fd, 0);

        const self = try alloc.create(Conn);
        errdefer alloc.destroy(self);

        const one_buf = tls.max_ciphertext_record_len;
        self.* = .{
            .alloc = alloc,
            .io = io,
            .stream = stream,
            .socket_reader = undefined,
            .socket_writer = undefined,
            .client = undefined,
            .bufs = undefined,
            .socket_read_buf = undefined,
            .tls_read_buf = undefined,
            .cipher_buf = undefined,
            .plain_buf = undefined,
            .write_lock = .init,
            .closed = std.atomic.Value(bool).init(false),
        };
        self.bufs = try alloc.alloc(u8, 4 * one_buf);
        errdefer alloc.free(self.bufs);
        self.cipher_buf = self.bufs[0..one_buf];
        self.plain_buf = self.bufs[one_buf .. 2 * one_buf];
        self.socket_read_buf = self.bufs[2 * one_buf .. 3 * one_buf];
        self.tls_read_buf = self.bufs[3 * one_buf .. 4 * one_buf];

        self.socket_reader = stream.reader(io, self.socket_read_buf);
        self.socket_writer = stream.writer(io, self.cipher_buf);

        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        Io.random(io, &entropy);

        self.client = try tls.Client.init(&self.socket_reader.interface, &self.socket_writer.interface, .{
            .host = if (insecure) .no_verification else .{ .explicit = sni },
            .ca = if (insecure) .no_verification else .{ .bundle = .{
                .gpa = alloc,
                .io = io,
                .lock = &ca_lock,
                .bundle = ca.?,
            } },
            .read_buffer = self.tls_read_buf,
            .write_buffer = self.plain_buf,
            .entropy = &entropy,
            .realtime_now = Io.Timestamp.now(io, .real),
            // AnyTLS frames carry their own lengths; a truncated TLS stream is
            // detected by the missing frame data, so this can stay strict.
            .allow_truncation_attacks = false,
        });

        setSocketTimeout(fd, 0);
        log.debug("tls: cipher {s}", .{@tagName(std.meta.activeTag(self.client.application_cipher))});
        log.debug("tls: negotiated {s} with {s}", .{
            @tagName(self.client.tls_version), sni,
        });
        return self;
    }

    pub fn readExact(self: *Conn, buf: []u8) !void {
        var i: usize = 0;
        while (i < buf.len) {
            const n = try self.client.reader.readSliceShort(buf[i..]);
            if (n == 0) return error.EndOfStream;
            i += n;
        }
    }

    /// One TLS application record group per call; used for padding packet accounting.
    pub fn writeAll(self: *Conn, data: []const u8) !void {
        self.write_lock.lockUncancelable(self.io);
        defer self.write_lock.unlock(self.io);
        if (self.closed.load(.acquire)) return error.Closed;

        self.client.writer.writeAll(data) catch |e| {
            self.closed.store(true, .release);
            return e;
        };
        self.client.writer.flush() catch |e| {
            self.closed.store(true, .release);
            return e;
        };
        self.socket_writer.interface.flush() catch |e| {
            self.closed.store(true, .release);
            return e;
        };
    }

    /// Stops all I/O but leaves the descriptor open until destroy().
    pub fn shutdown(self: *Conn) void {
        if (self.closed.swap(true, .acq_rel)) return;
        self.stream.shutdown(self.io, .both) catch {};
    }

    pub fn destroy(self: *Conn) void {
        self.shutdown();
        self.stream.close(self.io);
        self.alloc.free(self.bufs);
        self.alloc.destroy(self);
    }
};

fn setSocketTimeout(fd: posix.socket_t, ms: u32) void {
    const sec: isize = @intCast(ms / 1000);
    const usec: isize = @intCast((ms % 1000) * 1000);
    const tv = posix.timeval{ .sec = sec, .usec = usec };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

fn connectTcp(io: Io, host: []const u8, port: u16, timeout_ms: u32) !net.Stream {
    if (net.IpAddress.parse(host, port)) |addr| {
        return connectAddr(addr, timeout_ms);
    } else |_| {}

    var results: [8]net.HostName.LookupResult = undefined;
    var queue: std.Io.Queue(net.HostName.LookupResult) = .init(&results);
    const host_name = net.HostName.init(host) catch return error.UnknownHostName;
    try host_name.lookup(io, &queue, .{ .port = port });

    var last_err: anyerror = error.UnknownHostName;
    while (queue.getOne(io)) |item| {
        switch (item) {
            .address => |addr| {
                if (connectAddr(addr, timeout_ms)) |stream| return stream else |e| last_err = e;
            },
            .canonical_name => {},
        }
    } else |_| {}
    return last_err;
}

/// std.Io's threaded backend does not implement connect with a timeout yet
/// (`netConnectIpPosix` is a TODO), so connect on a raw socket: SO_SNDTIMEO
/// bounds a blocking connect without O_NONBLOCK bookkeeping.
fn connectAddr(addr: net.IpAddress, timeout_ms: u32) !net.Stream {
    const rc = std.c.socket(sockaddr.family(addr), posix.SOCK.STREAM | posix.SOCK.CLOEXEC, posix.IPPROTO.TCP);
    if (rc < 0) return error.SocketFailed;
    const fd: posix.socket_t = @intCast(rc);
    errdefer _ = std.c.close(fd);

    setSocketTimeout(fd, timeout_ms);

    var storage: posix.sockaddr.storage = undefined;
    const sa_len = sockaddr.toSockaddr(addr, &storage);
    const sa: *const posix.sockaddr = @ptrCast(&storage);
    if (std.c.connect(fd, sa, sa_len) != 0) return connectErr();

    const one: c_int = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&one)) catch {};

    return sockaddr.makeStream(fd, addr);
}

fn connectErr() anyerror {
    const e = sockaddr.errno();
    return switch (e) {
        .AGAIN, .INPROGRESS, .TIMEDOUT => error.ConnectionTimedOut,
        .CONNREFUSED => error.ConnectionRefused,
        .NETUNREACH => error.NetworkUnreachable,
        .HOSTUNREACH => error.NoRouteToHost,
        else => error.ConnectionFailed,
    };
}
