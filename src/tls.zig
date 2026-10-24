//! TLS 1.3 transport (std.crypto.tls, no external C library).
//!
//! Chain validation and hostname verification are always enabled unless the
//! operator explicitly opts out with --insecure; the default is a CA bundle.

const std = @import("std");
const log = @import("log.zig");
const posix = std.posix;
const net = std.net;
const Allocator = std.mem.Allocator;
const tls = std.crypto.tls;

pub const Conn = struct {
    alloc: Allocator,
    fd: posix.socket_t,
    stream: net.Stream,
    socket_reader: net.Stream.Reader,
    socket_writer: net.Stream.Writer,
    client: tls.Client,
    bufs: []u8,
    socket_read_buf: []u8,
    tls_read_buf: []u8,
    cipher_buf: []u8,
    plain_buf: []u8,
    write_lock: std.Thread.Mutex = .{},
    closed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn dial(
        alloc: Allocator,
        host: []const u8,
        port: u16,
        sni: []const u8,
        ca: ?*std.crypto.Certificate.Bundle,
        insecure: bool,
        timeout_ms: u32,
    ) !*Conn {
        if (!insecure and ca == null) return error.CaBundleRequired;
        const fd = try connectTcp(alloc, host, port, timeout_ms);
        errdefer posix.close(fd);

        setSocketTimeout(fd, timeout_ms);
        errdefer setSocketTimeout(fd, 0);

        const self = try alloc.create(Conn);
        errdefer alloc.destroy(self);

        const one_buf = tls.max_ciphertext_record_len;
        self.* = undefined;
        self.alloc = alloc;
        self.fd = fd;
        self.stream = .{ .handle = fd };
        self.bufs = try alloc.alloc(u8, 4 * one_buf);
        errdefer alloc.free(self.bufs);
        self.cipher_buf = self.bufs[0..one_buf];
        self.plain_buf = self.bufs[one_buf .. 2 * one_buf];
        self.socket_read_buf = self.bufs[2 * one_buf .. 3 * one_buf];
        self.tls_read_buf = self.bufs[3 * one_buf .. 4 * one_buf];
        self.write_lock = .{};
        self.closed = std.atomic.Value(bool).init(false);

        self.socket_reader = self.stream.reader(self.socket_read_buf);
        self.socket_writer = self.stream.writer(self.cipher_buf);

        self.client = try tls.Client.init(self.socket_reader.interface(), &self.socket_writer.interface, .{
            .host = if (insecure) .no_verification else .{ .explicit = sni },
            .ca = if (insecure) .no_verification else .{ .bundle = ca.?.* },
            .read_buffer = self.tls_read_buf,
            .write_buffer = self.plain_buf,
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
        self.write_lock.lock();
        defer self.write_lock.unlock();
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
        posix.shutdown(self.fd, .both) catch {};
    }

    pub fn destroy(self: *Conn) void {
        self.shutdown();
        posix.close(self.fd);
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

fn connectTcp(alloc: Allocator, host: []const u8, port: u16, timeout_ms: u32) !posix.socket_t {
    if (net.Address.parseIp(host, port)) |addr| {
        return connectAddr(addr, timeout_ms);
    } else |_| {}

    const list = try net.getAddressList(alloc, host, port);
    defer list.deinit();

    var last_err: anyerror = error.UnknownHostName;
    for (list.addrs) |addr| {
        if (connectAddr(addr, timeout_ms)) |fd| return fd else |e| {
            last_err = e;
        }
    }
    return last_err;
}

fn connectAddr(addr: net.Address, timeout_ms: u32) !posix.socket_t {
    const fd = try posix.socket(
        addr.any.family,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        posix.IPPROTO.TCP,
    );
    errdefer posix.close(fd);

    // SO_SNDTIMEO bounds a blocking TCP connect on Linux without O_NONBLOCK
    // bookkeeping; EAGAIN from connect surfaces as error.WouldBlock.
    setSocketTimeout(fd, timeout_ms);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |e| switch (e) {
        error.WouldBlock => return error.ConnectionTimedOut,
        else => return e,
    };

    const one: c_int = 1;
    posix.setsockopt(fd, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&one)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, std.mem.asBytes(&one)) catch {};
    return fd;
}
