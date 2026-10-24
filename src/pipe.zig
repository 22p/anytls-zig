//! Bounded byte pipe between the session reader thread and a stream consumer.
//!
//! One allocation per stream (the ring buffer). Backpressure is applied to the
//! session reader when a local consumer is slow, instead of buffering without
//! bound. EOF and abort are distinct so the consumer knows whether it should
//! half-close (FIN from peer) or fully tear down (session dead / stream error).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Pipe = struct {
    buf: []u8,
    head: usize = 0,
    len: usize = 0,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    not_empty: std.Io.Condition = .init,
    not_full: std.Io.Condition = .init,
    eof: bool = false,
    aborted: bool = false,

    pub fn init(alloc: Allocator, io: std.Io, capacity: usize) !Pipe {
        return .{ .io = io, .buf = try alloc.alloc(u8, capacity) };
    }

    pub fn deinit(self: *Pipe, alloc: Allocator) void {
        alloc.free(self.buf);
    }

    /// Blocks while the pipe is full. Returns error.Closed after abort().
    pub fn write(self: *Pipe, data: []const u8) error{Closed}!void {
        var rest = data;
        while (rest.len > 0) {
            self.mutex.lockUncancelable(self.io);
            while (self.len == self.buf.len and !self.aborted) {
                self.not_full.waitUncancelable(self.io, &self.mutex);
            }
            if (self.aborted) {
                self.mutex.unlock(self.io);
                return error.Closed;
            }
            const space = self.buf.len - self.len;
            const n = @min(space, rest.len);
            const tail = (self.head + self.len) % self.buf.len;
            const first = @min(n, self.buf.len - tail);
            @memcpy(self.buf[tail..][0..first], rest[0..first]);
            if (n > first) @memcpy(self.buf[0 .. n - first], rest[first..n]);
            self.len += n;
            self.not_empty.signal(self.io);
            self.mutex.unlock(self.io);
            rest = rest[n..];
        }
    }

    /// Returns null once the peer closed (EOF) or the stream was aborted.
    pub fn read(self: *Pipe, out: []u8) ?usize {
        if (out.len == 0) return 0;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.len == 0 and !self.eof and !self.aborted) {
            self.not_empty.waitUncancelable(self.io, &self.mutex);
        }
        if (self.len == 0) return null;
        const n = @min(out.len, self.len);
        const first = @min(n, self.buf.len - self.head);
        @memcpy(out[0..first], self.buf[self.head..][0..first]);
        if (n > first) @memcpy(out[first..n], self.buf[0 .. n - first]);
        self.head = (self.head + n) % self.buf.len;
        self.len -= n;
        self.not_full.signal(self.io);
        return n;
    }

    pub fn setEof(self: *Pipe) void {
        self.mutex.lockUncancelable(self.io);
        self.eof = true;
        self.not_empty.broadcast(self.io);
        self.mutex.unlock(self.io);
    }

    /// Discard buffered data, wake both sides. Used when the stream dies.
    pub fn abort(self: *Pipe) void {
        self.mutex.lockUncancelable(self.io);
        self.aborted = true;
        self.len = 0;
        self.not_empty.broadcast(self.io);
        self.not_full.broadcast(self.io);
        self.mutex.unlock(self.io);
    }

    pub fn wasAborted(self: *Pipe) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.aborted;
    }
};
