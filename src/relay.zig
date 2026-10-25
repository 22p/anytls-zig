//! Bidirectional relay between an AnyTLS stream and a local TCP socket.
//! Shared by the SOCKS5 and HTTP inbounds: the caller opens the stream and
//! owns its lifetime (`defer anytls.streamFinished(stream)`); `run` adds the
//! second reference for the stream->local pump and blocks until both
//! directions are done.

const std = @import("std");
const posix = std.posix;
const anytls = @import("anytls.zig");
const log = @import("log.zig");

const Relay = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    done: bool = false,

    fn finish(self: *Relay) void {
        self.mutex.lock();
        self.done = true;
        self.cond.broadcast();
        self.mutex.unlock();
    }

    fn wait(self: *Relay, timeout_ns: u64) bool {
        self.mutex.lock();
        if (!self.done) {
            self.cond.timedWait(&self.mutex, timeout_ns) catch {};
        }
        const d = self.done;
        self.mutex.unlock();
        return d;
    }
};

pub fn run(stream: *anytls.Stream, fd: posix.socket_t, half_close_wait_ns: u64) void {
    stream.acquire();
    var relay: Relay = .{};
    const thread = std.Thread.spawn(
        .{ .stack_size = 96 * 1024 },
        pumpToLocal,
        .{ stream, fd, &relay },
    ) catch |e| {
        log.err("relay: cannot start stream->local pump: {s}", .{@errorName(e)});
        stream.release();
        return;
    };

    pumpToRemote(stream, fd);

    if (!relay.wait(half_close_wait_ns)) {
        // Peer never sent its FIN. anytls-go servers close the stream on our
        // FIN without replying, so waiting forever would leak the thread.
        log.debug("relay: half-close grace expired, tearing down", .{});
        posix.shutdown(fd, .both) catch {};
        if (!relay.wait(2 * std.time.ns_per_s)) {
            // The pump is still blocked reading the stream; aborting the
            // pipe wakes it. Must happen before join().
            stream.closeNow();
        }
    }
    thread.join();
}

fn pumpToLocal(stream: *anytls.Stream, fd: posix.socket_t, relay: *Relay) void {
    defer relay.finish();
    defer stream.release();

    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) orelse break;
        if (n == 0) continue;
        writeAll(fd, buf[0..n]) catch {
            posix.shutdown(fd, .both) catch {};
            return;
        };
    }
    if (stream.wasAborted()) {
        posix.shutdown(fd, .both) catch {};
    } else {
        // Remote half-closed: propagate EOF to the local application, but keep
        // reading from it so it can still send (TCP half close).
        posix.shutdown(fd, .send) catch {};
    }
}

fn pumpToRemote(stream: *anytls.Stream, fd: posix.socket_t) void {
    var buf: [16 * 1024]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch break;
        if (n == 0) break;
        stream.write(buf[0..n]) catch break;
    }
    stream.sendFin();
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var i: usize = 0;
    while (i < data.len) {
        const n = try posix.send(fd, data[i..], posix.MSG.NOSIGNAL);
        i += n;
    }
}
