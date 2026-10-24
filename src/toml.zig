//! Minimal TOML reader for the client configuration file.
//!
//! Supported subset (deliberately small, dependency-free):
//!   - comments (`#`) and blank lines
//!   - tables `[server]`, `[listen]`, `[session]`, `[log]` (dotted names too)
//!   - bare keys `key = value`
//!   - basic strings with escapes (\" \\ \b \t \n \f \r \uXXXX)
//!   - literal strings ('...'), integers, booleans
//!
//! Arrays, inline tables, multi-line strings, dates and dotted keys are
//! rejected with a diagnostic instead of being silently misread.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    boolean: bool,
};

pub const Diag = struct {
    line: usize = 0,
    key: []const u8 = "",
    msg: []const u8 = "",
};

pub const Error = error{
    Syntax,
    DuplicateKey,
    Unsupported,
    OutOfMemory,
};

pub const Table = struct {
    arena: std.heap.ArenaAllocator,
    map: std.StringHashMapUnmanaged(Value) = .empty,

    pub fn deinit(self: *Table) void {
        self.arena.deinit();
    }

    pub fn count(self: *const Table) usize {
        return self.map.count();
    }

    /// Keys are stored as "table.key"; a top-level key has no prefix.
    pub fn get(self: *const Table, table_name: []const u8, key: []const u8) ?Value {
        if (table_name.len == 0) return self.map.get(key);
        var buf: [192]u8 = undefined;
        const k = std.fmt.bufPrint(&buf, "{s}.{s}", .{ table_name, key }) catch return null;
        return self.map.get(k);
    }
};

pub fn parse(alloc: Allocator, text: []const u8, diag: *Diag) Error!Table {
    var self: Table = .{ .arena = std.heap.ArenaAllocator.init(alloc) };
    errdefer self.arena.deinit();
    const a = self.arena.allocator();

    var table_name: []const u8 = "";
    var line_no: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (line[0] == '[') {
            const close = std.mem.indexOfScalar(u8, line, ']') orelse
                return syntax(diag, line_no, "unterminated table header");
            const name = std.mem.trim(u8, line[1..close], " \t");
            if (!validTableName(name)) return syntax(diag, line_no, "invalid table name");
            const rest = std.mem.trim(u8, line[close + 1 ..], " \t");
            if (rest.len > 0 and rest[0] != '#') return syntax(diag, line_no, "trailing characters after table header");
            table_name = try a.dupe(u8, name);
            continue;
        }

        const eq = findKeyEnd(line) orelse return syntax(diag, line_no, "expected key = value");
        const key = std.mem.trim(u8, line[0..eq], " \t");
        if (!validKey(key)) return syntax(diag, line_no, "invalid key (bare keys only)");

        var idx = eq + 1;
        const value = try parseValue(a, line, &idx, diag, line_no);
        const rest = std.mem.trim(u8, line[idx..], " \t");
        if (rest.len > 0 and rest[0] != '#') return syntax(diag, line_no, "unexpected characters after value");

        const full = if (table_name.len == 0)
            try a.dupe(u8, key)
        else
            try std.fmt.allocPrint(a, "{s}.{s}", .{ table_name, key });

        if (self.map.contains(full)) {
            // `full` lives in the arena, which is freed on this error path;
            // point the diagnostic at the input text instead.
            diag.line = line_no;
            diag.key = key;
            diag.msg = "duplicate key";
            return error.DuplicateKey;
        }
        try self.map.put(a, full, value);
    }
    return self;
}

fn syntax(diag: *Diag, line: usize, msg: []const u8) Error {
    diag.line = line;
    diag.msg = msg;
    return error.Syntax;
}

/// Index of the top-level '=' (outside quotes) on a key/value line.
fn findKeyEnd(line: []const u8) ?usize {
    var in_str: u8 = 0;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const c = line[i];
        if (in_str != 0) {
            if (c == '\\' and in_str == '"') {
                i += 1;
            } else if (c == in_str) {
                in_str = 0;
            }
            continue;
        }
        if (c == '"' or c == '\'') {
            in_str = c;
        } else if (c == '=') {
            return i;
        } else if (c == '#') {
            return null;
        }
    }
    return null;
}

fn validKey(k: []const u8) bool {
    if (k.len == 0) return false;
    for (k) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-') return false;
    }
    return true;
}

fn validTableName(k: []const u8) bool {
    if (k.len == 0) return false;
    for (k) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    }
    return true;
}

fn parseValue(a: Allocator, line: []const u8, idx: *usize, diag: *Diag, line_no: usize) Error!Value {
    while (idx.* < line.len and (line[idx.*] == ' ' or line[idx.*] == '\t')) idx.* += 1;
    if (idx.* >= line.len) return syntax(diag, line_no, "missing value");

    const c = line[idx.*];
    if (c == '"') return .{ .string = try basicString(a, line, idx, diag, line_no) };
    if (c == '\'') return .{ .string = try literalString(a, line, idx, diag, line_no) };

    if (std.mem.startsWith(u8, line[idx.*..], "true") and isDelimiterAt(line, idx.* + 4)) {
        idx.* += 4;
        return .{ .boolean = true };
    }
    if (std.mem.startsWith(u8, line[idx.*..], "false") and isDelimiterAt(line, idx.* + 5)) {
        idx.* += 5;
        return .{ .boolean = false };
    }
    if (c == '[' or c == '{') return syntax(diag, line_no, "arrays and inline tables are not supported");

    return .{ .integer = try parseInt(line, idx, diag, line_no) };
}

fn isDelimiterAt(s: []const u8, i: usize) bool {
    return i >= s.len or s[i] == ' ' or s[i] == '\t' or s[i] == '#';
}

fn basicString(a: Allocator, line: []const u8, idx: *usize, diag: *Diag, line_no: usize) Error![]const u8 {
    idx.* += 1;
    const out = try a.alloc(u8, line.len);
    var n: usize = 0;
    while (idx.* < line.len) {
        const c = line[idx.*];
        if (c == '"') {
            idx.* += 1;
            return out[0..n];
        }
        if (c != '\\') {
            out[n] = c;
            n += 1;
            idx.* += 1;
            continue;
        }
        idx.* += 1;
        if (idx.* >= line.len) return syntax(diag, line_no, "unterminated escape");
        const e = line[idx.*];
        idx.* += 1;
        switch (e) {
            '"' => out[n] = '"',
            '\\' => out[n] = '\\',
            'b' => out[n] = 0x08,
            't' => out[n] = '\t',
            'n' => out[n] = '\n',
            'f' => out[n] = 0x0c,
            'r' => out[n] = '\r',
            'u' => {
                const cp = try hex4(line, idx, diag, line_no);
                if (cp >= 0xd800 and cp <= 0xdfff) return syntax(diag, line_no, "surrogate escapes are not supported");
                const len = std.unicode.utf8Encode(@intCast(cp), out[n..][0..4]) catch
                    return syntax(diag, line_no, "invalid codepoint");
                n += len;
                continue;
            },
            else => return syntax(diag, line_no, "unsupported escape"),
        }
        n += 1;
    }
    return syntax(diag, line_no, "unterminated string");
}

fn literalString(a: Allocator, line: []const u8, idx: *usize, diag: *Diag, line_no: usize) Error![]const u8 {
    idx.* += 1;
    const start = idx.*;
    while (idx.* < line.len) : (idx.* += 1) {
        if (line[idx.*] == '\'') {
            const s = try a.dupe(u8, line[start..idx.*]);
            idx.* += 1;
            return s;
        }
    }
    return syntax(diag, line_no, "unterminated string");
}

fn hex4(line: []const u8, idx: *usize, diag: *Diag, line_no: usize) Error!u21 {
    if (idx.* + 4 > line.len) return syntax(diag, line_no, "short \\u escape");
    var v: u21 = 0;
    for (0..4) |k| {
        const d = std.fmt.charToDigit(line[idx.* + k], 16) catch
            return syntax(diag, line_no, "invalid \\u escape");
        v = v * 16 + d;
    }
    idx.* += 4;
    return v;
}

fn parseInt(line: []const u8, idx: *usize, diag: *Diag, line_no: usize) Error!i64 {
    const start = idx.*;
    if (idx.* < line.len and (line[idx.*] == '+' or line[idx.*] == '-')) idx.* += 1;
    var digits: usize = 0;
    while (idx.* < line.len) : (idx.* += 1) {
        const c = line[idx.*];
        if (std.ascii.isDigit(c)) {
            digits += 1;
        } else if (c != '_') {
            break;
        }
    }
    if (digits == 0) return syntax(diag, line_no, "invalid value");

    var buf: [64]u8 = undefined;
    var n: usize = 0;
    for (line[start..idx.*]) |c| {
        if (c == '_') continue;
        if (n == buf.len) return syntax(diag, line_no, "integer too long");
        buf[n] = c;
        n += 1;
    }
    return std.fmt.parseInt(i64, buf[0..n], 10) catch
        return syntax(diag, line_no, "integer out of range");
}
