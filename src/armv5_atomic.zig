//! 32-bit atomics for ARMv5 (armel), which has no LDREX/STREX.
//!
//! LLVM lowers `cmpxchg`/`atomicrmw` on pre-ARMv6 to the libgcc `__sync_*`
//! helpers, which Zig's compiler-rt does not provide for this target. We
//! implement them on top of the kernel's `__kuser_cmpxchg` helper at
//! 0xffff0fc0 (the same mechanism libgcc uses; OpenWrt ARMv5 kernels keep
//! CONFIG_KUSER_HELPERS enabled for old userspace).
//!
//! The client itself only needs 4-byte atomics; 1/2-byte variants are provided
//! because the Zig standard library (TLS CSPRNG) uses a byte-sized lock. They
//! are implemented as a CAS on the containing aligned word, so neighbouring
//! bytes are never clobbered.

const std = @import("std");

fn kuserCmpxchg(old: u32, new: u32, ptr: *u32) u32 {
    return asm volatile (
        \\ push {r3, lr}
        \\ mov r12, %[helper]
        \\ mov r0, %[old]
        \\ mov r1, %[new]
        \\ mov r2, %[ptr]
        \\ blx r12
        \\ mov %[ret], r0
        \\ pop {r3, lr}
        : [ret] "=r" (-> u32),
        : [old] "r" (old),
          [new] "r" (new),
          [ptr] "r" (ptr),
          [helper] "r" (@as(u32, 0xffff0fc0)),
        : .{ .r0 = true, .r1 = true, .r2 = true, .r3 = true, .r12 = true, .apsr = true, .memory = true });
}

fn cas(ptr: *u32, old: u32, new: u32) u32 {
    const p: *volatile u32 = @ptrCast(ptr);
    while (true) {
        const cur = p.*;
        if (cur != old) return cur;
        if (kuserCmpxchg(old, new, ptr) == 0) return old;
    }
}

fn casSmall(comptime T: type, ptr: *T, old: T, new: T) T {
    const bits = @bitSizeOf(T);
    const addr = @intFromPtr(ptr);
    const word: *u32 = @ptrFromInt(addr & ~@as(usize, 3));
    const shift: u5 = @intCast((addr & 3) * 8);
    const mask: u32 = (@as(u32, 1) << bits) - 1;
    const p: *volatile u32 = @ptrCast(word);
    while (true) {
        const cur_word = p.*;
        const cur: T = @truncate(cur_word >> shift);
        if (cur != old) return cur;
        const next = (cur_word & ~(mask << shift)) |
            ((@as(u32, new) & mask) << shift);
        if (cas(word, cur_word, next) == cur_word) return old;
    }
}

fn xchgSmall(comptime T: type, ptr: *T, val: T) T {
    const p: *volatile T = @ptrCast(ptr);
    var cur = p.*;
    while (true) {
        const prev = casSmall(T, ptr, cur, val);
        if (prev == cur) return prev;
        cur = prev;
    }
}

export fn __sync_val_compare_and_swap_4(ptr: *u32, old: u32, new: u32) callconv(.c) u32 {
    return cas(ptr, old, new);
}

export fn __sync_bool_compare_and_swap_4(ptr: *u32, old: u32, new: u32) callconv(.c) bool {
    return cas(ptr, old, new) == old;
}

export fn __sync_lock_test_and_set_4(ptr: *u32, val: u32) callconv(.c) u32 {
    const p: *volatile u32 = @ptrCast(ptr);
    var cur = p.*;
    while (true) {
        const prev = cas(ptr, cur, val);
        if (prev == cur) return prev;
        cur = prev;
    }
}

export fn __sync_fetch_and_add_4(ptr: *u32, val: u32) callconv(.c) u32 {
    const p: *volatile u32 = @ptrCast(ptr);
    var cur = p.*;
    while (true) {
        const prev = cas(ptr, cur, cur +% val);
        if (prev == cur) return prev;
        cur = prev;
    }
}

export fn __sync_fetch_and_sub_4(ptr: *u32, val: u32) callconv(.c) u32 {
    const p: *volatile u32 = @ptrCast(ptr);
    var cur = p.*;
    while (true) {
        const prev = cas(ptr, cur, cur -% val);
        if (prev == cur) return prev;
        cur = prev;
    }
}

export fn __sync_val_compare_and_swap_1(ptr: *u8, old: u8, new: u8) callconv(.c) u8 {
    return casSmall(u8, ptr, old, new);
}

export fn __sync_bool_compare_and_swap_1(ptr: *u8, old: u8, new: u8) callconv(.c) bool {
    return casSmall(u8, ptr, old, new) == old;
}

export fn __sync_lock_test_and_set_1(ptr: *u8, val: u8) callconv(.c) u8 {
    return xchgSmall(u8, ptr, val);
}

export fn __sync_val_compare_and_swap_2(ptr: *u16, old: u16, new: u16) callconv(.c) u16 {
    return casSmall(u16, ptr, old, new);
}

export fn __sync_bool_compare_and_swap_2(ptr: *u16, old: u16, new: u16) callconv(.c) bool {
    return casSmall(u16, ptr, old, new) == old;
}

export fn __sync_lock_test_and_set_2(ptr: *u16, val: u16) callconv(.c) u16 {
    return xchgSmall(u16, ptr, val);
}

fn addSmall(comptime T: type, ptr: *T, val: T, comptime subtract: bool) T {
    const p: *volatile T = @ptrCast(ptr);
    var cur = p.*;
    while (true) {
        const next = if (subtract) cur -% val else cur +% val;
        const prev = casSmall(T, ptr, cur, next);
        if (prev == cur) return prev;
        cur = prev;
    }
}

export fn __sync_fetch_and_add_1(ptr: *u8, val: u8) callconv(.c) u8 {
    return addSmall(u8, ptr, val, false);
}

export fn __sync_fetch_and_sub_1(ptr: *u8, val: u8) callconv(.c) u8 {
    return addSmall(u8, ptr, val, true);
}
