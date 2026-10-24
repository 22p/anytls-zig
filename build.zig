const std = @import("std");

pub fn build(b: *std.Build) void {
    // Default to static musl even for the host build: it matches the
    // deployment target and keeps host builds reproducible. Override with
    // -Dtarget=... when needed.
    const target = b.standardTargetOptions(.{ .default_target = .{ .abi = .musl } });
    const optimize = b.option(
        std.lang.Optimize,
        "optimize",
        "Optimization mode (default: small)",
    ) orelse .small;

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = optimize != .debug,
        // Release builds get no unwind metadata (saves ~25 KB on MIPS).
        .unwind_tables = if (optimize == .debug) null else .none,
    });
    const exe = b.addExecutable(.{ .name = "anytls-zig", .root_module = mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the client");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .link_libc = true,
    });
    const tests = b.addTest(.{ .root_module = test_mod });
    const test_run = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&test_run.step);
}
