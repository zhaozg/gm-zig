const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 16) {
        @compileError("Zig version 0.16 or newer is required");
    }
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor > 17) {
        @compileError("Zig version 0.17 is the latest supported version - use Zig 0.16.x or 0.17.x");
    }
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("gmlib", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const main_src = if (target.result.cpu.arch == .wasm32 and target.result.os.tag == .freestanding)
        b.path("src/wasm.zig")
    else
        b.path("src/main.zig");

    const exe_mod = b.createModule(.{
        .root_source_file = main_src,
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("gmlib", lib_mod);

    const exe = b.addExecutable(.{
        .name = "gm",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    if (target.result.cpu.arch == .wasm32) {
        exe.rdynamic = true;
        exe.is_linking_libc = false;
        exe.root_module.single_threaded = true;
    }

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addImport("gmlib", lib_mod); // 确保测试模块也能访问gmlib

    const tests = b.addTest(.{
        .root_module = test_mod,
    });
    tests.root_module.addImport("gmlib", lib_mod);
    tests.root_module.addIncludePath(.{ .cwd_relative = "src" });

    const run_tests = b.addRunArtifact(tests); // 创建运行步骤

    const test_step = b.step("test", "Run tests");
    // 确保所有测试都运行
    test_step.dependOn(&run_tests.step);

    // Add bench tool using zbench
    const zbench_dep = b.dependency("zbench", .{
        .target = target,
        .optimize = optimize,
    });

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("gmlib", lib_mod);
    bench_mod.addImport("zbench", zbench_dep.module("zbench"));

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    // zbench requires Zig 0.17+; on 0.16.x only build the bench step on demand
    if (comptime builtin.zig_version.minor >= 17) {
        b.installArtifact(bench_exe);
    }

    const bench_cmd = b.addRunArtifact(bench_exe);
    bench_cmd.step.dependOn(b.getInstallStep());

    const bench_step = b.step("bench", "Run zbench performance benchmarks");
    bench_step.dependOn(&bench_cmd.step);
}
