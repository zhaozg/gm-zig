const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 14) {
        @compileError("Zig version 0.14 or newer is required");
    }
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor > 15) {
        @compileError("Zig version 0.16 or newer is not supported yet - use Zig 0.14.x or 0.15.x");
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
    tests.addIncludePath(.{ .cwd_relative = "src" });

    const run_tests = b.addRunArtifact(tests); // 创建运行步骤

    const test_step = b.step("test", "Run tests");
    // 确保所有测试都运行
    test_step.dependOn(&run_tests.step);

    // Add benchmark executable
    const benchmark_mod = b.createModule(.{
        .root_source_file = b.path("src/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark_mod.addImport("gmlib", lib_mod);

    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_mod,
    });
    b.installArtifact(benchmark_exe);

    const benchmark_cmd = b.addRunArtifact(benchmark_exe);
    benchmark_cmd.step.dependOn(b.getInstallStep());

    const benchmark_step = b.step("benchmark", "Run performance benchmarks");
    benchmark_step.dependOn(&benchmark_cmd.step);

    // Add performance analysis tool
    const analyze_mod = b.createModule(.{
        .root_source_file = b.path("src/analyze_performance.zig"),
        .target = target,
        .optimize = optimize,
    });

    const analyze_exe = b.addExecutable(.{
        .name = "analyze-performance",
        .root_module = analyze_mod,
    });
    b.installArtifact(analyze_exe);

    const analyze_cmd = b.addRunArtifact(analyze_exe);
    analyze_cmd.step.dependOn(b.getInstallStep());

    const analyze_step = b.step("analyze", "Analyze performance data");
    analyze_step.dependOn(&analyze_cmd.step);
}
