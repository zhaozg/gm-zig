const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("gmlib", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const main_src =
        if (target.result.cpu.arch == .wasm32 and target.result.os.tag == .freestanding)
            b.path("src/wasm.zig") else b.path("src/main.zig");


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
        // 此项默认为false，如果你需要在js环境中调用导出的方法，需要设置为true
        exe.rdynamic = true;

        // 关键配置：禁用标准库的 POSIX 功能
        exe.is_linking_libc = false;
        exe.root_module.single_threaded = true;
    }

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Create test modules for comprehensive testing
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    lib_unit_tests.root_module.addImport("gmlib", lib_mod);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    exe_unit_tests.root_module.addImport("gmlib", lib_mod);

    // Additional comprehensive test suite
    const tests = b.addTest(.{
         .root_source_file = b.path("src/test.zig"),
         .target = target,
         .optimize = optimize,
    });
    tests.addIncludePath(.{ .cwd_relative = "src" }); // 添加包含路径
     
    const run_tests = b.addRunArtifact(tests);
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);


     // Test step with all test configurations
     const test_step = b.step("test", "Run tests");
     test_step.dependOn(&run_tests.step);
     test_step.dependOn(&run_lib_unit_tests.step);
     test_step.dependOn(&run_exe_unit_tests.step);
}
