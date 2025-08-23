const std = @import("std");

const builtin = @import("builtin");

/// 编译时检测是否为 Zig 0.15 或更新版本
pub const isZig015OrNewer = blk: {
    // Zig 版本号结构: major.minor.patch
    const version = builtin.zig_version;

    // 0.15.0 或更新版本
    break :blk (version.major == 0 and version.minor >= 15);
};

comptime {
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor < 14) {
        @compileError("Zig version 0.14 or newer is required");
    }
    if (builtin.zig_version.major == 0 and builtin.zig_version.minor > 15) {
        @compileError("Zig version 0.16 or newer is not supported yet");
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

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    lib_unit_tests.root_module.addImport("gmlib", lib_mod);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    exe_unit_tests.root_module.addImport("gmlib", lib_mod);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    if (isZig015OrNewer) {
        // 0.15+ 的代码
        const test_mod = b.createModule(.{
            .root_source_file = b.path("src/test.zig"),
            .target = target,
            .optimize = optimize,
        });
        const tests = b.addTest(.{
            .root_module = test_mod,
        });

        tests.addIncludePath(.{ .cwd_relative = "src" }); // 添加包含路径
        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&tests.step);
        test_step.dependOn(&run_lib_unit_tests.step);
        test_step.dependOn(&run_exe_unit_tests.step);
    } else {
        const tests = b.addTest(.{
            .root_source_file = b.path("src/test.zig"),
            .target = target,
            .optimize = optimize,
        });

        tests.addIncludePath(.{ .cwd_relative = "src" }); // 添加包含路径
        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&tests.step);
        test_step.dependOn(&run_lib_unit_tests.step);
        test_step.dependOn(&run_exe_unit_tests.step);
    }
}
