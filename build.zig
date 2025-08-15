const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

   // 创建模块
    const lib_mod = b.addModule("gmlib", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_mod.addImport("gmlib", lib_mod);

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "gmlib",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "gmlib",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

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

    const tests = b.addTest(.{
         .root_source_file = b.path("src/test.zig"),
         .target = target,
         .optimize = optimize,
     });
     
     const run_tests = b.addRunArtifact(tests);
     const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

     const test_step = b.step("test", "Run tests");
     test_step.dependOn(&run_tests.step);
     test_step.dependOn(&run_lib_unit_tests.step);
     test_step.dependOn(&run_exe_unit_tests.step);
}
