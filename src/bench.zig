const std = @import("std");
const zbench = @import("zbench");

const sm3_bench = @import("bench/sm3.zig");
const sm4_bench = @import("bench/sm4.zig");
const zuc_bench = @import("bench/zuc.zig");
const sm2_bench = @import("bench/sm2.zig");
const sm9_bench = @import("bench/sm9.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var filter: ?[]const u8 = null;
    var list_only = false;

    {
        var args_iter = try init.minimal.args.iterateAllocator(allocator);
        defer args_iter.deinit();

        // Skip the first arg (program name)
        _ = args_iter.next();

        while (args_iter.next()) |arg| {
            if (std.mem.eql(u8, arg, "--filter") or std.mem.eql(u8, arg, "-f")) {
                filter = args_iter.next() orelse {
                    std.log.err("Expected a filter pattern after --filter", .{});
                    std.process.exit(1);
                };
            } else if (std.mem.eql(u8, arg, "--list") or std.mem.eql(u8, arg, "-l")) {
                list_only = true;
            } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
                try printUsage();
                return;
            } else {
                std.log.err("Unknown argument: {s}", .{arg});
                try printUsage();
                std.process.exit(1);
            }
        }
    }

    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stdout: std.Io.File = .stdout();

    var bench = zbench.Benchmark.init(allocator, .{});
    defer bench.deinit();

    try addAllBenchmarks(&bench);

    if (list_only) {
        try listBenchmarks(bench, filter);
        return;
    }

    if (filter) |f| {
        filterBenchmarks(&bench, f);
        if (bench.benchmarks.items.len == 0) {
            std.log.err("No benchmarks match filter: {s}\n", .{f});
            std.process.exit(1);
        }
    }

    // Print system information
    const sysinfo = try zbench.getSystemInfo();
    var w: std.Io.File.Writer = stdout.writerStreaming(io, &.{});
    try sysinfo.format(&w.interface);

    try bench.run(io, stdout);
}

fn printUsage() !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stderr = std.Io.File.stderr();
    var w = stderr.writerStreaming(io, &.{});
    try w.interface.writeAll(
        \\Usage: bench [options]
        \\
        \\Options:
        \\  -f, --filter <pattern>    Run only benchmarks whose name contains the given pattern
        \\  -l, --list                List all available benchmarks (optionally filtered)
        \\  -h, --help                Show this help message
        \\
        \\Examples:
        \\  bench --filter SM3        Run only SM3 benchmarks
        \\  bench --filter SM4        Run only SM4 benchmarks
        \\  bench --filter "SM2 sign" Run only SM2 signing benchmarks
        \\  bench --list              List all benchmarks
        \\  bench --list --filter ZUC List ZUC benchmarks
        \\
    );
}

fn listBenchmarks(bench: zbench.Benchmark, filter: ?[]const u8) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();
    const stdout = std.Io.File.stdout();
    var w = stdout.writerStreaming(io, &.{});
    try w.interface.writeAll("Available benchmarks:\n");
    try w.interface.writeAll("---------------------\n");
    for (bench.benchmarks.items) |item| {
        if (filter) |f| {
            if (std.mem.indexOf(u8, item.name, f) == null) continue;
        }
        try w.interface.print("  {s}\n", .{item.name});
    }
}

fn filterBenchmarks(bench: *zbench.Benchmark, filter: []const u8) void {
    var i: usize = 0;
    while (i < bench.benchmarks.items.len) {
        const name = bench.benchmarks.items[i].name;
        if (std.mem.indexOf(u8, name, filter) == null) {
            _ = bench.benchmarks.swapRemove(i);
        } else {
            i += 1;
        }
    }
}

fn addAllBenchmarks(bench: *zbench.Benchmark) !void {
    // SM3 benchmarks
    try bench.add("SM3 hash 64B  ", sm3_bench.benchSm3Hash64B, .{});
    try bench.add("SM3 hash 1K   ", sm3_bench.benchSm3Hash1K, .{});
    try bench.add("SM3 hash 64K  ", sm3_bench.benchSm3Hash64K, .{});
    try bench.add("SM3 hash 1M   ", sm3_bench.benchSm3Hash1M, .{});
    try bench.add("SM3 hash 10M  ", sm3_bench.benchSm3Hash10M, .{});

    // SM4 benchmarks
    try bench.add("SM4 ECB E 16B ", sm4_bench.benchSm4EcbEncrypt16B, .{});
    try bench.add("SM4 ECB D 16B ", sm4_bench.benchSm4EcbDecrypt16B, .{});
    try bench.add("SM4 ECB E 1K  ", sm4_bench.benchSm4EcbEncrypt1K, .{});
    try bench.add("SM4 ECB D 1K  ", sm4_bench.benchSm4EcbDecrypt1K, .{});
    try bench.add("SM4 ECB E 64K ", sm4_bench.benchSm4EcbEncrypt64K, .{});
    try bench.add("SM4 ECB D 64K ", sm4_bench.benchSm4EcbDecrypt64K, .{});
    try bench.add("SM4 ECB E 1M  ", sm4_bench.benchSm4EcbEncrypt1M, .{});
    try bench.add("SM4 ECB D 1M  ", sm4_bench.benchSm4EcbDecrypt1M, .{});

    // ZUC benchmarks
    try bench.add("ZUC key stream ", zuc_bench.benchZucKeystream, .{});
    try bench.add("ZUC crypt 1K   ", zuc_bench.benchZucCrypt1K, .{});
    try bench.add("ZUC crypt 64K  ", zuc_bench.benchZucCrypt64K, .{});
    try bench.add("ZUC crypt 1M   ", zuc_bench.benchZucCrypt1M, .{});
    try bench.add("ZUC MAC 16B    ", zuc_bench.benchZucMac16B, .{});
    try bench.add("ZUC MAC 4K     ", zuc_bench.benchZucMac4K, .{});
    try bench.add("ZUC AEAD 1K    ", zuc_bench.benchZucAeadSeal1K, .{});
    try bench.add("ZUC AEAD 64K   ", zuc_bench.benchZucAeadSeal64K, .{});

    // SM4 additional mode benchmarks
    try bench.add("SM4 CBC E 1K   ", sm4_bench.benchSm4CbcEncrypt1K, .{});
    try bench.add("SM4 CBC D 1K   ", sm4_bench.benchSm4CbcDecrypt1K, .{});
    try bench.add("SM4 CTR E 1K   ", sm4_bench.benchSm4CtrEncrypt1K, .{});
    try bench.add("SM4 CTR D 1K   ", sm4_bench.benchSm4CtrDecrypt1K, .{});
    try bench.add("SM4 CTR E 64K  ", sm4_bench.benchSm4CtrEncrypt64K, .{});
    try bench.add("SM4 CTR D 64K  ", sm4_bench.benchSm4CtrDecrypt64K, .{});
    try bench.add("SM4 GCM 1K     ", sm4_bench.benchSm4GcmSeal1K, .{});
    try bench.add("SM4 GCM 64K    ", sm4_bench.benchSm4GcmSeal64K, .{});
    try bench.add("SM4 XTS E 1K   ", sm4_bench.benchSm4XtsEncrypt1K, .{});
    try bench.add("SM4 XTS D 1K   ", sm4_bench.benchSm4XtsDecrypt1K, .{});
    try bench.add("SM4 XTS E 64K  ", sm4_bench.benchSm4XtsEncrypt64K, .{});
    try bench.add("SM4 XTS D 64K  ", sm4_bench.benchSm4XtsDecrypt64K, .{});

    // SM2 benchmarks
    try bench.add("SM2 key gen    ", sm2_bench.benchSm2KeyGen, .{});
    try bench.add("SM2 sign small ", sm2_bench.benchSm2SignSmall, .{});
    try bench.add("SM2 sign med   ", sm2_bench.benchSm2SignMedium, .{});
    try bench.add("SM2 verify sml ", sm2_bench.benchSm2VerifySmall, .{});
    try bench.add("SM2 verify med ", sm2_bench.benchSm2VerifyMedium, .{});
    try bench.add("SM2 enc small  ", sm2_bench.benchSm2EncryptSmall, .{});
    try bench.add("SM2 enc med    ", sm2_bench.benchSm2EncryptMedium, .{});
    try bench.add("SM2 dec small  ", sm2_bench.benchSm2DecryptSmall, .{});
    try bench.add("SM2 dec med    ", sm2_bench.benchSm2DecryptMedium, .{});

    // SM9 benchmarks
    try bench.add("SM9 ext sign   ", sm9_bench.benchSm9ExtractSignKey, .{});
    try bench.add("SM9 ext enc    ", sm9_bench.benchSm9EncryptSmall, .{});
    try bench.add("SM9 sign small ", sm9_bench.benchSm9SignSmall, .{});
    try bench.add("SM9 sign med   ", sm9_bench.benchSm9SignMedium, .{});
    try bench.add("SM9 verify sml ", sm9_bench.benchSm9VerifySmall, .{});
    try bench.add("SM9 verify med ", sm9_bench.benchSm9VerifyMedium, .{});
    try bench.add("SM9 enc small  ", sm9_bench.benchSm9EncryptSmall, .{});
    try bench.add("SM9 enc med    ", sm9_bench.benchSm9EncryptMedium, .{});
    try bench.add("SM9 dec small  ", sm9_bench.benchSm9DecryptSmall, .{});
    try bench.add("SM9 dec med    ", sm9_bench.benchSm9DecryptMedium, .{});
}
