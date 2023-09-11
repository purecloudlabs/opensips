const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "crypto",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    lib.linkLibC();
    lib.addIncludePath(.{ .path = "../../" });
    lib.strip = true;

    var defs = std.mem.tokenizeSequence(u8, std.os.getenv("MAKE_DEFS").?, "-D");
    while (defs.next()) |def| {
        var kv = std.mem.tokenize(u8, def, "=");
        const key = kv.next().?;
        const value = kv.next();
        if (value == null) {
            lib.defineCMacro(key[0 .. key.len - 1], "");
            continue;
        }
        const trim: usize = if (value.?[0] == '\'') 1 else 0;
        lib.defineCMacro(key, value.?[trim..(value.?.len - trim - 1)]);
    }

    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
