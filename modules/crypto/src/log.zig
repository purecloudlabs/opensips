const std = @import("std");
pub const c = @cImport({
    @cInclude("sr_module.h");
});

// Fixed C-to-Zig dp_time:
fn dp_time() callconv(.C) [*c]u8 {
    var ltime: c.time_t = undefined;
    _ = c.time(&ltime);
    _ = c.ctime_r(&ltime, c.ctime_buf);
    c.ctime_buf[19] = 0;
    return c.ctime_buf + 4;
}

fn logLevelText(comptime level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "ERROR",
        .warn => "WARNING",
        .info => "INFO",
        .debug => "DEBUG",
    };
}

pub fn logger(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const prefix = "{s} [{d}] " ++ comptime logLevelText(level) ++ ":" ++ @tagName(scope) ++ ": ";
    var log_buf: [4096:0]u8 = undefined;
    const log = std.fmt.bufPrint(&log_buf, prefix ++ format ++ "\n\x00", .{ dp_time(), c.dp_my_pid() } ++ args) catch trimmed: {
        std.debug.assert(log_buf.len > 5);
        const trim_text: []const u8 = "...\n";
        @memcpy(log_buf[log_buf.len - trim_text.len ..], trim_text);
        break :trimmed &log_buf;
    };
    const opensips_level = switch (level) {
        std.log.Level.err => -1,
        std.log.Level.warn => 1,
        std.log.Level.info => 3,
        std.log.Level.debug => 4,
    };
    if (opensips_level > c.log_level.*) return;
    _ = c.dprint(opensips_level, c.log_facility, null, null, @ptrCast(@constCast(log)), @ptrCast(@constCast(log)), null);
}
