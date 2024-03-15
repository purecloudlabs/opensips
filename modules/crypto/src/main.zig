const std = @import("std");
const opensips = @import("opensips.zig");
const c = @cImport({
    @cInclude("sr_module.h");
});

// Logger Initialization
pub const std_options = struct {
    pub const log_level = .debug;
    pub const logFn = @import("log.zig").logger;
};

const log = std.log.scoped(.crypto);

// Module Definition
const module = opensips.moduleExport(.{
    .name = "crypto",
    .cmds = &[_]c.cmd_export_t{
        opensips.cmdExport(.{
            .name = "rand",
            .flags = c.ALL_ROUTES,
            .function = &rand,
            .param1_flags = c.CMD_PARAM_INT,
            .param2_flags = c.CMD_PARAM_VAR,
        }),
        opensips.cmdExport(.{
            .name = "md5",
            .flags = c.ALL_ROUTES,
            .function = &md5,
            .param1_flags = c.CMD_PARAM_STR,
            .param2_flags = c.CMD_PARAM_VAR,
        }),
        opensips.cmdExport(.{
            .name = "sha1",
            .flags = c.ALL_ROUTES,
            .function = &sha1,
            .param1_flags = c.CMD_PARAM_STR,
            .param2_flags = c.CMD_PARAM_VAR,
        }),
        opensips.cmdExport(.{
            .name = "blake3",
            .flags = c.ALL_ROUTES,
            .function = &blake3,
            .param1_flags = c.CMD_PARAM_STR,
            .param2_flags = c.CMD_PARAM_VAR,
        }),
    },
    .init_f = &init,
    .destroy_f = &deinit,
});

comptime {
    @export(module, .{ .name = "exports" });
}

// Module Loaded Event
var rand_impl: std.rand.DefaultCsprng = undefined;

fn init() callconv(.C) c_int {
    var seed: [std.rand.DefaultCsprng.secret_seed_length]u8 = undefined;
    _ = std.os.getrandom(&seed) catch {
        log.err("The Crypto module load failed: failed to get initial random.", .{});
        return -1;
    };
    rand_impl = std.rand.DefaultCsprng.init(seed);
    std.crypto.utils.secureZero(u8, &seed);

    log.debug("The Crypto module has been loaded.", .{});
    return 0;
}

// Module Unloaded Event
fn deinit() callconv(.C) c_int {
    rand_impl = undefined;
    log.debug("The Crypto module has been unloaded.", .{});
    return 0;
}

// Exported Functions
pub fn rand(msg: [*c]const c.sip_msg, input_int: *c_int, out_var: *c.pv_spec_t) callconv(.C) c_int {
    const len = opensips.inputInt(input_int);
    var rand_raw: [1024]u8 = undefined;
    if (len > rand_raw.len) {
        std.log.err("Requested random bytes: {d}; upper limit: {d}. Failed to generate.", .{ len, rand_raw.len });
        return -1;
    }

    rand_impl.random().bytes(rand_raw[0..len]);
    var rand_hex: [rand_raw.len * 2]u8 = undefined;
    var rand_hex_trimmed = std.fmt.bufPrint(&rand_hex, "{}", .{std.fmt.fmtSliceHexLower(rand_raw[0..len])}) catch unreachable;

    opensips.outStr(msg, out_var, rand_hex_trimmed) catch {
        std.log.err("Output variable setting failed.", .{});
        return -1;
    };
    return 1;
}

pub fn md5(msg: [*c]const c.sip_msg, input_str: *c.__str, out_var: *c.pv_spec_t) callconv(.C) c_int {
    return hash(std.crypto.hash.Md5, msg, input_str, out_var);
}

pub fn sha1(msg: [*c]const c.sip_msg, input_str: *c.__str, out_var: *c.pv_spec_t) callconv(.C) c_int {
    return hash(std.crypto.hash.Sha1, msg, input_str, out_var);
}

pub fn blake3(msg: [*c]const c.sip_msg, input_str: *c.__str, out_var: *c.pv_spec_t) callconv(.C) c_int {
    return hash(std.crypto.hash.Blake3, msg, input_str, out_var);
}

pub fn hash(comptime T: type, msg: [*c]const c.sip_msg, input_str: *c.__str, out_var: *c.pv_spec_t) c_int {
    const input = opensips.inputStr(input_str);

    var hash_raw: [T.digest_length]u8 = undefined;
    T.hash(input, &hash_raw, .{});
    const hash_hex = std.fmt.bytesToHex(&hash_raw, .lower);

    opensips.outStr(msg, out_var, &hash_hex) catch {
        std.log.err("Output variable setting failed.", .{});
        return -1;
    };
    return 1;
}
