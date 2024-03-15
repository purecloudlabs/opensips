const std = @import("std");
pub const c = @cImport({
    @cInclude("sr_module.h");
});

pub const OpenSIPSError = error{OpenSIPSError};

fn defaultInit(comptime T: type, init: anytype) T {
    var data = std.mem.zeroes(T);
    for (@typeInfo(@TypeOf(init)).Struct.fields) |field| {
        if (@hasField(T, field.name)) {
            const value = @field(init, field.name);
            switch (@typeInfo(field.type)) {
                .Pointer => {
                    @field(data, field.name) = @ptrCast(value);
                },
                else => {
                    @field(data, field.name) = value;
                },
            }
        }
    }
    return data;
}

pub fn moduleExport(init: anytype) c.module_exports {
    var module = defaultInit(c.module_exports, init);

    // zig fmt: off
    module.ver_info = .{
        .version = c.OPENSIPS_FULL_VERSION,
        .compile_flags = c.OPENSIPS_COMPILE_FLAGS,
        .scm = .{
            .type = c.VERSIONTYPE,
            .rev = c.THISREVISION,
        }
    };
    // zig fmt: on

    return module;
}

pub fn cmdExport(init: anytype) c.cmd_export_t {
    const T = @TypeOf(init);

    var cmd = defaultInit(c.cmd_export_t, init);

    var params: [9]c.cmd_param = undefined;
    for (0..params.len) |idx| {
        const flags_field = std.fmt.comptimePrint("param{d}_flags", .{idx + 1});
        const fixup_field = std.fmt.comptimePrint("param{d}_fixup", .{idx + 1});
        const free_fixup_field = std.fmt.comptimePrint("param{d}_free_fixup_field", .{idx + 1});
        params[idx] = c.cmd_param{
            .flags = if (@hasField(T, flags_field)) @field(init, flags_field) else 0,
            .fixup = if (@hasField(T, fixup_field)) @field(init, fixup_field) else null,
            .free_fixup = if (@hasField(T, free_fixup_field)) @field(init, free_fixup_field) else null,
        };
    }
    cmd.params = params;

    return cmd;
}

pub fn inputStr(input_str: *c.__str) []u8 {
    return input_str.s[0..@intCast(input_str.len)];
}

pub fn inputInt(input_int: *c_int) usize {
    return @intCast(input_int.*);
}

pub fn outStr(msg: [*c]const c.sip_msg, out_var: *c.pv_spec_t, str: []const u8) OpenSIPSError!void {
    const out_val = c.pv_value_t{
        .rs = .{
            .s = @ptrCast(@constCast(str)),
            .len = @intCast(str.len),
        },
        .ri = 0,
        .flags = c.PV_VAL_STR,
    };
    if (c.pv_set_value(@constCast(msg), out_var, 0, @constCast(&out_val)) != 0) {
        return error.OpenSIPSError;
    }
}
