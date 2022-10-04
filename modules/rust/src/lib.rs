#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused
)]

mod modul;

use crate::modul::print;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::ffi::c_char;
use std::ffi::c_int;
use std::ffi::c_void;
use std::ffi::CStr;
use std::ptr::null_mut;

const REQUEST_ROUTE: i32 = 1; /* Request route block */
const FAILURE_ROUTE: i32 = 2; /* Negative-reply route block */
const ONREPLY_ROUTE: i32 = 4; /* Received-reply route block */
const BRANCH_ROUTE: i32 = 8; /* Sending-branch route block */
const ERROR_ROUTE: i32 = 16; /* Error-handling route block */
const LOCAL_ROUTE: i32 = 32; /* Local-requests route block */
const STARTUP_ROUTE: i32 = 64; /* Startup route block */
const TIMER_ROUTE: i32 = 128; /* Timer route block */
const EVENT_ROUTE: i32 = 256; /* Event route block */
const ALL_ROUTES: i32 = REQUEST_ROUTE
    | FAILURE_ROUTE
    | ONREPLY_ROUTE
    | BRANCH_ROUTE
    | ERROR_ROUTE
    | LOCAL_ROUTE
    | STARTUP_ROUTE
    | TIMER_ROUTE
    | EVENT_ROUTE;

const DEFAULT_DFLAGS: u32 = 0;

const CMD_PARAM_INT: i32 = 1 << 0; /* integer parameter */
const CMD_PARAM_STR: i32 = 1 << 1; /* string parameter */
const CMD_PARAM_VAR: i32 = 1 << 2; /* PV spec parameter */
const CMD_PARAM_REGEX: i32 = 1 << 3; /* regexp string parameter */
const CMD_PARAM_OPT: i32 = 1 << 4; /* optional parameter */
const CMD_PARAM_FIX_NULL: i32 = 1 << 5; /* run fixup even if optional parameter is omitted */
const CMD_PARAM_NO_EXPAND: i32 = 1 << 6; /* do not pv-expand strings */
const CMD_PARAM_STATIC: i32 = 1 << 7; /* don't accept variables or formatted string */

static mut cmd_export: [cmd_export_; 1] = [cmd_export_ {
    name: "rust_print\0".as_ptr() as *mut i8,
    function: Some(unsafe {
        std::mem::transmute::<
            unsafe extern "C" fn(*mut sip_msg, *mut __str) -> i32,
            unsafe extern "C" fn(
                *mut sip_msg,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> i32,
        >(rust_print)
    }),
    params: [
        cmd_param {
            flags: CMD_PARAM_STR,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
        cmd_param {
            flags: 0,
            fixup: None,
            free_fixup: None,
        },
    ],
    flags: ALL_ROUTES as i32,
}];

#[no_mangle]
pub static mut exports: module_exports = module_exports {
    name: "rust\0".as_ptr() as *mut i8,
    type_: module_type_MOD_TYPE_DEFAULT,
    version: "opensips 3.2.8 (x86_64/linux)\0".as_ptr() as *mut i8, // TODO
    compile_flags: "STATS: On, DISABLE_NAGLE, USE_MCAST, SHM_MMAP, PKG_MALLOC, Q_MALLOC, F_MALLOC, HP_MALLOC, DBG_MALLOC, FAST_LOCK-ADAPTIVE_WAIT\0".as_ptr() as *mut i8, // TODO
    dlflags: DEFAULT_DFLAGS,
    load_f: None,
    deps: null_mut(),
    cmds: unsafe { &mut cmd_export as *mut cmd_export_},
    acmds: null_mut(),
    params: null_mut(),
    stats: null_mut(),
    mi_cmds: null_mut(),
    items: null_mut(),
    trans: null_mut(),
    procs: null_mut(),
    preinit_f: None,
    init_f: None,
    response_f: None,
    destroy_f: None,
    init_child_f: None,
    reload_ack_f: None,
};

#[no_mangle]
pub unsafe extern "C" fn rust_print(_: *mut sip_msg, cmd: *mut __str) -> c_int {
    let cstr = CStr::from_ptr((*cmd).s);
    let cmd_str = String::from_utf8_lossy(cstr.to_bytes()).to_string();
    if print(&cmd_str) {
        1
    } else {
        0
    }
}
