extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let bindings = bindgen::Builder::default()
        .header("../../sr_module.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .allowlist_type("cmd_export_t")
        .allowlist_type("module_exports")
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
