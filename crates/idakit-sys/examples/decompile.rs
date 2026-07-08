//! Decompile a function and traverse its ctree (the marquee unknown).
//! Run: `cargo run -p idakit-sys --example decompile -- path/to/database.i64 [func_index]`

use std::env;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use idakit_sys::*;

fn pseudocode(cf: *mut c_void) -> String {
    let mut buf = vec![0 as c_char; 64 * 1024];
    let n = unsafe { idakit_cfunc_pseudocode(cf, buf.as_mut_ptr(), buf.len()) };
    if n <= 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let db = env::args().nth(1).expect("usage: decompile <db.i64> [idx]");
    let idx: usize = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(7);

    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open failed"
        );

        let hr = idakit_hexrays_init();
        println!("hexrays_init -> {hr}");
        assert_eq!(hr, 1, "hexrays unavailable");

        let address = idakit_func_ea(idx);
        println!("decompiling function[{idx}] @ {address:#x} ...\n");

        let mut err = [0 as c_char; 256];
        let cf = idakit_decompile(address, err.as_mut_ptr(), err.len());
        assert!(!cf.is_null(), "decompile returned null");

        let (mut ni, mut ne, mut nc): (c_int, c_int, c_int) = (0, 0, 0);
        idakit_cfunc_ctree_counts(cf, &mut ni, &mut ne, &mut nc);

        let text = pseudocode(cf);
        let shown: String = text.lines().take(30).collect::<Vec<_>>().join("\n");
        println!("{shown}");
        if text.lines().count() > 30 {
            println!("    ... ({} lines total)", text.lines().count());
        }
        println!("\nctree: statements={ni} expressions={ne} calls={nc}");

        idakit_cfunc_dispose(cf);
        close_database(false);
    }

    println!("\nDECOMPILE OK");
}
