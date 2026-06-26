//! Core-read through the facade: open a DB copy, list functions + segments.
//! Run: cargo run -p idakit-sys --example read -- scratch/bf4-smoke.i64

use std::env;
use std::ffi::{c_char, CStr, CString};
use std::ptr;

use idakit_sys::*;

fn func_name(ea: Ea) -> String {
    let mut buf = [0 as c_char; 512];
    let n = unsafe { idakit_func_name(ea, buf.as_mut_ptr(), buf.len()) };
    if n <= 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn seg_name(n: i32) -> String {
    let mut buf = [0 as c_char; 256];
    let len = unsafe { idakit_seg_name(n, buf.as_mut_ptr(), buf.len()) };
    if len <= 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: read <db.i64>  (a COPY; opened save=false)");

    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");

        let cpath = CString::new(db.clone()).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open_database failed"
        );

        let nf = idakit_func_qty();
        println!("functions: {nf}");
        println!("first 12 by index:");
        for i in 0..12.min(nf) {
            let ea = idakit_func_ea(i);
            println!("  [{i:>2}] {ea:#012x}  {}", func_name(ea));
        }

        let ns = idakit_seg_qty();
        println!("\nsegments: {ns}");
        for n in 0..ns {
            let (s, e) = (idakit_seg_start(n), idakit_seg_end(n));
            println!("  {:#012x}..{:#012x}  {}", s, e, seg_name(n));
        }

        close_database(false);
    }

    println!("\nREAD OK");
}
