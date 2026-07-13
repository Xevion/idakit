//! Core-read through the generated cxx bridge: open a DB copy, list functions + segments.
//! Run: cargo run -p idakit-sys --example read -- path/to/database.i64

use std::env;
use std::ffi::CString;
use std::ptr;

use idakit_sys::*;

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: read <db.i64>  (a COPY; opened save=false)");

    // SAFETY: the library lifecycle is the raw C ABI; the func_*/seg_* reads below are safe bridge
    // calls needing no `unsafe`.
    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open_database failed"
        );
    }

    let nf = func_qty();
    println!("functions: {nf}");
    println!("first 12 by index:");
    for i in 0..12.min(nf) {
        let address = func_ea(i);
        let name = func_name(address).unwrap_or_default();
        println!("  [{i:>2}] {address:#012x}  {name}");
    }

    let ns = gen_seg_qty();
    println!("\nsegments: {ns}");
    for n in 0..ns {
        let n = n as i32;
        let (s, e) = (gen_seg_start(n), gen_seg_end(n));
        let name = gen_seg_name(n).unwrap_or_default();
        println!("  {s:#012x}..{e:#012x}  {name}");
    }

    // SAFETY: raw C ABI lifecycle call.
    unsafe {
        close_database(false);
    }

    println!("\nREAD OK");
}
