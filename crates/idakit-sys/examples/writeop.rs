//! Write path: rename + comment a function, SAVE, reopen, verify it persisted.
//! Proves the &mut path and that close_database(save=true) round-trips.
//! Run: cargo run -p idakit-sys --example writeop -- path/to/database.i64

use std::env;
use std::ffi::CString;
use std::ptr;

use idakit_sys::*;

const SN_NOWARN: i32 = 0x100;
const SN_FORCE: i32 = 0x800;

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: writeop <db.i64>  (a writable COPY)");
    let new_name = "idakit_renamed_fn";

    // Pass 1: rename + comment, then SAVE.
    // SAFETY: the library lifecycle is the raw C ABI; func_ea/func_name are safe bridge reads.
    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init failed");
        let cpath = CString::new(db.clone()).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open failed"
        );
    }

    let address = func_ea(7);
    let old = func_name(address).unwrap_or_default();
    println!("function[7] @ {address:#x}  old name = {old}");

    // SAFETY: set_name/set_cmt/close_database are the raw C ABI on the open database.
    unsafe {
        let nm = CString::new(new_name).unwrap();
        let ok = set_name(address, nm.as_ptr(), SN_NOWARN | SN_FORCE);
        let cmt = CString::new("renamed by idakit write-op test").unwrap();
        let ok_cmt = set_cmt(address, cmt.as_ptr(), false);
        println!("set_name -> {ok}   set_cmt -> {ok_cmt}");

        close_database(true); // SAVE into the copy
    }
    println!("saved.");

    // Pass 2: reopen and confirm persistence.
    // SAFETY: raw C ABI lifecycle call.
    unsafe {
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "reopen failed"
        );
    }

    let address = func_ea(7);
    let now = func_name(address).unwrap_or_default();
    println!("after reopen, function[7] name = {now}");

    // SAFETY: raw C ABI lifecycle call.
    unsafe {
        close_database(false);
    }

    assert_eq!(now, new_name, "rename did not persist!");
    println!("\nWRITEOP OK (rename persisted across save/reopen)");
}
