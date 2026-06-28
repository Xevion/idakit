//! Write path: rename + comment a function, SAVE, reopen, verify it persisted.
//! Proves the &mut path and that close_database(save=true) round-trips.
//! Run: cargo run -p idakit-sys --example writeop -- path/to/database.i64

use std::env;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

use idakit_sys::*;

const SN_NOWARN: i32 = 0x100;
const SN_FORCE: i32 = 0x800;

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

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: writeop <db.i64>  (a writable COPY)");
    let new_name = "idakit_renamed_fn";

    unsafe {
        // Pass 1: rename + comment, then SAVE.
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init failed");
        let cpath = CString::new(db.clone()).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open failed"
        );

        let ea = idakit_func_ea(7);
        let old = func_name(ea);
        println!("func[7] @ {ea:#x}  old name = {old}");

        let nm = CString::new(new_name).unwrap();
        let ok = set_name(ea, nm.as_ptr(), SN_NOWARN | SN_FORCE);
        let cmt = CString::new("renamed by idakit write-op test").unwrap();
        let ok_cmt = set_cmt(ea, cmt.as_ptr(), false);
        println!("set_name -> {ok}   set_cmt -> {ok_cmt}");

        close_database(true); // SAVE into the copy
        println!("saved.");
    }

    unsafe {
        // Pass 2: reopen and confirm persistence.
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "reopen failed"
        );
        let ea = idakit_func_ea(7);
        let now = func_name(ea);
        println!("after reopen, func[7] name = {now}");
        close_database(false);

        assert_eq!(now, new_name, "rename did not persist!");
    }

    println!("\nWRITEOP OK (rename persisted across save/reopen)");
}
