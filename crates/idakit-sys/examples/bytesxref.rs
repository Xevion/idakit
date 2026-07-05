//! Bytes + xrefs through the facade: hex-dump a function's head, then list who calls it.
//! Run: cargo run -p idakit-sys --example bytesxref -- path/to/database.i64

use std::env;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;

use idakit_sys::*;

fn func_name(address: Address) -> String {
    let mut buf = [0 as c_char; 512];
    let n = unsafe { idakit_func_name(address, buf.as_mut_ptr(), buf.len()) };
    if n <= 0 {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

/// Walk the reference cursor for every reference targeting `address`, collecting `(from, type, iscode)`.
fn references_to(address: Address) -> Vec<(Address, u8, u8)> {
    let mut out = Vec::new();
    unsafe {
        let cursor = idakit_xref_open(address, 1);
        let (mut from, mut to, mut ty, mut iscode) = (0u64, 0u64, 0u8, 0u8);
        while idakit_xref_next(cursor, &mut from, &mut to, &mut ty, &mut iscode) != 0 {
            out.push((from, ty, iscode));
        }
        idakit_xref_close(cursor);
    }
    out
}

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: bytesxref <db.i64>  (a COPY; opened save=false)");

    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open_database failed"
        );

        let nf = idakit_func_qty();
        assert!(nf > 0, "no functions in db");

        // bytes: hex-dump the first 16 bytes of function[7]'s entry.
        let address = idakit_func_ea(7);
        let mut bytes = [0u8; 16];
        let got = idakit_get_bytes(address, bytes.as_mut_ptr() as *mut c_void, bytes.len());
        println!("function[7] {address:#012x}  {}", func_name(address));
        print!("  first {got} bytes:");
        for b in &bytes[..got.max(0) as usize] {
            print!(" {b:02x}");
        }
        println!();

        // xrefs: who references function[7]? If it has no callers, scan forward for a function
        // that does, so the demo always shows real cross-references.
        let mut target = address;
        let mut refs = references_to(target);
        if refs.is_empty() {
            for i in 0..nf {
                let e = idakit_func_ea(i);
                let r = references_to(e);
                if !r.is_empty() {
                    target = e;
                    refs = r;
                    break;
                }
            }
        }

        println!(
            "\nxrefs_to {target:#012x}  {}   (total {})",
            func_name(target),
            refs.len()
        );
        for (from, ty, iscode) in &refs {
            let kind = if *iscode != 0 { "code" } else { "data" };
            println!(
                "  from {from:#012x}  {kind} type={ty:<2}  in {}",
                func_name(*from)
            );
        }

        close_database(false);
    }

    println!("\nBYTESXREF OK");
}
