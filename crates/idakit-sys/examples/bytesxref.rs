//! Bytes + xrefs through the facade: hex-dump a function's head, then list who calls it.
//! Run: cargo run -p idakit-sys --example bytesxref -- scratch/bf4-smoke.i64

use std::env;
use std::ffi::{CStr, CString, c_char, c_void};
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

        // bytes: hex-dump the first 16 bytes of func[7]'s entry.
        let ea = idakit_func_ea(7);
        let mut bytes = [0u8; 16];
        let got = idakit_get_bytes(ea, bytes.as_mut_ptr() as *mut c_void, bytes.len());
        println!("func[7] {ea:#012x}  {}", func_name(ea));
        print!("  first {got} bytes:");
        for b in &bytes[..got.max(0) as usize] {
            print!(" {b:02x}");
        }
        println!();

        // xrefs: who references func[7]? If it has no callers, scan forward for a function
        // that does, so the demo always shows real cross-references.
        let mut from = [0u64; 64];
        let mut typ = [0u8; 64];
        let mut iscode = [0u8; 64];
        let dump = |ea: Ea, from: &mut [u64], typ: &mut [u8], iscode: &mut [u8]| -> usize {
            idakit_xrefs_to(
                ea,
                from.as_mut_ptr(),
                typ.as_mut_ptr(),
                iscode.as_mut_ptr(),
                from.len(),
            )
        };

        let mut target = ea;
        let mut count = dump(target, &mut from, &mut typ, &mut iscode);
        if count == 0 {
            for i in 0..nf {
                let e = idakit_func_ea(i);
                let c = dump(e, &mut from, &mut typ, &mut iscode);
                if c > 0 {
                    target = e;
                    count = c;
                    break;
                }
            }
        }

        println!(
            "\nxrefs_to {target:#012x}  {}   (total {count})",
            func_name(target)
        );
        for k in 0..count.min(from.len()) {
            let kind = if iscode[k] != 0 { "code" } else { "data" };
            println!(
                "  from {:#012x}  {kind} type={:<2}  in {}",
                from[k],
                typ[k],
                func_name(from[k])
            );
        }

        close_database(false);
    }

    println!("\nBYTESXREF OK");
}
