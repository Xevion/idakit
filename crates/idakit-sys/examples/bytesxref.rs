//! Bytes + xrefs through the generated cxx bridge: hex-dump a function's head, then who calls it.
//! Run: cargo run -p idakit-sys --example bytesxref -- path/to/database.i64

use std::env;
use std::ffi::CString;
use std::ptr;

use idakit_sys::*;

fn func_label(address: Address) -> String {
    func_name(address).unwrap_or_default()
}

/// Every reference targeting `address`, as `(from, type, iscode)`, from the owned xref snapshot.
fn references_to(address: Address) -> Vec<(Address, i32, bool)> {
    xrefs_build(address, true)
        .into_iter()
        .map(|r| (r.from, r.type_, r.iscode))
        .collect()
}

fn main() {
    let db = env::args()
        .nth(1)
        .expect("usage: bytesxref <db.i64>  (a COPY; opened save=false)");

    // SAFETY: the library lifecycle is the raw C ABI; the bridge reads below are safe.
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
    assert!(nf > 0, "no functions in db");

    // bytes: hex-dump the first 16 bytes of function[7]'s entry.
    let address = func_ea(7);
    let bytes = get_bytes(address, 16).unwrap_or_default();
    println!("function[7] {address:#012x}  {}", func_label(address));
    print!("  first {} bytes:", bytes.len());
    for b in &bytes {
        print!(" {b:02x}");
    }
    println!();

    // xrefs: who references function[7]? If it has no callers, scan forward for a function
    // that does, so the demo always shows real cross-references.
    let mut target = address;
    let mut refs = references_to(target);
    if refs.is_empty() {
        for i in 0..nf {
            let e = func_ea(i);
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
        func_label(target),
        refs.len()
    );
    for (from, ty, iscode) in &refs {
        let kind = if *iscode { "code" } else { "data" };
        println!(
            "  from {from:#012x}  {kind} type={ty:<2}  in {}",
            func_label(*from)
        );
    }

    // SAFETY: raw C ABI lifecycle call.
    unsafe {
        close_database(false);
    }

    println!("\nBYTESXREF OK");
}
