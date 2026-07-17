//! Decompile a function and inspect its ctree through the generated cxx bridge.
//! Run: `cargo run -p idakit-sys --example decompile -- path/to/database.i64 [func_index]`

use std::env;
use std::ffi::CString;
use std::ptr;

use idakit_sys::*;

fn main() {
    let db = env::args().nth(1).expect("usage: decompile <db.i64> [idx]");
    let idx: usize = env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(7);

    // SAFETY: the library lifecycle is the raw C ABI; hexrays_init/decompile/cfunc_* are safe
    // bridge calls.
    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open failed"
        );
    }

    let hr = hexrays_init();
    println!("hexrays_init -> {hr}");
    assert!(hr, "hexrays unavailable");

    let address = func_ea(idx);
    println!("decompiling function[{idx}] @ {address:#x} ...\n");

    // `decompile` returns a `UniquePtr<CFunc>` (one owned cfuncptr_t ref); its cxx deleter frees it
    // on drop, so there is no manual dispose.
    let cf = decompile(address).expect("decompile returned an error");
    let (counts, text) = {
        let cref = cf.as_ref().expect("non-null cfunc handle");
        (
            cfunc_counts(cref),
            cfunc_pseudocode(cref).unwrap_or_default(),
        )
    };

    let shown: String = text.lines().take(30).collect::<Vec<_>>().join("\n");
    println!("{shown}");
    if text.lines().count() > 30 {
        println!("    ... ({} lines total)", text.lines().count());
    }
    println!(
        "\nctree: statements={} expressions={} calls={}",
        counts.statements, counts.expressions, counts.calls
    );

    // Free the cfunc before tearing down the database.
    drop(cf);

    // SAFETY: raw C ABI lifecycle call.
    unsafe {
        close_database(false);
    }

    println!("\nDECOMPILE OK");
}
