//! typeinf through the facade: a function prototype + a struct's full member layout.
//! Run: cargo run -p idakit-sys --example typeinfo -- scratch/bf4-smoke.i64 [StructName]

use std::env;
use std::ffi::{CStr, CString, c_char, c_void};
use std::ptr;

use idakit_sys::*;

fn cstr(buf: &[c_char]) -> String {
    unsafe { CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn main() {
    let mut args = env::args().skip(1);
    let db = args.next().expect("usage: typeinfo <db.i64> [StructName]");
    let want = args.next();

    unsafe {
        assert_eq!(init_library(0, ptr::null_mut()), 0, "init_library failed");
        let cpath = CString::new(db).unwrap();
        assert_eq!(
            open_database(cpath.as_ptr(), false, ptr::null()),
            0,
            "open_database failed"
        );

        // (1) function prototype of func[7] via print_type(ea).
        let ea = idakit_func_ea(7);
        let mut buf = [0 as c_char; 1024];
        let n = idakit_func_type(ea, buf.as_mut_ptr(), buf.len());
        println!("func[7] {ea:#012x} prototype:");
        println!(
            "  {}",
            if n > 0 {
                cstr(&buf)
            } else {
                "<no type info>".into()
            }
        );

        // (2) a struct: the named one if given, else the first local type that is a
        // struct/union with >= 2 members.
        let count = idakit_type_ordinal_count();
        println!("\nlocal named types: {count}");

        let chosen: Option<(*mut c_void, String)> = if let Some(name) = want {
            let c = CString::new(name.clone()).unwrap();
            let h = idakit_type_open(c.as_ptr());
            if h.is_null() { None } else { Some((h, name)) }
        } else {
            let mut found = None;
            for ord in 1..=count as u32 {
                let mut nb = [0 as c_char; 256];
                if idakit_type_ordinal_name(ord, nb.as_mut_ptr(), nb.len()) <= 0 {
                    continue;
                }
                let h = idakit_type_open(nb.as_ptr());
                if h.is_null() {
                    continue;
                }
                if idakit_type_nmembers(h) >= 2 {
                    found = Some((h, cstr(&nb)));
                    break;
                }
                idakit_type_dispose(h);
            }
            found
        };

        match chosen {
            None => println!("\n(no struct with members found to introspect)"),
            Some((h, name)) => {
                let size = idakit_type_size(h);
                let nm = idakit_type_nmembers(h);
                // exercise the full-decl printer too (length only, to keep output clean)
                let mut decl = [0 as c_char; 4096];
                let dl = idakit_type_print(h, decl.as_mut_ptr(), decl.len());
                println!("\nstruct {name}  (size={size} bytes, {nm} members, decl {dl} chars):");
                for i in 0..nm {
                    let (mut off, mut sz): (u64, u64) = (0, 0);
                    if idakit_type_member_info(h, i, &mut off, &mut sz) == 0 {
                        continue;
                    }
                    let (mut namebuf, mut typebuf) = ([0 as c_char; 256], [0 as c_char; 1024]);
                    idakit_type_member_name(h, i, namebuf.as_mut_ptr(), namebuf.len());
                    idakit_type_member_type(h, i, typebuf.as_mut_ptr(), typebuf.len());
                    println!(
                        "  +{:#06x}  {:<28} {:>4}B  {}",
                        off,
                        cstr(&namebuf),
                        sz,
                        cstr(&typebuf)
                    );
                }
                idakit_type_dispose(h);
            }
        }

        close_database(false);
    }

    println!("\nTYPEINFO OK");
}
