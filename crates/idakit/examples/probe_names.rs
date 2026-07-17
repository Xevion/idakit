//! Tally a database's name list by weak/public binding and by which `NameFlags` spellings disagree,
//! printing examples of each. Verifies whether a fixture can distinguish the name accessors.
//!
//!   `cargo run -p idakit --example probe_names -- <db.i64> [max-names]`

use idakit::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let bin = args
        .next()
        .expect("usage: probe_names <db.i64> [max-names]");
    let max: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(50_000);

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&bin).call()?;

            let (mut total, mut weak, mut public, mut mangled) = (0usize, 0usize, 0usize, 0usize);
            let mut demangles = 0usize;
            let mut substitutes = 0usize;
            let mut short_differs = 0usize;
            let mut short_vs_long = 0usize;
            let mut samples: Vec<String> = Vec::new();
            let mut first_weak: Option<usize> = None;
            let mut first_public: Option<usize> = None;

            for Name { address, name } in idb.names().take(max) {
                total += 1;
                let is_weak = idb.is_weak_name(address);
                weak += usize::from(is_weak);
                if is_weak && first_weak.is_none() {
                    first_weak = Some(total - 1);
                }
                if idb.is_public_name(address) && first_public.is_none() {
                    first_public = Some(total - 1);
                }
                public += usize::from(idb.is_public_name(address));
                if name.starts_with("_Z") {
                    mangled += 1;
                }
                if idb.demangle(&name).is_some() {
                    demangles += 1;
                }

                let raw = idb.name_with(address, NameFlags::empty());
                let visible = idb.visible_name(address);
                if raw != visible {
                    substitutes += 1;
                    if samples.len() < 4 {
                        samples.push(format!(
                            "  subst {:#x}\n    raw     {raw:?}\n    visible {visible:?}",
                            address.get()
                        ));
                    }
                }

                // The mutant that survives collapses `short_name` to plain VISIBLE, so this is
                // the exact comparison that has to differ somewhere for a test to catch it.
                let short = idb.short_name(address);
                if short != visible {
                    short_differs += 1;
                }
                if short != idb.long_name(address) {
                    short_vs_long += 1;
                }

                if is_weak && name.starts_with("_Z") && samples.len() < 8 {
                    samples.push(format!(
                        "  weak+mangled {:#x}\n    raw   {name:?}\n    short {short:?}",
                        address.get()
                    ));
                }
            }

            println!("=== {total} names scanned");
            println!("weak            {weak}  (first at index {first_weak:?})");
            println!("public          {public}  (first at index {first_public:?})");
            println!("raw '_Z' prefix {mangled}");
            println!("demangle(name)  {demangles}");
            println!("raw != visible  {substitutes}");
            println!("short != visible {short_differs}   <- kills the short_name mutant");
            println!("short != long    {short_vs_long}");
            println!("=== samples");
            for s in &samples {
                println!("{s}");
            }

            idb.close(false);
            Ok(())
        })??;
        Ok(())
    })??;

    println!("PROBE_NAMES OK");
    Ok(())
}
