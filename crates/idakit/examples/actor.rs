//! Executor proof from the idiomatic API: kernel on its own thread, app on the
//! caller, calls (including from sub-workers) marshaled to the kernel.
//! Run: cargo run -p idakit --example actor -- path/to/database.i64

use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = std::env::args().nth(1).expect("usage: actor <db.i64>");

    // `run` -> Err on kernel setup; the app closure -> Err on an operational failure.
    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        {
            let db = db.clone();
            ida.call(move |idb| idb.open(&db).call())??;
        }

        let n = ida.call(|idb| idb.functions().count())?;
        let segs = ida.call(|idb| idb.segments().count())?;
        println!("[app] func_count={n}  segments={segs}");

        // Sig scan: build a hex pattern from the first function's opening bytes and count
        // how often that exact sequence recurs across the image. A `Pattern` borrows the
        // `Idb`, so it is built, searched, and dropped inside a single kernel call.
        let hits = ida.call(|idb| {
            let Some(address) = idb.functions().next().map(|f| f.address()) else {
                return 0;
            };
            let sig = idb
                .bytes(address, 8)
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ");
            match idakit::Pattern::hex(idb, &sig) {
                Ok(pat) => idb.search(&pat).count(),
                Err(_) => 0,
            }
        })?;
        println!("[app] first function's opening 8 bytes recur {hits} time(s) in the image");

        // Sub-workers each hold a handle clone; their calls serialize onto the kernel.
        let mut hs = vec![];
        for t in 0..4usize {
            let ida = ida.clone();
            hs.push(thread::spawn(move || {
                let idx = t * 1000;
                let (address, name) = ida
                    .call(move |idb| {
                        idb.functions()
                            .nth(idx)
                            .map_or((None, None), |f| (Some(f.address()), f.name()))
                    })
                    .expect("kernel call");
                let address = address.map_or_else(|| "<none>".into(), |e| format!("{e:#012x}"));
                let name = name.unwrap_or_else(|| "<unnamed>".into());
                println!("[worker {t}] function[{idx}] @ {address}  {name}");
            }));
        }
        for h in hs {
            h.join().unwrap();
        }

        ida.call(|idb| idb.close(false))?;
        Ok(())
    })??;

    println!("\nACTOR OK (kernel on its own thread; calls marshaled from app + 4 workers)");
    Ok(())
}
