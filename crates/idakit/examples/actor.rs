//! Executor proof from the idiomatic API: kernel on its own thread, app on the
//! caller, calls (including from sub-workers) marshaled to the kernel.
//! Run: cargo run -p idakit --example actor -- scratch/bf4-smoke.i64

use std::thread;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = std::env::args().nth(1).expect("usage: actor <db.i64>");

    // `run` -> Err on kernel setup; the app closure -> Err on an operational failure.
    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        // `.expect` discharges the call boundary (panicked/gone kernel); `?` an open error.
        {
            let db = db.clone();
            ida.call(move |idb| idb.open(&db)).expect("kernel call")?;
        }

        let n = ida
            .call(|idb| idb.functions().count())
            .expect("kernel call");
        let segs = ida.call(|idb| idb.segments().count()).expect("kernel call");
        println!("[app] func_count={n}  segments={segs}");

        // Sub-workers each hold a handle clone; their calls serialize onto the kernel.
        let mut hs = vec![];
        for t in 0..4usize {
            let ida = ida.clone();
            hs.push(thread::spawn(move || {
                let idx = t * 1000;
                let (ea, name) = ida
                    .call(move |idb| {
                        idb.functions()
                            .nth(idx)
                            .map_or((None, None), |f| (Some(f.ea()), f.name()))
                    })
                    .expect("kernel call");
                let ea = ea.map_or_else(|| "<none>".into(), |e| format!("{e:#012x}"));
                let name = name.unwrap_or_else(|| "<unnamed>".into());
                println!("[worker {t}] func[{idx}] @ {ea}  {name}");
            }));
        }
        for h in hs {
            h.join().unwrap();
        }

        ida.call(|idb| idb.close(false)).expect("kernel call");
        Ok(())
    })??;

    println!("\nACTOR OK (kernel on its own thread; calls marshaled from app + 4 workers)");
    Ok(())
}
