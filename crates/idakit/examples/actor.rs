//! Main-thread executor proof from the idiomatic API: kernel on main, app logic on a
//! spawned thread, calls (including from sub-workers) marshaled to main.
//! Run: cargo run -p idakit --example actor -- scratch/bf4-smoke.i64

use std::thread;

fn main() {
    let db = std::env::args().nth(1).expect("usage: actor <db.i64>");

    idakit::run_on_main(move |ida| {
        // Open on the kernel thread via a marshaled call.
        {
            let db = db.clone();
            ida.call(move |idb| idb.open(&db).expect("open failed"));
        }

        let n = ida.call(|idb| idb.func_count());
        let segs = ida.call(|idb| idb.segment_count());
        println!("[app] func_count={n}  segments={segs}");

        // Sub-workers each hold a handle clone; their calls serialize onto main.
        let mut hs = vec![];
        for t in 0..4usize {
            let ida = ida.clone();
            hs.push(thread::spawn(move || {
                let idx = t * 1000;
                let (ea, name) = ida.call(move |idb| {
                    let ea = idb.func_ea(idx);
                    (ea, idb.func_name(ea))
                });
                println!("[worker {t}] func[{idx}] @ {ea:#012x}  {name}");
            }));
        }
        for h in hs {
            h.join().unwrap();
        }

        ida.call(|idb| idb.close(false));
    });

    println!("\nACTOR OK (kernel on main; calls marshaled from app + 4 workers)");
}
