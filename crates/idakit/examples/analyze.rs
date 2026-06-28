//! Auto-analyze a raw binary headlessly and report what IDA found — the inverse of
//! the other examples, which open an already-analyzed `.i64`. This is the path that
//! turns a fixture binary into an analyzed database (IDA writes `<binary>.i64` beside
//! the input), so it doubles as the smoke test for `open(...).run_auto(true)`.
//!
//!   cargo run -p idakit --example analyze -- <path/to/binary>

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::args()
        .nth(1)
        .expect("usage: analyze <path/to/binary>");

    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        ida.call(move |idb| -> Result<(), idakit::Error> {
            idb.open(&bin).run_auto(true).call()?;

            let funcs = idb.functions().count();
            let segs = idb.segments().count();
            println!("analyzed {bin}: {funcs} functions, {segs} segments");
            assert!(funcs > 0, "auto-analysis found no functions");

            idb.close(false);
            Ok(())
        })
        .expect("kernel call")
    })??;

    Ok(())
}
