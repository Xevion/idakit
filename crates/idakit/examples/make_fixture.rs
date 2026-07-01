//! Turn a binary into a saved `.i64` database, headlessly. Unlike the read-only examples
//! it auto-analyzes the input and *persists* the result beside it as `<binary>.i64`, so
//! the output is a self-contained fixture a test can open with `IDAKIT_TEST_DB`.
//!
//!   cargo run -p idakit --example make_fixture -- <path/to/binary>

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = std::env::args()
        .nth(1)
        .expect("usage: make_fixture <path/to/binary>");

    idakit::Ida::run(move |ida| -> Result<(), idakit::Error> {
        ida.call(move |idb| -> Result<(), idakit::Error> {
            idb.open(&bin).run_auto(true).call()?;
            let funcs = idb.functions().count();
            let segs = idb.segments().count();
            // save = true: IDA flushes the analyzed database to <binary>.i64.
            idb.close(true);
            println!("wrote {bin}.i64: {funcs} functions, {segs} segments");
            Ok(())
        })?
    })??;

    Ok(())
}
