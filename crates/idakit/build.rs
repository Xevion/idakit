//! Re-applies `idakit-sys`'s IDA runtime rpath to this crate's own binaries, and forwards the
//! resolved SDK include dir to the doc-alias validity test.
//!
//! `idakit-sys` publishes the resolved dir as `DEP_IDA_LIB_DIR`; its rpath link-arg covers only
//! its own artifacts, not this crate's examples/tests. rpath is an ELF/Mach-O notion; on Windows
//! the DLL is found via the search path instead, so there's nothing to emit. `idakit-sys` also
//! publishes its SDK include dir as `DEP_IDA_SDK_INCLUDE`, re-emitted here as `IDA_SDK_INCLUDE`
//! so `tests/doc_alias.rs` can read the SDK headers.
fn main() {
    if cfg!(not(target_os = "windows"))
        && let Ok(idadir) = std::env::var("DEP_IDA_LIB_DIR")
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir}");
    }
    if let Ok(sdk_include) = std::env::var("DEP_IDA_SDK_INCLUDE") {
        println!("cargo:rustc-env=IDA_SDK_INCLUDE={sdk_include}");
    }
    println!("cargo:rerun-if-env-changed=DEP_IDA_SDK_INCLUDE");
}
