//! Re-applies idakit-sys's IDA runtime rpath to this crate's binaries (the smoke test), so they
//! find `libida.so` at run time; the linkage itself comes through idakit.
fn main() {
    if cfg!(not(target_os = "windows"))
        && let Ok(lib_dir) = std::env::var("DEP_IDA_LIB_DIR")
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{lib_dir}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DEP_IDA_LIB_DIR");
}
