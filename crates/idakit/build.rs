// rpath this crate's own binaries (examples/tests) to the IDA runtime. idakit-sys
// publishes the resolved dir as DEP_IDA_LIB_DIR; its rpath link-arg covers only
// its own artifacts, not ours. rpath is an ELF/Mach-O notion -- on Windows the DLL is
// found via the search path instead, so there's nothing to emit.
fn main() {
    if cfg!(not(target_os = "windows"))
        && let Ok(idadir) = std::env::var("DEP_IDA_LIB_DIR")
    {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir}");
    }
}
