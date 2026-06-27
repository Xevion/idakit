// rpath this crate's own binaries (examples/tests) to the IDA runtime. idakit-sys
// publishes the resolved dir as DEP_IDA_LIB_DIR; its rpath link-arg covers only
// its own artifacts, not ours.
fn main() {
    if let Ok(idadir) = std::env::var("DEP_IDA_LIB_DIR") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir}");
    }
}
