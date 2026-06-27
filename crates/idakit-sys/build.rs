use std::env;
use std::path::PathBuf;

// Compile the C++ facade against the IDA SDK headers and link the kernel.
//
// __EA64__  -> ea_t is 64-bit (bf4 / any 64-bit target).
// __LINUX__ -> platform (pro.h auto-detects from __linux__, set explicitly anyway).
fn main() {
    let idadir = env::var("IDADIR").unwrap_or_else(|_| {
        let home = env::var("HOME").expect("HOME unset");
        format!("{home}/ida-pro-9.3")
    });

    let runtime = PathBuf::from(&idadir).join("libida.so");
    assert!(
        runtime.exists(),
        "libida.so not found at {} - set IDADIR to your IDA install directory",
        runtime.display()
    );

    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sdk_include = manifest.join("../../ida-sdk-tmp/src/include");
    assert!(
        sdk_include.join("idalib.hpp").exists(),
        "SDK headers not found at {}",
        sdk_include.display()
    );

    let sdk_include_str = sdk_include.to_str().expect("SDK include path is not UTF-8");

    cc::Build::new()
        .cpp(true)
        .std("c++17")
        .file("facade/idakit_facade.cpp")
        .include("facade")
        // Treat the SDK headers as system includes so their warning noise is
        // suppressed while the facade's own warnings still surface. Emitted as an
        // adjacent pair so the compiler reads the path as `-isystem`'s argument.
        .flag("-isystem")
        .flag(sdk_include_str)
        .define("__EA64__", None)
        .define("__LINUX__", None)
        .compile("idakit_facade");

    println!("cargo:rustc-link-search=native={idadir}");
    println!("cargo:rustc-link-lib=dylib=ida");
    println!("cargo:rustc-link-lib=dylib=idalib");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir}");
    println!("cargo:lib_dir={idadir}"); // -> DEP_IDA_LIB_DIR for dependents' rpath
    println!("cargo:rerun-if-changed=facade/idakit_facade.cpp");
    println!("cargo:rerun-if-changed=facade/idakit_facade.h");
    println!("cargo:rerun-if-env-changed=IDADIR");
}
