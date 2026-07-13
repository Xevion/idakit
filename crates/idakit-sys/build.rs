use std::env;
use std::ffi::c_int;
use std::path::{Path, PathBuf};
use std::process::Command;

// The spec-driven cxx-gen pipeline: a declarative spec generates the Rust bridge, the C++ shim
// glue (via cxx-gen), and the templated C++ bodies. See the module for the full arrangement.
#[path = "build_support/gen.rs"]
mod codegen;

// Compile the C++ facade against the IDA SDK headers and link the kernel. __EA64__ makes
// ea_t 64-bit; `PLATFORM_DEFINE` (`__LINUX__`/`__MAC__`/`__NT__`) tells the SDK which OS it
// targets. SDK headers: `IDA_SDK_DIR`, else fetched to match the installed IDA's version.

const SDK_REPO: &str = "https://github.com/HexRaysSA/ida-sdk.git";

// Per-target runtime/import-library filenames, the SDK platform macro, and whether the
// linker takes an rpath. The build links a *native* IDA, so host and target coincide; keying
// off `#[cfg]` (host) is therefore correct and lets the version probe below share the split.
#[cfg(target_os = "windows")]
mod platform {
    pub const RUNTIME_LIB: &str = "ida.dll";
    pub const IDALIB_LIB: &str = "idalib.dll";
    pub const PLATFORM_DEFINE: &str = "__NT__";
    // PE resolves DLLs via the search path, not an embedded rpath.
    pub const EMIT_RPATH: bool = false;
    // MSVC links the C++ runtime by default; nothing to name explicitly.
    pub const CPP_STDLIB: Option<&str> = None;
}
#[cfg(target_os = "macos")]
mod platform {
    pub const RUNTIME_LIB: &str = "libida.dylib";
    pub const IDALIB_LIB: &str = "libidalib.dylib";
    pub const PLATFORM_DEFINE: &str = "__MAC__";
    pub const EMIT_RPATH: bool = true;
    pub const CPP_STDLIB: Option<&str> = Some("c++");
}
#[cfg(all(unix, not(target_os = "macos")))]
mod platform {
    pub const RUNTIME_LIB: &str = "libida.so";
    pub const IDALIB_LIB: &str = "libidalib.so";
    pub const PLATFORM_DEFINE: &str = "__LINUX__";
    pub const EMIT_RPATH: bool = true;
    pub const CPP_STDLIB: Option<&str> = Some("stdc++");
}
use platform::{CPP_STDLIB, EMIT_RPATH, IDALIB_LIB, PLATFORM_DEFINE, RUNTIME_LIB};

const FACADE_SOURCES: &[&str] = &["facade/runtime.cpp", "facade/db.cpp"];

// Compile one cxx bridge into its own static archive. cxx_build seeds a cc::Build with the
// generated glue; this mirrors the facade's flags (c++17, SDK as -isystem, __EA64__, platform
// macro), adds any bridge-specific `defines`, and appends the hand-written body TUs. No
// whole-archive is needed (no load-time constructor) and the C++ runtime link rides on the cxx
// crate's link-cplusplus dependency, so each bridge emits its own link directive.
fn cxx_bridge(rs: &str, bodies: &[&str], archive: &str, sdk_include: &str, defines: &[&str]) {
    let mut b = cxx_build::bridge(rs);
    b.std("c++17").include("facade");
    if b.get_compiler().is_like_msvc() {
        b.include(sdk_include);
    } else {
        b.flag("-isystem").flag(sdk_include);
    }
    b.define("__EA64__", None).define(PLATFORM_DEFINE, None);
    for d in defines {
        b.define(d, None);
    }
    for f in bodies {
        b.file(f);
    }
    b.compile(archive);
}

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR unset");

    // Spec-driven codegen is pure Rust/tokens (no IDA, no network), so it runs even under
    // DOCS_RS: src/bridge_gen.rs `include!`s $OUT_DIR/gen_bridge.rs, so rustdoc needs it present
    // before the native build is skipped below. The generated C++ is compiled further down.
    codegen::generate(Path::new(&out_dir));

    // docs.rs has no IDA and no network: skip the native build (rustdoc still renders).
    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let idadir = resolve_idadir();
    let runtime = idadir.join(RUNTIME_LIB);
    assert!(
        runtime.exists(),
        "{RUNTIME_LIB} not found at {} - set IDADIR to your IDA install directory",
        runtime.display()
    );

    let sdk_include = resolve_sdk_include(&idadir);
    let sdk_include_str = sdk_include.to_str().expect("SDK include path is not UTF-8");

    let mut build = cc::Build::new();
    build.cpp(true).std("c++17").include("facade");
    // Treat the SDK headers as system includes so their warning noise is suppressed while
    // the facade's own warnings still surface. `cl.exe`/`clang-cl` have no `-isystem`, so
    // there fall back to a plain include (SDK warnings stay non-fatal in this build).
    if build.get_compiler().is_like_msvc() {
        build.include(sdk_include_str);
    } else {
        build.flag("-isystem").flag(sdk_include_str);
    }
    build.define("__EA64__", None).define(PLATFORM_DEFINE, None);
    // The cfunc placement shims (moveit inline CfuncVal path) are a plain facade TU, not a cxx
    // bridge, so they ride along in the whole-archived facade.
    build.file("facade/cfunc_cxx.cc");
    // Mirror the caller's `-Zsanitizer=<name>` onto the facade TUs so bugs inside facade/*.cpp
    // are caught too, not just at the FFI boundary. Comma-separated like rustc's flag. `undefined`
    // uses trap mode: rustc links no UBSan runtime, so the usual `__ubsan_handle_*` calls would
    // dangle at link -- trap mode emits an inline trap instead, needing no runtime.
    if let Ok(sanitizers) = env::var("IDAKIT_SANITIZE") {
        let is_clang = build.get_compiler().is_like_clang();
        for name in sanitizers.split(',') {
            build.flag(format!("-fsanitize={name}"));
            if name == "undefined" {
                let trap_flag = if is_clang {
                    "-fsanitize-trap=undefined"
                } else {
                    "-fsanitize-undefined-trap-on-error"
                };
                build.flag(trap_flag);
            }
        }
        build.flag("-fno-omit-frame-pointer");
    }
    for src in FACADE_SOURCES {
        build.file(src);
    }
    // Emit the link directives ourselves (below) so the facade is *whole-archive* linked.
    build.cargo_metadata(false);
    build.compile("idakit_facade");

    // Whole-archive the facade so its load-time constructor, the idalib exit-banner filter
    // in runtime.cpp, is present in every binary, even pure unit-test binaries that call no
    // facade function. Otherwise the linker never pulls that object and macOS idalib's goodbye
    // banner (registered at dylib load) leaks into stdout, breaking `nextest --list`. The
    // modifier maps per-linker (-force_load / --whole-archive / /WHOLEARCHIVE).
    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=static:+whole-archive=idakit_facade");
    // cargo_metadata(false) also dropped cc's C++ runtime link, which the whole-archived
    // facade (std::string, exceptions, RTTI) needs; re-emit it after the facade so the
    // dependency order is right.
    if let Some(stdlib) = CPP_STDLIB {
        println!("cargo:rustc-link-lib=dylib={stdlib}");
    }

    // The cxx signature-bridge spine coexists with the raw facade rather than replacing it; each
    // bridge is its own static archive (see `cxx_bridge`).
    //
    // A hand-written bridge over the *generated* qflow_chart_t ExternType, proving a hand bridge
    // can share a spec-generated ExternType with the CFG domain.
    cxx_bridge(
        "src/bridge_cfg_check.rs",
        &["facade/cfg_check_cxx.cc"],
        "idakit_cxx_cfg_check_bridge",
        sdk_include_str,
        &[],
    );
    // qvector<T> bound per-instantiation (the KDAB recipe), read by copy and zero-copy.
    cxx_bridge(
        "src/bridge_qvec.rs",
        &["facade/qvec_cxx.cc"],
        "idakit_cxx_qvec_bridge",
        sdk_include_str,
        &[],
    );
    // The spec-driven cxx-gen bridges: namespace idakit_gen (the domain bridge) and namespace
    // idakit_cxx (the ctree/tinfo extern "Rust" opaque-visitor bridge). Unlike every bridge above,
    // neither is hand-written: codegen::generate builds each `#[cxx::bridge] mod` tokens from a
    // declarative spec and emits, into OUT_DIR, the Rust side (include!d by src/bridge_gen.rs /
    // src/bridge_visitors.rs), the C++ shim glue (via cxx-gen), the templated C++ bodies, and a
    // private rust/cxx.h. Compiled with plain cc (the glue already exists) mirroring the facade's
    // flags; OUT_DIR is on the include path for the generated headers and rust/cxx.h. The cxx
    // runtime it links against is the one the hand-written bridges above already compiled. The
    // domain bridge's Custom escape-hatch bodies and the visitor bridge's ctree/typewalk drivers
    // are hand-written TUs compiled alongside.
    let out_path = PathBuf::from(&out_dir);
    let mut gen_bridge = cc::Build::new();
    gen_bridge
        .cpp(true)
        .std("c++17")
        .include("facade")
        .include(&out_dir);
    if gen_bridge.get_compiler().is_like_msvc() {
        gen_bridge.include(sdk_include_str);
    } else {
        gen_bridge.flag("-isystem").flag(sdk_include_str);
    }
    gen_bridge
        .define("__EA64__", None)
        .define(PLATFORM_DEFINE, None);
    for tu in codegen::body_tus(&out_path) {
        gen_bridge.file(tu);
    }
    for tu in codegen::custom_tus() {
        gen_bridge.file(tu);
    }
    gen_bridge.file("facade/ctree_cxx.cc");
    gen_bridge.file("facade/typewalk_cxx.cc");
    gen_bridge.compile("idakit_cxx_gen_bridge");

    // The cxx fault-injection and boundary probe bridges. Each is its own static archive, like the
    // production bridges above; their Rust bindings are `#[doc(hidden)]`, keeping them off the API.
    cxx_bridge(
        "src/bridge_probe.rs",
        &["facade/probe_cxx.cc"],
        "idakit_cxx_probe",
        sdk_include_str,
        &[],
    );
    cxx_bridge(
        "src/bridge_probe_ext.rs",
        &["facade/probe_ext_cxx.cc"],
        "idakit_cxx_probe_ext_bridge",
        sdk_include_str,
        &[],
    );

    if env::var_os("IDAKIT_EMIT_COMPILE_COMMANDS").is_some() {
        emit_compile_commands(sdk_include_str);
    }

    let idadir_str = idadir.to_str().expect("IDADIR is not UTF-8");
    println!("cargo:rustc-link-search=native={idadir_str}");
    // Names resolve to `libida.so`/`libida.dylib` on Unix and the `ida.lib`/`idalib.lib`
    // import libraries on Windows (both must sit under IDADIR).
    println!("cargo:rustc-link-lib=dylib=ida");
    println!("cargo:rustc-link-lib=dylib=idalib");
    if EMIT_RPATH {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir_str}");
    }
    println!("cargo:lib_dir={idadir_str}"); // -> DEP_IDA_LIB_DIR for dependents' rpath
    for src in FACADE_SOURCES {
        println!("cargo:rerun-if-changed={src}");
    }
    println!("cargo:rerun-if-changed=facade/cfg_check_cxx.cc");
    println!("cargo:rerun-if-changed=facade/cfg_check_cxx.h");
    println!("cargo:rerun-if-changed=src/bridge_cfg_check.rs");
    println!("cargo:rerun-if-changed=facade/qvec_cxx.cc");
    println!("cargo:rerun-if-changed=facade/qvec_cxx.h");
    println!("cargo:rerun-if-changed=src/bridge_qvec.rs");
    println!("cargo:rerun-if-changed=facade/typewalk_cxx.cc");
    println!("cargo:rerun-if-changed=facade/typewalk_cxx.h");
    println!("cargo:rerun-if-changed=facade/ctree_cxx.cc");
    println!("cargo:rerun-if-changed=facade/ctree_cxx.h");
    println!("cargo:rerun-if-changed=src/bridge_visitors.rs");
    println!("cargo:rerun-if-changed=facade/probe_cxx.cc");
    println!("cargo:rerun-if-changed=facade/probe_cxx.h");
    println!("cargo:rerun-if-changed=facade/cfunc_cxx.cc");
    println!("cargo:rerun-if-changed=facade/cfunc_cxx.h");
    println!("cargo:rerun-if-changed=src/bridge_cfunc.rs");
    println!("cargo:rerun-if-changed=facade/probe_ext_cxx.cc");
    println!("cargo:rerun-if-changed=facade/probe_ext_cxx.h");
    println!("cargo:rerun-if-changed=src/bridge_probe_ext.rs");
    println!("cargo:rerun-if-changed=src/bridge_probe.rs");
    println!("cargo:rerun-if-changed=src/bridge_gen.rs");
    println!("cargo:rerun-if-changed=build_support/gen.rs");
    println!("cargo:rerun-if-changed=build_support/visitor_spec.rs");
    println!("cargo:rerun-if-changed=facade/custom_escape_hatch.cc");
    println!("cargo:rerun-if-changed=facade/import_custom.cc");
    println!("cargo:rerun-if-changed=facade/range_custom.cc");
    println!("cargo:rerun-if-changed=facade/function_custom.cc");
    println!("cargo:rerun-if-changed=facade/export_custom.cc");
    println!("cargo:rerun-if-changed=facade/meta_custom.cc");
    println!("cargo:rerun-if-changed=facade/name_custom.cc");
    println!("cargo:rerun-if-changed=facade/strings_custom.cc");
    println!("cargo:rerun-if-changed=facade/cfg_custom.cc");
    println!("cargo:rerun-if-changed=facade/reference_custom.cc");
    println!("cargo:rerun-if-changed=facade/bytes_custom.cc");
    println!("cargo:rerun-if-changed=facade/instruction_custom.cc");
    println!("cargo:rerun-if-changed=facade/hexrays_custom.cc");
    println!("cargo:rerun-if-changed=facade/type_build_custom.cc");
    println!("cargo:rerun-if-changed=facade/ty_custom.cc");
    println!("cargo:rerun-if-changed=facade/netnode_custom.cc");
    println!("cargo:rerun-if-changed=facade/idakit_facade.h");
    println!("cargo:rerun-if-changed=facade/idakit_facade_internal.hpp");
    println!("cargo:rerun-if-changed=facade/typewalk_walker.hpp");
    println!("cargo:rerun-if-env-changed=IDADIR");
    println!("cargo:rerun-if-env-changed=IDAKIT_EMIT_COMPILE_COMMANDS");
    println!("cargo:rerun-if-env-changed=IDA_SDK_DIR");
    println!("cargo:rerun-if-env-changed=IDA_SDK_CACHE_DIR");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    println!("cargo:rerun-if-env-changed=IDAKIT_SANITIZE");
}

/// Emit `compile_commands.json` for clang-tidy/clangd (opt-in via `just tidy`).
fn emit_compile_commands(sdk_include: &str) {
    let dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR unset");
    let mut json = String::from("[\n");
    for (i, src) in FACADE_SOURCES.iter().enumerate() {
        if i > 0 {
            json.push_str(",\n");
        }
        let plat = format!("-D{PLATFORM_DEFINE}");
        json.push_str(&format!(
            "  {{\"directory\": {dir:?}, \"file\": {src:?}, \"arguments\": \
             [\"c++\", \"-std=c++17\", \"-Ifacade\", \"-isystem\", {sdk_include:?}, \
             \"-D__EA64__\", {plat:?}, \"-c\", {src:?}]}}"
        ));
    }
    json.push_str("\n]\n");
    std::fs::write(Path::new(&dir).join("compile_commands.json"), json)
        .expect("write compile_commands.json");
}

/// The IDA install holding the runtime (`RUNTIME_LIB`): `IDADIR`, else `idat64`/`idat` on
/// `PATH`, else the known install locations. Any valid install will do, since its version is
/// read at link time.
fn resolve_idadir() -> PathBuf {
    if let Some(dir) = env::var_os("IDADIR") {
        return PathBuf::from(dir);
    }
    idadir_from_path()
        .or_else(idadir_from_known_locations)
        .unwrap_or_else(|| {
            panic!(
                "could not locate an IDA install; set IDADIR to your IDA directory \
                 (the one holding {RUNTIME_LIB})"
            )
        })
}

fn has_runtime(dir: &Path) -> bool {
    dir.join(RUNTIME_LIB).exists()
}

/// The install dir of `idat64`/`idat` if on `PATH` (canonicalized, so a wrapper symlink
/// resolves to the real root).
fn idadir_from_path() -> Option<PathBuf> {
    // The text-mode driver ships as `idat64.exe` on Windows, bare elsewhere.
    #[cfg(windows)]
    const IDAT: &[&str] = &["idat64.exe", "idat.exe"];
    #[cfg(not(windows))]
    const IDAT: &[&str] = &["idat64", "idat"];

    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        for exe in IDAT {
            let bin = dir.join(exe);
            if !bin.is_file() {
                continue;
            }
            let real = std::fs::canonicalize(&bin).unwrap_or(bin);
            if let Some(parent) = real.parent()
                && has_runtime(parent)
            {
                return Some(parent.to_path_buf());
            }
        }
    }
    None
}

/// Scan the OS's default IDA install locations, preferring the highest-named (newest) one.
fn idadir_from_known_locations() -> Option<PathBuf> {
    let mut found = known_install_dirs();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.pop().map(|(_, runtime_dir)| runtime_dir)
}

/// Immediate children of `roots` whose name matches `pat`, resolved to where the runtime
/// should sit (the child itself, or `runtime_subdir` within it) and kept only if it does.
/// Returns `(child name, runtime dir)` so the caller can pick the newest by name.
fn collect_installs(
    roots: impl IntoIterator<Item = PathBuf>,
    pat: impl Fn(&str) -> bool,
    runtime_subdir: Option<&str>,
) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !pat(&name) {
                continue;
            }
            let dir = match runtime_subdir {
                Some(sub) => entry.path().join(sub),
                None => entry.path(),
            };
            if has_runtime(&dir) {
                found.push((name, dir));
            }
        }
    }
    found
}

/// `(install name, runtime dir)` for every IDA install under this OS's default locations.
#[cfg(all(unix, not(target_os = "macos")))]
fn known_install_dirs() -> Vec<(String, PathBuf)> {
    // Linux: `~/ida-pro-9.3`, `/opt/idapro-9.3`; the runtime sits in the install dir.
    let roots = env::var_os("HOME")
        .map(PathBuf::from)
        .into_iter()
        .chain([PathBuf::from("/opt")]);
    collect_installs(
        roots,
        |n| n.starts_with("ida-pro-") || n.starts_with("idapro-"),
        None,
    )
}

/// `(install name, runtime dir)` for every IDA install under this OS's default locations.
#[cfg(target_os = "macos")]
fn known_install_dirs() -> Vec<(String, PathBuf)> {
    // macOS: `/Applications/IDA Professional 9.3.app`; the runtime is in `Contents/MacOS`.
    let roots = env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Applications"))
        .into_iter()
        .chain([PathBuf::from("/Applications")]);
    collect_installs(
        roots,
        |n| n.starts_with("IDA ") && n.ends_with(".app"),
        Some("Contents/MacOS"),
    )
}

/// `(install name, runtime dir)` for every IDA install under this OS's default locations.
#[cfg(windows)]
fn known_install_dirs() -> Vec<(String, PathBuf)> {
    // Windows: `C:\Program Files\IDA Professional 9.3`; the runtime sits in the install dir.
    let roots = ["ProgramFiles", "ProgramFiles(x86)"]
        .into_iter()
        .filter_map(env::var_os)
        .map(PathBuf::from);
    collect_installs(roots, |n| n.starts_with("IDA "), None)
}

/// Locate the SDK `include` directory holding `idalib.hpp`: an explicit
/// `IDA_SDK_DIR`, else a version-matched checkout fetched into the cache.
fn resolve_sdk_include(idadir: &Path) -> PathBuf {
    if let Some(dir) = env::var_os("IDA_SDK_DIR") {
        let root = PathBuf::from(dir);
        return find_include(&root).unwrap_or_else(|| {
            panic!(
                "IDA_SDK_DIR={} has no idalib.hpp under src/include/ or include/",
                root.display()
            )
        });
    }

    let (major, minor) = library_version(idadir);
    let tag = newest_release_tag(major, minor);
    let root = fetch_sdk(&tag);
    find_include(&root)
        .unwrap_or_else(|| panic!("fetched SDK at {} has no idalib.hpp", root.display()))
}

/// The include dir under an SDK root: `src/include/` (the GitHub repo layout) or
/// `include/` (the classic SDK zip). `None` if neither holds `idalib.hpp`.
fn find_include(root: &Path) -> Option<PathBuf> {
    ["src/include", "include"]
        .into_iter()
        .map(|sub| root.join(sub))
        .find(|dir| dir.join("idalib.hpp").exists())
}

const VERSION_HINT: &str = "set IDA_SDK_DIR to a local SDK checkout to skip version auto-detection";

/// idalib's `get_library_version(major, minor, build)`.
type GetLibraryVersion = unsafe extern "C" fn(*mut c_int, *mut c_int, *mut c_int) -> bool;

/// The installed IDA's `(major, minor)`, by loading the runtime + idalib and calling
/// `get_library_version` (no headers needed, so it runs before the fetch that uses the tag).
/// The dlopen differs per OS ([`load_version_fn`]); the call is shared.
fn library_version(idadir: &Path) -> (i32, i32) {
    let get = load_version_fn(idadir);
    let (mut major, mut minor, mut build) = (0, 0, 0);
    unsafe { get(&mut major, &mut minor, &mut build) };
    (major, minor)
}

/// dlopen the runtime + idalib and resolve `get_library_version`. Both libraries are leaked so
/// the returned pointer stays valid for the process. Unix preloads the runtime `RTLD_GLOBAL` in
/// case idalib's runpath misses it; Windows loads `ida.dll` first so idalib's import of it from
/// the same dir resolves.
#[cfg(unix)]
fn load_version_fn(idadir: &Path) -> GetLibraryVersion {
    use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_LAZY, Symbol};

    let idalib = idadir.join(IDALIB_LIB);
    unsafe {
        if let Ok(ida) = Library::open(Some(idadir.join(RUNTIME_LIB)), RTLD_LAZY | RTLD_GLOBAL) {
            std::mem::forget(ida);
        }
        let lib = Library::open(Some(&idalib), RTLD_LAZY | RTLD_GLOBAL).unwrap_or_else(|e| {
            panic!(
                "could not dlopen {} ({e}); {VERSION_HINT}",
                idalib.display()
            )
        });
        let get: Symbol<GetLibraryVersion> =
            lib.get(b"get_library_version\0").unwrap_or_else(|e| {
                panic!(
                    "no get_library_version in {} ({e}); {VERSION_HINT}",
                    idalib.display()
                )
            });
        let ptr = *get;
        std::mem::forget(lib);
        ptr
    }
}

#[cfg(windows)]
fn load_version_fn(idadir: &Path) -> GetLibraryVersion {
    use libloading::os::windows::{Library, Symbol};

    let idalib = idadir.join(IDALIB_LIB);
    unsafe {
        if let Ok(ida) = Library::new(idadir.join(RUNTIME_LIB)) {
            std::mem::forget(ida);
        }
        let lib = Library::new(&idalib).unwrap_or_else(|e| {
            panic!("could not load {} ({e}); {VERSION_HINT}", idalib.display())
        });
        let get: Symbol<GetLibraryVersion> =
            lib.get(b"get_library_version\0").unwrap_or_else(|e| {
                panic!(
                    "no get_library_version in {} ({e}); {VERSION_HINT}",
                    idalib.display()
                )
            });
        let ptr = *get;
        std::mem::forget(lib);
        ptr
    }
}

/// The newest `vMAJOR.MINOR.*-release` tag matching major.minor (IDA's build number isn't
/// the SDK patch level), taking the highest patch.
fn newest_release_tag(major: i32, minor: i32) -> String {
    let prefix = format!("v{major}.{minor}.");
    let out = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(["ls-remote", "--tags", "--refs", SDK_REPO])
        .output()
        .unwrap_or_else(|e| {
            panic!("`git ls-remote` failed ({e}); install git or set IDA_SDK_DIR to a local SDK checkout")
        });
    assert!(
        out.status.success(),
        "`git ls-remote {SDK_REPO}` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.rsplit('/').next()) // refs/tags/v9.3.1-release -> v9.3.1-release
        .filter_map(|tag| {
            let patch: u32 = tag
                .strip_prefix(&prefix)?
                .strip_suffix("-release")?
                .parse()
                .ok()?;
            Some((patch, tag.to_owned()))
        })
        .max_by_key(|(patch, _)| *patch)
        .map(|(_, tag)| tag)
        .unwrap_or_else(|| {
            panic!(
                "no SDK release tag matching v{major}.{minor}.*-release in {SDK_REPO}; \
                 set IDA_SDK_DIR to a local SDK checkout"
            )
        })
}

/// Fetch the SDK at `tag` into the cache and return its root (partial + sparse checkout of
/// `src/include` only). A no-op once the completion marker exists.
fn fetch_sdk(tag: &str) -> PathBuf {
    let dir = cache_dir(tag);
    let marker = dir.join(MARKER);
    if marker.exists() {
        return dir;
    }
    preflight_git();
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|e| panic!("could not create cache dir {}: {e}", parent.display()));
    }

    // Stage in a unique dir then rename into place, so concurrent builds never see a
    // half-written cache.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let staging = dir.with_file_name(format!(".staging-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    let staging_str = staging.to_str().expect("staging path is not UTF-8");

    run_git(
        None,
        &[
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            "--depth",
            "1",
            "--branch",
            tag,
            SDK_REPO,
            staging_str,
        ],
    );
    run_git(Some(&staging), &["sparse-checkout", "init", "--cone"]);
    run_git(Some(&staging), &["sparse-checkout", "set", "src/include"]);
    run_git(Some(&staging), &["checkout"]);
    std::fs::write(staging.join(MARKER), tag).ok();

    match std::fs::rename(&staging, &dir) {
        Ok(()) => {}
        // Lost the race: another build published the cache first. Drop our staging copy.
        Err(_) if marker.exists() => {
            let _ = std::fs::remove_dir_all(&staging);
        }
        Err(e) => panic!(
            "could not publish SDK cache {} -> {}: {e}",
            staging.display(),
            dir.display()
        ),
    }
    dir
}

/// Written inside a finished checkout; its presence means the cache entry is complete.
const MARKER: &str = ".idakit-sdk-complete";

fn cache_dir(tag: &str) -> PathBuf {
    env::var_os("IDA_SDK_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(dirs::cache_dir)
        .unwrap_or_else(env::temp_dir)
        .join("idakit")
        .join("ida-sdk")
        .join(tag)
}

fn preflight_git() {
    let ok = Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        ok,
        "`git` is required to fetch the IDA SDK; install git or set IDA_SDK_DIR to a local checkout"
    );
}

fn run_git(cwd: Option<&Path>, args: &[&str]) {
    let mut cmd = Command::new("git");
    cmd.env("GIT_TERMINAL_PROMPT", "0").args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to run `git {}`: {e}", args.join(" ")));
    assert!(status.success(), "`git {}` failed", args.join(" "));
}
