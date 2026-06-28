use std::env;
use std::ffi::c_int;
use std::path::{Path, PathBuf};
use std::process::Command;

// Compile the C++ facade against the IDA SDK headers and link the kernel.
//
// __EA64__  -> ea_t is 64-bit (bf4 / any 64-bit target).
// __LINUX__ -> platform (pro.h auto-detects from __linux__, set explicitly anyway).
//
// The SDK headers are resolved in order: an explicit `IDA_SDK_DIR` checkout, else a
// version-matched checkout fetched from the public SDK repo into a persistent cache.
// The installed IDA tells us its own version (dlopen + get_library_version), so the
// fetched headers always match the runtime we link against.

const SDK_REPO: &str = "https://github.com/HexRaysSA/ida-sdk.git";

fn main() {
    // docs.rs has no IDA runtime and no network. Emit nothing native and bail; the
    // FFI items still render (rustdoc documents `extern` blocks without linking).
    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let idadir = resolve_idadir();
    let runtime = idadir.join("libida.so");
    assert!(
        runtime.exists(),
        "libida.so not found at {} - set IDADIR to your IDA install directory",
        runtime.display()
    );

    let sdk_include = resolve_sdk_include(&idadir);
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

    let idadir_str = idadir.to_str().expect("IDADIR is not UTF-8");
    println!("cargo:rustc-link-search=native={idadir_str}");
    println!("cargo:rustc-link-lib=dylib=ida");
    println!("cargo:rustc-link-lib=dylib=idalib");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{idadir_str}");
    println!("cargo:lib_dir={idadir_str}"); // -> DEP_IDA_LIB_DIR for dependents' rpath
    println!("cargo:rerun-if-changed=facade/idakit_facade.cpp");
    println!("cargo:rerun-if-changed=facade/idakit_facade.h");
    println!("cargo:rerun-if-env-changed=IDADIR");
    println!("cargo:rerun-if-env-changed=IDA_SDK_DIR");
    println!("cargo:rerun-if-env-changed=IDA_SDK_CACHE_DIR");
    println!("cargo:rerun-if-env-changed=DOCS_RS");
}

fn resolve_idadir() -> PathBuf {
    env::var_os("IDADIR").map(PathBuf::from).unwrap_or_else(|| {
        let home = env::var_os("HOME").expect("HOME unset");
        Path::new(&home).join("ida-pro-9.3")
    })
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

/// dlopen the installed `libidalib.so` and read its `(major, minor)` version. A
/// `dlsym` needs no SDK headers, so this runs before the headers exist — it is how
/// the fetch path learns which SDK tag to pull.
fn library_version(idadir: &Path) -> (i32, i32) {
    use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_LAZY, Symbol};

    let hint = "set IDA_SDK_DIR to a local SDK checkout to skip version auto-detection";
    let idalib = idadir.join("libidalib.so");
    unsafe {
        // libidalib depends on libida; preload it with global visibility (and leak it,
        // so it stays resident) in case libidalib's own runpath doesn't resolve it.
        if let Ok(ida) = Library::open(Some(idadir.join("libida.so")), RTLD_LAZY | RTLD_GLOBAL) {
            std::mem::forget(ida);
        }
        let lib = Library::open(Some(&idalib), RTLD_LAZY | RTLD_GLOBAL)
            .unwrap_or_else(|e| panic!("could not dlopen {} ({e}); {hint}", idalib.display()));
        let get: Symbol<unsafe extern "C" fn(*mut c_int, *mut c_int, *mut c_int) -> bool> =
            lib.get(b"get_library_version\0").unwrap_or_else(|e| {
                panic!(
                    "no get_library_version in {} ({e}); {hint}",
                    idalib.display()
                )
            });
        let (mut major, mut minor, mut build) = (0, 0, 0);
        get(&mut major, &mut minor, &mut build);
        std::mem::forget(lib);
        (major, minor)
    }
}

/// The newest `vMAJOR.MINOR.PATCH-release` tag in the SDK repo. IDA's build number is
/// a datestamp, not the SDK patch level, so we match major.minor and take the highest
/// patch.
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

/// Fetch the SDK at `tag` into a persistent cache and return its root. Only the
/// `src/include/` subtree is materialized (partial + sparse checkout). Re-runs are a
/// no-op once the completion marker is present.
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

    // Clone into a unique staging dir, then atomically rename into place, so two
    // concurrent builds racing on the shared cache can't observe a half-written tree.
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

/// Marker file written inside a finished checkout; its presence means the cache entry
/// is complete (an interrupted clone leaves only a `.staging-*` dir).
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
