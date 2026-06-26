//! Idiomatic core, built on the empirically validated concurrency model.
//!
//! The IDA kernel must run on the process main thread (tid == pid). Heavy ops
//! (init_library, open_database, decompile, auto-analysis) dispatch to an internal
//! kernel thread pool that coordinates through the main thread; called from any other
//! thread they deadlock in `qsem_wait`. So idakit uses a main-thread executor:
//! `run_on_main` takes over the main thread to init the kernel and pump a job queue,
//! while application logic runs on a spawned thread and marshals closures back via an
//! `Ida` handle. `Idb` only exists inside a job on the main thread; `&Idb` vs
//! `&mut Idb` gives borrow-checked read/write separation.

use std::ffi::{c_char, CStr, CString};
use std::marker::PhantomData;
use std::ptr;
use std::sync::mpsc::{channel, Sender};
use std::thread;

use idakit_sys as sys;

/// The open database. `!Send + !Sync`: it only ever exists inside a job running on
/// the kernel (main) thread, so the "main thread only" rule is enforced at compile time.
pub struct Idb {
    _not_send: PhantomData<*const ()>,
}

impl Idb {
    pub fn open(&mut self, path: &str) -> Result<(), i32> {
        let c = CString::new(path).expect("nul in path");
        let rc = unsafe { sys::open_database(c.as_ptr(), false, ptr::null()) };
        if rc == 0 { Ok(()) } else { Err(rc) }
    }

    pub fn close(&mut self, save: bool) {
        unsafe { sys::close_database(save) }
    }

    pub fn func_count(&self) -> usize {
        unsafe { sys::idakit_func_qty() }
    }

    pub fn func_ea(&self, n: usize) -> u64 {
        unsafe { sys::idakit_func_ea(n) }
    }

    pub fn func_name(&self, ea: u64) -> String {
        let mut buf = [0 as c_char; 512];
        let n = unsafe { sys::idakit_func_name(ea, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            return String::new();
        }
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    }

    pub fn segment_count(&self) -> i32 {
        unsafe { sys::idakit_seg_qty() }
    }
}

type Job = Box<dyn FnOnce(&mut Idb) + Send>;

/// A `Send + Sync + Clone` handle to the kernel. Hand it to any thread; calls are
/// marshaled to and run on the main thread.
#[derive(Clone)]
pub struct Ida {
    tx: Sender<Job>,
}

impl Ida {
    pub fn call<R, F>(&self, f: F) -> R
    where
        F: FnOnce(&mut Idb) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (rtx, rrx) = channel();
        self.tx
            .send(Box::new(move |idb| {
                let _ = rtx.send(f(idb));
            }))
            .expect("kernel pump gone");
        rrx.recv().expect("kernel dropped the job")
    }
}

fn os_tid() -> i64 {
    unsafe { libc::syscall(libc::SYS_gettid) }
}

/// Take over the CURRENT thread (which MUST be the process main thread) to initialize
/// the IDA kernel and pump jobs. `app` runs on a spawned thread with an `Ida` handle.
pub fn run_on_main<R, F>(app: F) -> R
where
    F: FnOnce(Ida) -> R + Send + 'static,
    R: Send + 'static,
{
    let (tid, pid) = (os_tid(), std::process::id() as i64);
    assert_eq!(
        tid, pid,
        "idakit::run_on_main must be called from the process MAIN thread \
         (tid={tid} != pid={pid}); the IDA kernel deadlocks otherwise"
    );

    unsafe {
        sys::init_library(0, ptr::null_mut());
    }

    let (tx, rx) = channel::<Job>();
    let (rtx, rrx) = channel::<R>();
    let app_thread = thread::Builder::new()
        .name("idakit-app".into())
        .spawn(move || {
            let r = app(Ida { tx });
            let _ = rtx.send(r);
        })
        .expect("spawn app thread");

    let mut idb = Idb { _not_send: PhantomData };
    while let Ok(job) = rx.recv() {
        job(&mut idb);
    }
    let _ = app_thread.join();
    rrx.recv().expect("app thread panicked before returning")
}
