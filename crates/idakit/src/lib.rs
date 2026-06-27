//! Idiomatic core over the IDA kernel.
//!
//! All work funnels to the thread that claimed the kernel ([`Ida::run_on_main`]);
//! other threads marshal closures to it via an [`Ida`] handle. `Idb` exists only
//! inside a job there, so `&Idb`/`&mut Idb` gives borrow-checked read/write
//! separation. See `design.md` §4.1 for the threading model.

use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr;
use std::sync::mpsc::{Sender, channel};
use std::thread;

use idakit_sys as sys;

mod decompile;
mod ea;
mod error;
mod ffi;
mod func;
mod segment;
mod ty;
mod xref;

pub use decompile::{Cfunc, CtreeCounts};
pub use ea::{BADADDR, Ea, Offset};
pub use error::{Error, Result};
pub use func::{Func, Functions};
pub use segment::{Segment, Segments};
pub use ty::{Member, Members, TypeInfo};
pub use xref::{CodeRef, DataRef, Xref, XrefKind};

/// The open database. `!Send + !Sync`, so it exists only on the kernel thread.
/// Reads borrow `&Idb` (returning [`Func`]/[`Segment`] views); writes take
/// `&mut Idb`, so a read view can't be held across a write.
pub struct Idb {
    /// Interior mutability lets `decompile(&self)` init Hex-Rays lazily.
    hexrays_ready: Cell<bool>,
    _not_send: PhantomData<*const ()>,
}

impl Idb {
    fn new() -> Self {
        Self {
            hexrays_ready: Cell::new(false),
            _not_send: PhantomData,
        }
    }

    /// Open a database file. Re-opening after [`close`](Self::close) works.
    pub fn open(&mut self, path: &str) -> Result<()> {
        let rc = ffi::with_cstr(path, "path", |p| unsafe {
            sys::open_database(p, false, ptr::null())
        })?;
        if rc == 0 {
            Ok(())
        } else {
            Err(Error::Open {
                path: path.to_owned(),
                code: rc,
            })
        }
    }

    /// Close the current database, optionally saving analysis back to the `.i64`.
    pub fn close(&mut self, save: bool) {
        unsafe { sys::close_database(save) }
    }

    /// A typed cursor at `ea`; does not verify a function lives there (absence
    /// surfaces lazily). Use [`functions`](Self::functions) to enumerate real ones.
    #[inline]
    #[must_use]
    pub fn func(&self, ea: Ea) -> Func<'_> {
        Func::new(ea, self)
    }

    /// Iterate every function in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn functions(&self) -> Functions<'_> {
        Functions::new(self)
    }

    /// Iterate every segment in the database, in kernel order.
    #[inline]
    #[must_use]
    pub fn segments(&self) -> Segments<'_> {
        Segments::new(self)
    }

    /// Read bytes at `ea` into `buf`, returning how many were supplied. Zero-alloc;
    /// reuse one buffer on hot loops. [`bytes`](Self::bytes) is the owning shortcut.
    pub fn read_into(&self, ea: Ea, buf: &mut [u8]) -> usize {
        let got = unsafe { sys::idakit_get_bytes(ea.get(), buf.as_mut_ptr().cast(), buf.len()) };
        (got.max(0) as usize).min(buf.len())
    }

    /// Read up to `len` bytes at `ea` into a fresh vector (empty on failure).
    #[must_use]
    pub fn bytes(&self, ea: Ea, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let got = self.read_into(ea, &mut buf);
        buf.truncate(got);
        buf
    }

    /// All cross-references targeting `ea`. Owned `Vec`: the facade is a bulk
    /// count-then-fill API, not a cursor.
    #[must_use]
    pub fn xrefs_to(&self, ea: Ea) -> Vec<Xref> {
        // Count (cap 0 writes nothing), then fill exact buffers.
        let n = unsafe {
            sys::idakit_xrefs_to(
                ea.get(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        if n == 0 {
            return Vec::new();
        }
        let mut from = vec![0u64; n];
        let mut types = vec![0u8; n];
        let mut iscode = vec![0u8; n];
        let written = unsafe {
            sys::idakit_xrefs_to(
                ea.get(),
                from.as_mut_ptr(),
                types.as_mut_ptr(),
                iscode.as_mut_ptr(),
                n,
            )
        };
        let written = written.min(n);
        (0..written)
            .filter_map(|i| Xref::from_raw(from[i], types[i], iscode[i]))
            .collect()
    }

    /// Resolve a named type and its member layout. `Err` if no such type exists.
    pub fn type_named(&self, name: &str) -> Result<TypeInfo<'_>> {
        let handle = ffi::with_cstr(name, "name", |p| unsafe { sys::idakit_type_open(p) })?;
        if handle.is_null() {
            return Err(Error::TypeNotFound {
                name: name.to_owned(),
            });
        }
        Ok(TypeInfo::from_handle(handle, self))
    }

    /// Decompile the function containing `ea` (inits Hex-Rays on first use).
    pub fn decompile(&self, ea: Ea) -> Result<Cfunc<'_>> {
        if !self.hexrays_ready.get() {
            let rc = unsafe { sys::idakit_hexrays_init() };
            if rc != 1 {
                return Err(Error::HexRaysInit { code: rc });
            }
            self.hexrays_ready.set(true);
        }
        let handle = unsafe { sys::idakit_decompile(ea.get()) };
        if handle.is_null() {
            return Err(Error::Decompile { ea: ea.get() });
        }
        Ok(Cfunc::from_handle(handle, self))
    }

    /// Rename the item at `ea`.
    pub fn rename(&mut self, ea: Ea, name: &str) -> Result<()> {
        let ok = ffi::with_cstr(name, "name", |p| unsafe { sys::set_name(ea.get(), p, 0) })?;
        if ok {
            Ok(())
        } else {
            Err(Error::WriteRejected {
                op: "rename",
                ea: ea.get(),
            })
        }
    }

    /// Set the comment at `ea`. `repeatable` repeats it at every reference.
    pub fn set_comment(&mut self, ea: Ea, text: &str, repeatable: bool) -> Result<()> {
        let ok = ffi::with_cstr(text, "comment", |p| unsafe {
            sys::set_cmt(ea.get(), p, repeatable)
        })?;
        if ok {
            Ok(())
        } else {
            Err(Error::WriteRejected {
                op: "set_comment",
                ea: ea.get(),
            })
        }
    }
}

type Job = Box<dyn FnOnce(&mut Idb) + Send>;

/// A `Send + Clone` handle to the kernel; marshal closures to it from any thread.
#[derive(Clone)]
pub struct Ida {
    tx: Sender<Job>,
}

impl Ida {
    /// Claim and drive the kernel on the current thread, running `app` on a
    /// spawned thread with an [`Ida`] handle. Must be called from the OS main
    /// thread (`tid == pid`) — a constraint of the current direct-link layout,
    /// not the kernel; see `design.md` §4.1.
    pub fn run_on_main<R, F>(app: F) -> R
    where
        F: FnOnce(Ida) -> R + Send + 'static,
        R: Send + 'static,
    {
        let (tid, pid) = (os_tid(), std::process::id() as i64);
        assert_eq!(
            tid, pid,
            "Ida::run_on_main must run on the OS main thread (tid={tid} != pid={pid}); \
             the kernel was claimed there at load and any other thread deadlocks"
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

        let mut idb = Idb::new();
        while let Ok(job) = rx.recv() {
            job(&mut idb);
        }
        let _ = app_thread.join();
        rrx.recv().expect("app thread panicked before returning")
    }

    /// Run a closure against the open database on the kernel thread. Any thread.
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
