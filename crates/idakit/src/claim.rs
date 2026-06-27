//! Re-point libida's "main thread" claim onto a thread we pick.
//!
//! libida marks the first thread to call [`is_main_thread`](sys::is_main_thread) as
//! "main" via a nullable global `g_main`. DT_NEEDED-linked, its static init claims
//! the OS main thread at load, and the kernel's heavy ops only run on that thread.
//! To free the OS main thread we null `g_main` on the kernel thread and let
//! `is_main_thread` re-claim it for us, before `init_library`.
//!
//! `g_main` is private, so we decode the rip-relative load opening `is_main_thread`
//! (`48 8b 3d <disp32>` = `mov rdi, [rip+disp32]`) instead of hardcoding an offset.

use std::ffi::c_void;
use std::ptr;

use idakit_sys as sys;

/// libida's private `g_main`: whatever thread it names is the kernel "main" thread.
struct MainClaim(*mut *mut c_void);

impl MainClaim {
    /// Decode `g_main`'s address from the first instruction of `is_main_thread`.
    fn locate() -> Self {
        #[cfg(not(target_arch = "x86_64"))]
        compile_error!("g_main steal is x86-64 only");

        let entry = sys::is_main_thread as *const u8;
        // SAFETY: `entry` is a mapped executable function; its first 7 bytes (the
        // `mov reg, [rip+disp32]` we decode) lie within the body.
        let head: [u8; 7] = unsafe { ptr::read(entry.cast()) };

        // REX.W, opcode 0x8b, ModRM mod=00 rm=101 (rip-relative); reg field ignored.
        let [0x48, 0x8b, modrm, disp @ ..] = head else {
            panic!("is_main_thread: unexpected prologue {head:02x?}");
        };
        assert!(
            modrm & 0xc7 == 0x05,
            "is_main_thread: not a rip-relative load"
        );

        // rip points past the 7-byte instruction.
        let g_main = entry.wrapping_offset(7 + i32::from_le_bytes(disp) as isize);
        Self(g_main as *mut *mut c_void)
    }

    /// Re-point `g_main` at the calling thread. Run on the kernel thread before
    /// `init_library`; panics if the re-claim does not take.
    fn reclaim(self) {
        // SAFETY: `self.0` addresses libida's writable `g_main` (a `qthread_t`).
        // Nulling it makes the next `is_main_thread()` claim this thread. Runs once
        // on the kernel thread before any kernel call, so nothing races it.
        unsafe { self.0.write(ptr::null_mut()) };

        // SAFETY: plain C-ABI call; null `g_main` claims the caller.
        assert!(
            unsafe { sys::is_main_thread() },
            "g_main reclaim did not take"
        );
    }
}

/// Claim the kernel "main" thread for the caller, before `init_library`.
pub(crate) fn steal_main() {
    MainClaim::locate().reclaim();
}
