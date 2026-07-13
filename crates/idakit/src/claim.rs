//! Re-point libida's "main thread" claim onto a thread we pick.
//!
//! libida marks the first thread to call [`is_main_thread`](sys::is_main_thread) as
//! "main" via a nullable global `g_main`. DT_NEEDED-linked, its static init claims
//! the OS main thread at load, and the kernel's heavy ops only run on that thread.
//! To free the OS main thread we null `g_main` on the kernel thread and let
//! `is_main_thread` re-claim it for us, before `init_library`.
//!
//! `g_main` is private, so we recover its address by decoding the PC-relative load
//! in `is_main_thread`'s prologue instead of hardcoding an offset: `mov register,
//! [rip+disp32]` on x86-64, an `adrp`+`ldr` pair on aarch64.

use std::ffi::c_void;
use std::ptr;

use idakit_sys as sys;

/// libida's private `g_main`: whatever thread it names is the kernel "main" thread.
struct MainClaim(*mut *mut c_void);

impl MainClaim {
    /// Recovers `g_main`'s address by decoding the PC-relative load in `is_main_thread`'s
    /// prologue ([`decode_g_main`], per target arch).
    fn locate() -> Result<Self, String> {
        let g_main = decode_g_main(sys::is_main_thread as *const u8)?;
        Ok(Self(g_main as *mut *mut c_void))
    }

    /// Re-points `g_main` at the calling thread.
    ///
    /// Run on the kernel thread before `init_library`.
    fn reclaim(self) -> Result<(), String> {
        // SAFETY: `self.0` addresses libida's writable `g_main` (a `qthread_t`).
        // Nulling it makes the next `is_main_thread()` claim this thread. Runs once
        // on the kernel thread before any kernel call, so nothing races it.
        unsafe { self.0.write(ptr::null_mut()) };

        // SAFETY: plain C-ABI call; null `g_main` claims the caller.
        if unsafe { sys::is_main_thread() } {
            Ok(())
        } else {
            Err("re-claim did not take (located g_main address is wrong)".to_owned())
        }
    }
}

/// x86-64: decodes `is_main_thread`'s `g_main` load, `mov register, [rip+disp32]` (REX.W
/// `48 8b`, ModRM mod=00 rm=101).
///
/// The Linux build emits it as the first instruction; the macOS and Windows builds push a
/// stack frame first, so this scans a short window for the first such load (the aarch64 path
/// scans for the same reason). `g_main` sits at rip (past the 7-byte instruction) + disp32.
/// On Windows the function's address is first an import/incremental-link thunk (`jmp qword
/// [rip+disp32]`, `ff 25`); [`follow_jmp_thunk`] resolves it to the body.
#[cfg(target_arch = "x86_64")]
fn decode_g_main(entry: *const u8) -> Result<*const u8, String> {
    const WINDOW: usize = 32;

    // SAFETY: `entry` is a mapped code pointer; a thunk and its slot are mapped (see fn doc).
    let entry = unsafe { follow_jmp_thunk(entry) };

    // SAFETY: `entry` is a mapped executable function; the load we decode lies within its
    // first WINDOW bytes.
    let head: [u8; WINDOW] = unsafe { ptr::read(entry.cast()) };

    for k in 0..=WINDOW - 7 {
        // REX.W, opcode 0x8b, ModRM mod=00 rm=101 (rip-relative); register field ignored.
        if head[k] == 0x48 && head[k + 1] == 0x8b && head[k + 2] & 0xc7 == 0x05 {
            let disp = i32::from_le_bytes([head[k + 3], head[k + 4], head[k + 5], head[k + 6]]);
            // rip points past the 7-byte instruction at offset k.
            return Ok(entry.wrapping_offset(k as isize + 7 + disp as isize));
        }
    }
    Err(format!(
        "no rip-relative g_main load in is_main_thread prologue {head:02x?}"
    ))
}

/// Follows a `jmp qword [rip+disp32]` thunk (`ff 25 disp32`) to its target.
///
/// On Windows the address of an imported function is such a thunk rather than the body; the
/// real address lives in the pointer slot at rip+disp32. Elsewhere the address is already the
/// body (its leading bytes are the prologue), so `entry` is returned unchanged.
///
/// # Safety
/// `entry` must be a mapped code pointer. When it is a thunk, its 6-byte instruction and the
/// pointer slot it references (both in the same image) must be mapped, which holds for a
/// real thunk.
#[cfg(target_arch = "x86_64")]
unsafe fn follow_jmp_thunk(entry: *const u8) -> *const u8 {
    // SAFETY: caller guarantees `entry` is a mapped code pointer, so its first 6 bytes read.
    let head: [u8; 6] = unsafe { ptr::read(entry.cast()) };
    if head[0] == 0xff && head[1] == 0x25 {
        let disp = i32::from_le_bytes([head[2], head[3], head[4], head[5]]);
        // rip points past the 6-byte instruction; the slot there holds the real target.
        let slot = entry.wrapping_offset(6 + disp as isize) as *const *const u8;
        // SAFETY: a real `ff 25` thunk's slot is a mapped pointer into the same image.
        return unsafe { *slot };
    }
    entry
}

/// aarch64: decodes `is_main_thread`'s `&g_main` materialization, an `adrp Xd, page` +
/// `ldr Xt, [Xd, off]` pair.
///
/// A stack-save prologue precedes it, so this scans a short window for the first such pair:
/// `g_main = (adrp_pc & !0xfff) + (page << 12) + off`.
#[cfg(target_arch = "aarch64")]
fn decode_g_main(entry: *const u8) -> Result<*const u8, String> {
    const WINDOW: usize = 8;
    // SAFETY: `entry` is a mapped executable function; its first WINDOW 4-byte
    // instructions lie within the body.
    let insns: [u32; WINDOW] = unsafe { ptr::read(entry.cast()) };

    for (i, &adrp) in insns.iter().enumerate() {
        // ADRP: bit31=1, bits28..24=10000 (mask 0x9f00_0000 -> 0x9000_0000).
        if adrp & 0x9f00_0000 != 0x9000_0000 {
            continue;
        }
        let rd = adrp & 0x1f;
        let imm = i64::from((((adrp >> 5) & 0x7_ffff) << 2) | ((adrp >> 29) & 0x3));
        let page = (imm ^ 0x10_0000) - 0x10_0000; // sign-extend the 21-bit page count
        let adrp_pc = entry.wrapping_add(i * 4) as u64;
        let base = ((adrp_pc & !0xfff) as i64 + (page << 12)) as u64;

        // First following `ldr Xt, [Xd, off]` (64-bit unsigned offset, mask
        // 0xffc0_0000 -> 0xf940_0000) that dereferences Xd carries the offset.
        for &ldr in &insns[i + 1..] {
            if ldr & 0xffc0_0000 != 0xf940_0000 || (ldr >> 5) & 0x1f != rd {
                continue;
            }
            let off = u64::from((ldr >> 10) & 0xfff) * 8; // imm12, scaled by access size
            return Ok(base.wrapping_add(off) as *const u8);
        }
    }
    Err("is_main_thread has no adrp+ldr g_main load in its prologue".to_owned())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn decode_g_main(_entry: *const u8) -> Result<*const u8, String> {
    compile_error!("g_main steal supports x86-64 and aarch64 only");
}

/// Claims the kernel "main" thread for the caller, before `init_library`.
///
/// `Err` carries why the steal could not be done (no recovery: the kernel needs it).
pub(crate) fn steal_main() -> Result<(), String> {
    MainClaim::locate()?.reclaim()
}

// The decoders do dense pointer/bit math over machine-code bytes; exercise them on synthetic
// buffers with hand-computed expected addresses, so a regression surfaces here instead of as an
// opaque "re-claim did not take" from a full kernel bring-up. Each arch tests its own decoder.
#[cfg(all(test, target_arch = "x86_64"))]
mod x86_64_tests {
    use assert2::assert;

    use super::*;

    /// A 32-byte (WINDOW) code buffer padded with `0x90` nops, holding `mov register,[rip+disp]`
    /// (`48 8b 05 <disp32>`) at `offset`.
    fn code_at(offset: usize, disp: i32) -> [u8; 32] {
        let mut buf = [0x90u8; 32];
        buf[offset] = 0x48;
        buf[offset + 1] = 0x8b;
        buf[offset + 2] = 0x05;
        buf[offset + 3..offset + 7].copy_from_slice(&disp.to_le_bytes());
        buf
    }

    #[test]
    fn decodes_load_at_prologue_start() {
        let code = code_at(0, 0x1234);
        let entry = code.as_ptr();
        // g_main sits at rip (past the 7-byte instruction) + disp.
        assert!(decode_g_main(entry).unwrap() == entry.wrapping_offset(7 + 0x1234));
    }

    #[test]
    fn scans_past_a_stack_frame() {
        let code = code_at(6, -0x40);
        let entry = code.as_ptr();
        assert!(decode_g_main(entry).unwrap() == entry.wrapping_offset(6 + 7 - 0x40));
    }

    #[test]
    fn no_rip_load_in_window_is_err() {
        let code = [0x90u8; 32];
        assert!(decode_g_main(code.as_ptr()).is_err());
    }

    #[test]
    fn follows_thunk_to_slot_target() {
        // The slot at (instruction end + disp) holds the real body pointer; keep it 8-aligned.
        #[repr(align(8))]
        struct Aligned([u8; 16]);
        let target = 0u8;
        let body = &target as *const u8;
        let mut buf = Aligned([0u8; 16]);
        buf.0[0] = 0xff;
        buf.0[1] = 0x25;
        buf.0[2..6].copy_from_slice(&2i32.to_le_bytes()); // disp=2 -> slot at entry+8
        buf.0[8..16].copy_from_slice(&(body as usize).to_le_bytes());
        let entry = buf.0.as_ptr();
        // SAFETY: `entry` is a valid `ff 25` thunk whose 8-aligned slot holds a live pointer.
        assert!(unsafe { follow_jmp_thunk(entry) } == body);
    }

    #[test]
    fn non_thunk_entry_passes_through() {
        let code = code_at(0, 0);
        let entry = code.as_ptr();
        // SAFETY: `entry`'s first 6 bytes are readable and are not an `ff 25` thunk.
        assert!(unsafe { follow_jmp_thunk(entry) } == entry);
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod aarch64_tests {
    use assert2::assert;

    use super::*;

    // `adrp x0, +1 page` (immlo=1, immhi=0) then `ldr x0, [x0, #24]` (imm12=3, scaled x8):
    // g_main = (adrp page base + 0x1000) + 24.
    const ADRP_X0_PLUS1: u32 = 0xB000_0000;
    const LDR_X0_X0_24: u32 = 0xF940_0C00;

    /// An 8-instruction window padded with `0` (not a valid `adrp`, so inert), holding the
    /// adrp+ldr pair at `offset`.
    fn window(offset: usize) -> [u32; 8] {
        let mut w = [0u32; 8];
        w[offset] = ADRP_X0_PLUS1;
        w[offset + 1] = LDR_X0_X0_24;
        w
    }

    fn expected(entry: *const u8, adrp_index: usize) -> *const u8 {
        let adrp_pc = entry as usize + adrp_index * 4;
        ((adrp_pc & !0xfff) + 0x1000 + 24) as *const u8
    }

    #[test]
    fn decodes_adrp_ldr_at_start() {
        let w = window(0);
        let entry = w.as_ptr().cast::<u8>();
        assert!(decode_g_main(entry).unwrap() == expected(entry, 0));
    }

    #[test]
    fn scans_past_a_stack_frame() {
        let w = window(2);
        let entry = w.as_ptr().cast::<u8>();
        assert!(decode_g_main(entry).unwrap() == expected(entry, 2));
    }

    #[test]
    fn no_adrp_ldr_in_window_is_err() {
        let w = [0u32; 8];
        assert!(decode_g_main(w.as_ptr().cast::<u8>()).is_err());
    }
}
