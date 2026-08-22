//! Makes worker processes die with the runner, on every supported platform.
//!
//! A test run that leaves live kernels behind is the failure mode this exists to prevent: they hold
//! hundreds of megabytes each and keep database file locks. Killing children in a normal shutdown
//! path is not enough, because the runner may itself be killed (Ctrl-C, a CI timeout, a crash), so
//! the guarantee has to come from the operating system.
//!
//! Windows uses a [job object] with kill-on-close, which fires even when the runner dies abruptly,
//! since the kernel closes the handle on process exit. Linux arms `PR_SET_PDEATHSIG` in the child.
//! Other Unixes have no equivalent, so [`Nursery::adopt`] falls back to the runner's own cleanup.
//!
//! [job object]: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects

use std::io;
use std::process::{Child, Command};

/// Owns the platform mechanism that ties worker lifetimes to the runner's.
///
/// Dropping it releases that mechanism, which on Windows is what terminates any surviving worker.
#[derive(Debug)]
pub struct Nursery {
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

impl Nursery {
    /// Creates the nursery.
    ///
    /// # Errors
    /// On Windows, if the job object cannot be created or configured.
    #[allow(
        clippy::unnecessary_wraps,
        reason = "the Result is load-bearing on Windows, where the job object can fail to be created; the Unix body simply has nothing to fail at"
    )]
    pub fn new() -> io::Result<Self> {
        #[cfg(windows)]
        {
            use std::ptr;

            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };

            // SAFETY: a null security descriptor and name asks for an unnamed, default-secured job.
            let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` is a live, correctly-sized value of the type the class names.
            let ok = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    ptr::from_mut(&mut info).cast(),
                    u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                        .expect("struct size fits in u32"),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                // SAFETY: `job` is a live handle this function created and is about to abandon.
                unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
                return Err(err);
            }
            Ok(Self { job })
        }
        #[cfg(not(windows))]
        Ok(Self {})
    }

    /// Configures `command` so the child it spawns is bound to this runner's lifetime.
    #[allow(
        unused_variables,
        clippy::unused_self,
        clippy::needless_pass_by_ref_mut,
        reason = "the `&mut` is load-bearing on Linux; other platforms have nothing to do here"
    )]
    pub fn configure(&self, command: &mut Command) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;

            // SAFETY: `pre_exec` runs between fork and exec, where only async-signal-safe calls are
            // allowed. `prctl` is such a call, and this one only arms a signal for the child.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
    }

    /// Adopts a spawned child so it cannot outlive this nursery.
    ///
    /// # Errors
    /// On Windows, if the child cannot be assigned to the job object.
    #[allow(
        unused_variables,
        clippy::unused_self,
        clippy::missing_const_for_fn,
        clippy::unnecessary_wraps,
        reason = "the Result and both parameters are load-bearing on Windows, where this assigns the child to the job object; other platforms have nothing to do here"
    )]
    pub fn adopt(&self, child: &Child) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;

            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;

            // SAFETY: both handles are live: the job is owned by `self`, and `child` is borrowed for
            // this call, so it cannot have been reaped.
            let ok = unsafe { AssignProcessToJobObject(self.job, child.as_raw_handle().cast()) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Nursery {
    fn drop(&mut self) {
        // Closing the last handle is what terminates any worker still assigned to the job.
        // SAFETY: `self.job` is live for the nursery's whole lifetime and closed exactly here.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.job) };
    }
}
