//! The persistent daemon: bring the kernel up once, then fork a copy-on-write child per request.
//!
//! [`run`] opens the database on its own main thread (the `g_main` owner), publishes it for
//! children to inherit, then loops: accept proxy connections, admit any queued case that fits the
//! token pool, fork a warm child for it, and stream each finished child's output and exit code back
//! to its proxy. Admission is skip-over, so a case heavier than the free tokens waits without
//! blocking lighter cases queued behind it; a weight at or above the pool size runs exclusively.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Instant;
use std::{env, fs, panic};

use idakit::prelude::Ida;

use crate::{KernelTest, all, db, wire};

/// A queued request: the proxy connection to answer, the case name, and its admission weight.
struct Request {
    conn: UnixStream,
    name: String,
    weight: u32,
}

/// A forked child still running: its proxy connection, pid, output pipe, and accounting.
struct InFlight {
    conn: UnixStream,
    pid: c_int,
    pipe_read: c_int,
    name: String,
    weight: u32,
    out: Vec<u8>,
    start: Instant,
}

/// Live daemon state: the registry, the token pool, and the queued and running cases.
struct Daemon {
    cases: Vec<&'static KernelTest>,
    total: u32,
    avail: u32,
    pending: VecDeque<Request>,
    inflight: Vec<InFlight>,
    epoch: Instant,
}

/// Brings the kernel up, opens the database once, and serves fork-per-request cases forever.
///
/// # Panics
/// If the kernel cannot be brought up, the database cannot be opened, or the socket cannot be
/// bound; the daemon has nothing to serve in any of those cases.
pub fn run(db_arg: Option<String>, sock_path: &str) -> ! {
    let (_working, path) = db::resolve(db_arg);
    let warmup = Instant::now();
    let mut database = Ida::here().expect("kernel bring-up (Ida::here)");
    database.open(&path).call().expect("open database");
    db::publish(&mut database);

    let total = token_budget();
    let _ = fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path).expect("bind unix socket");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    eprintln!(
        "[daemon] warm in {:.3}s: init+open once, {total} tokens, listening on {sock_path}",
        warmup.elapsed().as_secs_f64()
    );

    let mut daemon = Daemon {
        cases: all(),
        total,
        avail: total,
        pending: VecDeque::new(),
        inflight: Vec::new(),
        epoch: Instant::now(),
    };
    loop {
        daemon.admit();
        daemon.poll_once(&listener);
    }
}

impl Daemon {
    /// Forks a warm child for every queued case that fits the free tokens, skipping over any that
    /// does not so a heavy case never blocks lighter ones behind it.
    fn admit(&mut self) {
        while let Some(i) = self
            .pending
            .iter()
            .position(|r| r.weight.min(self.total) <= self.avail)
        {
            let Request {
                mut conn,
                name,
                weight,
            } = self.pending.remove(i).expect("index in range");
            let eff = weight.min(self.total);
            if let Some(case) = self.cases.iter().find(|c| c.name == name).copied() {
                self.avail -= eff;
                eprintln!(
                    "[daemon] +{:.3}s admit {name} (weight {eff})",
                    self.epoch.elapsed().as_secs_f64()
                );
                self.inflight.push(spawn(case, conn, name, eff, self.epoch));
            } else {
                let msg = format!("no such test {name:?}\n");
                let _ = wire::write_reply(&mut conn, msg.as_bytes(), 101);
            }
        }
    }

    /// Blocks until the listener or a running child is ready, then accepts new requests and reaps
    /// any finished children.
    fn poll_once(&mut self, listener: &UnixListener) {
        let mut fds = vec![pollfd(listener.as_raw_fd())];
        fds.extend(self.inflight.iter().map(|f| pollfd(f.pipe_read)));

        // SAFETY: poll over pollfds for descriptors the daemon owns; -1 blocks until one is ready.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if ready < 0 {
            return;
        }
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            self.accept(listener);
        }
        self.reap_ready(&fds[1..]);
    }

    /// Drains every ready listener connection into the pending queue, tagging each with its
    /// registered weight.
    fn accept(&mut self, listener: &UnixListener) {
        loop {
            match listener.accept() {
                Ok((mut conn, _)) => {
                    let name = wire::read_request(&mut conn);
                    let weight = self
                        .cases
                        .iter()
                        .find(|c| c.name == name)
                        .map_or(1, |c| c.weight);
                    self.pending.push_back(Request { conn, name, weight });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    /// Drains output from each ready child; when one reaches EOF, reaps it, releases its tokens, and
    /// replies to its proxy. `child_fds` is [`poll_once`]'s pollfd slice for [`Self::inflight`], in
    /// order.
    fn reap_ready(&mut self, child_fds: &[libc::pollfd]) {
        let mut i = 0;
        while i < self.inflight.len() {
            if child_fds[i].revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                i += 1;
                continue;
            }
            if !drain_into(self.inflight[i].pipe_read, &mut self.inflight[i].out) {
                i += 1;
                continue;
            }
            let mut done = self.inflight.swap_remove(i);
            self.avail += done.weight;
            let code = reap(done.pid);
            eprintln!(
                "[daemon] +{:.3}s reap {} ({}), avail {}/{}",
                done.start.elapsed().as_secs_f64(),
                done.name,
                if code == 0 { "pass" } else { "FAIL" },
                self.avail,
                self.total
            );
            // SAFETY: close the read end this daemon owns.
            unsafe { libc::close(done.pipe_read) };
            let _ = wire::write_reply(&mut done.conn, &done.out, code as u32);
            // `swap_remove` moved a new element into `i`, so revisit it without advancing.
        }
    }
}

/// Reads whatever `total` tokens the pool should hold: an explicit `IDAKIT_TEST_TOKENS`, else the
/// core count capped at 8.
fn token_budget() -> u32 {
    env::var("IDAKIT_TEST_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(4, |n| n.get() as u32)
                .min(8)
        })
}

/// Forks a warm child that runs `case` and `_exit`s with its pass/fail, returning the parent's
/// handle on the running child.
fn spawn(
    case: &'static KernelTest,
    conn: UnixStream,
    name: String,
    weight: u32,
    epoch: Instant,
) -> InFlight {
    let mut fds: [c_int; 2] = [0; 2];
    // SAFETY: standard pipe(2) into a two-element array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let [read_fd, write_fd] = fds;

    // SAFETY: fork from the daemon's single main thread, so the child copies the sole kernel owner.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: route the child's stdout/stderr into the pipe, then drop the raw fds.
        unsafe {
            libc::close(read_fd);
            libc::dup2(write_fd, 1);
            libc::dup2(write_fd, 2);
            libc::close(write_fd);
        }
        let passed = run_body(case);
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let _ = std::io::Write::flush(&mut std::io::stderr());
        // SAFETY: terminate the child, skipping idalib teardown and atexit handlers.
        unsafe { libc::_exit(i32::from(!passed)) };
    }
    // SAFETY: the parent closes the write end so the pipe reports EOF when the child exits.
    unsafe { libc::close(write_fd) };
    InFlight {
        conn,
        pid,
        pipe_read: read_fd,
        name,
        weight,
        out: Vec::new(),
        start: epoch,
    }
}

/// Runs the case body under `catch_unwind` (a panic is a failure), then flushes this child's
/// coverage before it `_exit`s.
fn run_body(case: &KernelTest) -> bool {
    let passed = panic::catch_unwind(case.run).is_ok();
    flush_coverage();
    passed
}

/// Writes this forked child's coverage profile before `_exit`, which would otherwise skip the
/// atexit writer, so `cargo llvm-cov` still sees the test-body lines run only in children.
///
/// The LLVM profiler runtime is statically linked, so its symbols are absent from the dynamic table
/// and `dlsym` cannot reach them; the writer is called directly instead. The extern and the call
/// compile only under coverage instrumentation, so a normal build never references the symbol.
#[cfg(coverage_nightly)]
fn flush_coverage() {
    unsafe extern "C" {
        fn __llvm_profile_write_file() -> c_int;
    }
    // SAFETY: a coverage build links the profiler runtime; this writes the child's counters to the
    // inherited LLVM_PROFILE_FILE pool, whose locked online merge is safe across concurrent children.
    let _ = unsafe { __llvm_profile_write_file() };
}

#[cfg(not(coverage_nightly))]
fn flush_coverage() {}

/// A pollfd waiting for input or hangup on `fd`.
fn pollfd(fd: c_int) -> libc::pollfd {
    libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }
}

/// Reads whatever is available from `fd` into `out`, returning `true` once the child's write end
/// closed (EOF).
fn drain_into(fd: c_int, out: &mut Vec<u8>) -> bool {
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: read into a local buffer from a descriptor the daemon owns.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        match n.cmp(&0) {
            Ordering::Greater => out.extend_from_slice(&buf[..n as usize]),
            Ordering::Equal => return true, // EOF: child's write end closed
            Ordering::Less => return false, // would block: nothing more for now
        }
    }
}

/// Reaps `pid` and returns its exit code, or 101 if it did not exit normally.
fn reap(pid: c_int) -> c_int {
    let mut status: c_int = 0;
    // SAFETY: reap the specific child by pid into a local status word.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        101
    }
}
