//! Proxy mode: nextest's per-test invocation, forwarding one case to the warm daemon.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::exit;
use std::{env, io};

use crate::wire;

/// Environment variable naming the daemon's Unix socket; set by the test recipe when a daemon is up.
const SOCK_ENV: &str = "IDAKIT_TEST_SOCK";

/// Runs one case by proxy: connect to the daemon, request `name`, and mirror the child's output and
/// exit code. Never returns.
///
/// When [`SOCK_ENV`] is unset or empty no daemon is running (a plain run with no corpus, say), so
/// the case skips: it prints why and exits 0, matching the corpus rule that an absent fixture
/// passes rather than fails.
///
/// # Panics
/// If the daemon is named but unreachable, or its reply cannot be read; a live daemon that drops
/// the request is a real harness failure, not a skip.
pub fn run(name: &str) -> ! {
    let Some(sock_path) = env::var(SOCK_ENV).ok().filter(|s| !s.is_empty()) else {
        println!("skipping {name}: no warm-kernel daemon ({SOCK_ENV} unset)");
        exit(0);
    };

    let mut sock =
        UnixStream::connect(&sock_path).unwrap_or_else(|e| panic!("connect {sock_path}: {e}"));
    sock.write_all(name.as_bytes()).expect("send request name");
    sock.write_all(b"\n").expect("send request newline");
    sock.flush().expect("flush request");

    let reply = wire::read_reply(&mut sock).expect("read daemon reply");
    io::stdout()
        .write_all(&reply.output)
        .expect("mirror child output");
    io::stdout().flush().expect("flush child output");
    exit(reply.code as i32);
}
