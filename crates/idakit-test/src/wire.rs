//! The daemon/proxy wire protocol over a Unix stream.
//!
//! A proxy sends one request line (`<case name>\n`) and reads back one reply frame: a little-endian
//! `u32` output length, that many bytes of the child's captured output, then a little-endian `u32`
//! exit code. Length-prefixing lets the proxy read the whole frame without guessing where output
//! ends.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// The daemon's reply for one case: its captured output and exit code.
pub struct Reply {
    /// The child's combined stdout and stderr.
    pub output: Vec<u8>,
    /// The child's exit code (0 = pass).
    pub code: u32,
}

/// Writes a reply frame: output length, the output bytes, then the exit code.
///
/// # Errors
/// Propagates any write error on `sock`, e.g. a proxy that disconnected before the reply.
pub fn write_reply(sock: &mut UnixStream, output: &[u8], code: u32) -> std::io::Result<()> {
    sock.write_all(&(output.len() as u32).to_le_bytes())?;
    sock.write_all(output)?;
    sock.write_all(&code.to_le_bytes())?;
    sock.flush()
}

/// Reads one reply frame written by [`write_reply`].
///
/// # Errors
/// Propagates any read error on `sock`, including an early EOF if the daemon died mid-reply.
pub fn read_reply(sock: &mut UnixStream) -> std::io::Result<Reply> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len)?;
    let mut output = vec![0u8; u32::from_le_bytes(len) as usize];
    sock.read_exact(&mut output)?;
    let mut code = [0u8; 4];
    sock.read_exact(&mut code)?;
    Ok(Reply {
        output,
        code: u32::from_le_bytes(code),
    })
}

/// Reads a request line (up to `\n`) from `sock`, returning the case name without the newline.
///
/// Stops at the first newline or at EOF, so a proxy that closed early yields whatever it sent.
pub fn read_request(sock: &mut UnixStream) -> String {
    let mut name = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match sock.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) => name.push(byte[0]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&name).into_owned()
}
