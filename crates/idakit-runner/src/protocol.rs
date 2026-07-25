//! The line-framed protocol the runner and its workers speak over standard streams.
//!
//! Only the standard streams carry it, so no extra inherited handles are needed and the same code
//! works on Windows, where passing a fourth handle would need `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
//! The runner writes [`Request`]s to a worker's stdin; the worker answers with [`Event`]s on
//! stdout.
//!
//! A worker's stdout and stderr are merged into one pipe, and the case's own output shares it with
//! the control frames. That is deliberate on both counts. The kernel prints banners of its own that
//! no wrapper can suppress, so a channel assumed to be clean would eventually be corrupted by
//! them; instead every control line starts with [`CONTROL_PREFIX`], and the runner treats anything
//! else as output from the case currently running. Sharing one pipe also means output and control
//! cannot be reordered relative to each other, so a case's output needs no separate synchronization
//! to be attributed correctly.
//!
//! Every frame is one text line. An [`Event::End`] line is followed by exactly the number of
//! message bytes it declares, so a failure message may contain newlines without escaping.

use std::io::{BufRead, Write};

/// Marks a line as a control frame rather than output from the case.
///
/// An ASCII record separator, which ordinary program output does not emit, so a case would have to
/// go out of its way to forge a frame.
pub const CONTROL_PREFIX: &str = "\x1e";

/// What the runner asks a worker to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Run the named case, reporting one [`Event::Start`] and then one [`Event::End`].
    Run(String),
    /// Shut down cleanly; no further requests follow.
    Quit,
}

impl Request {
    /// Writes this request as one line and flushes it.
    ///
    /// # Errors
    /// Propagates any write error on `out`, including a worker that already exited.
    pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        match self {
            Self::Run(name) => writeln!(out, "RUN {name}")?,
            Self::Quit => writeln!(out, "QUIT")?,
        }
        out.flush()
    }

    /// Reads the next request, or `None` at end of input, which a worker treats as [`Self::Quit`].
    ///
    /// # Errors
    /// Propagates any read error on `input`.
    pub fn read_from(input: &mut impl BufRead) -> std::io::Result<Option<Self>> {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        let line = line.trim_end_matches(['\r', '\n']);
        // The name is the whole remainder, so a case name may contain spaces.
        Ok(match line.split_once(' ') {
            Some(("RUN", name)) => Some(Self::Run(name.to_owned())),
            _ if line == "QUIT" => Some(Self::Quit),
            _ => None,
        })
    }
}

/// How a case finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The case ran to completion successfully.
    Passed,
    /// The case ran and failed; the message carries the reason.
    Failed,
    /// The case did not run because a precondition was unmet; the message carries the reason.
    Skipped,
}

impl Status {
    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "ok",
            Self::Failed => "fail",
            Self::Skipped => "skip",
        }
    }

    /// Parses a wire spelling produced by [`Self::as_str`].
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ok" => Some(Self::Passed),
            "fail" => Some(Self::Failed),
            "skip" => Some(Self::Skipped),
            _ => None,
        }
    }
}

/// One line read from a worker's merged output stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A control frame from the harness.
    Control(Event),
    /// A line the running case (or the kernel underneath it) printed.
    Output(String),
}

/// What a worker reports back about the case it is running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The named case is about to run.
    ///
    /// Sent before any of the case's own work, so a worker that dies mid-case leaves exactly one
    /// unterminated `Start` naming the case that killed it.
    Start(String),
    /// The case finished.
    End {
        /// How it finished.
        status: Status,
        /// Wall time of the case body, in milliseconds.
        millis: u64,
        /// Failure reason, skip reason, or a one-line summary; empty when there is nothing to say.
        message: String,
    },
}

impl Event {
    /// Writes this event as a control frame and flushes it.
    ///
    /// # Errors
    /// Propagates any write error on `out`, including a runner that stopped listening.
    pub fn write_to(&self, out: &mut impl Write) -> std::io::Result<()> {
        match self {
            Self::Start(name) => writeln!(out, "{CONTROL_PREFIX}START {name}")?,
            Self::End {
                status,
                millis,
                message,
            } => {
                writeln!(
                    out,
                    "{CONTROL_PREFIX}END {} {millis} {}",
                    status.as_str(),
                    message.len()
                )?;
                out.write_all(message.as_bytes())?;
            }
        }
        out.flush()
    }
}

/// Reads the next line from a worker, classifying it as a control frame or case output.
///
/// Returns `None` at end of input, which means the worker exited.
///
/// # Errors
/// Propagates any read error on `input`, or reports [`std::io::ErrorKind::InvalidData`] for a
/// control line that does not parse.
pub fn read_line(input: &mut impl BufRead) -> std::io::Result<Option<Line>> {
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let trimmed = line.trim_end_matches(['\r', '\n']);

    let Some(frame) = trimmed.strip_prefix(CONTROL_PREFIX) else {
        return Ok(Some(Line::Output(trimmed.to_owned())));
    };

    if let Some(name) = frame.strip_prefix("START ") {
        return Ok(Some(Line::Control(Event::Start(name.to_owned()))));
    }
    let Some(rest) = frame.strip_prefix("END ") else {
        return Err(malformed(frame));
    };
    let mut parts = rest.splitn(3, ' ');
    let status = parts
        .next()
        .and_then(Status::parse)
        .ok_or_else(|| malformed(frame))?;
    let millis = parts
        .next()
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| malformed(frame))?;
    let len: usize = parts
        .next()
        .and_then(|t| t.parse().ok())
        .ok_or_else(|| malformed(frame))?;

    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf)?;
    Ok(Some(Line::Control(Event::End {
        status,
        millis,
        message: String::from_utf8_lossy(&buf).into_owned(),
    })))
}

fn malformed(frame: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("malformed worker frame: {frame:?}"),
    )
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    fn roundtrip(event: &Event) -> Line {
        let mut buf = Vec::new();
        event.write_to(&mut buf).expect("write");
        let mut cursor = std::io::Cursor::new(buf);
        read_line(&mut cursor).expect("read").expect("a line")
    }

    #[test]
    fn start_roundtrips() {
        let event = Event::Start("fixture::check".to_owned());
        assert!(roundtrip(&event) == Line::Control(event));
    }

    #[test]
    fn end_roundtrips_with_multiline_message() {
        // Length-prefixing exists so a failure message can carry newlines unescaped.
        let event = Event::End {
            status: Status::Failed,
            millis: 42,
            message: "line one\nline two\n".to_owned(),
        };
        assert!(roundtrip(&event) == Line::Control(event));
    }

    #[test]
    fn end_roundtrips_when_empty() {
        let event = Event::End {
            status: Status::Passed,
            millis: 0,
            message: String::new(),
        };
        assert!(roundtrip(&event) == Line::Control(event));
    }

    #[test]
    fn plain_lines_are_case_output() {
        let mut cursor = std::io::Cursor::new(b"Thank you for using IDA.\n".to_vec());
        let line = read_line(&mut cursor).expect("read").expect("a line");
        assert!(line == Line::Output("Thank you for using IDA.".to_owned()));
    }

    #[test]
    fn output_interleaves_with_control_in_order() {
        // One stream carries both, so a case's output cannot be reordered across its own frames.
        let mut buf = Vec::new();
        Event::Start("c".to_owned()).write_to(&mut buf).expect("w");
        buf.extend_from_slice(b"printed by the case\n");
        Event::End {
            status: Status::Passed,
            millis: 1,
            message: String::new(),
        }
        .write_to(&mut buf)
        .expect("w");

        let mut cursor = std::io::Cursor::new(buf);
        let mut lines = Vec::new();
        while let Some(line) = read_line(&mut cursor).expect("read") {
            lines.push(line);
        }
        assert!(lines.len() == 3);
        assert!(lines[0] == Line::Control(Event::Start("c".to_owned())));
        assert!(lines[1] == Line::Output("printed by the case".to_owned()));
        assert!(matches!(lines[2], Line::Control(Event::End { .. })));
    }

    #[test]
    fn requests_roundtrip() {
        for request in [Request::Run("a b::c".to_owned()), Request::Quit] {
            let mut buf = Vec::new();
            request.write_to(&mut buf).expect("write");
            let mut cursor = std::io::Cursor::new(buf);
            let read = Request::read_from(&mut cursor)
                .expect("read")
                .expect("a request");
            assert!(read == request);
        }
    }

    #[test]
    fn empty_input_ends_the_stream() {
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(Request::read_from(&mut cursor).expect("read").is_none());
        let mut cursor = std::io::Cursor::new(Vec::new());
        assert!(read_line(&mut cursor).expect("read").is_none());
    }

    #[test]
    fn statuses_roundtrip() {
        for status in [Status::Passed, Status::Failed, Status::Skipped] {
            assert!(Status::parse(status.as_str()) == Some(status));
        }
    }
}
