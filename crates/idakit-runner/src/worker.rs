//! The worker half: a test binary that keeps expensive state warm and runs cases leased to it.
//!
//! A binary enters this mode when the runner spawns it with the worker flag. It pays its one-time
//! setup (for kernel tests, bringing IDA up), then calls [`serve`], which loops until the runner
//! says to stop. Every case runs in the same process, so the setup is amortized across all of them,
//! yet each still reports its own name, status, duration, and output.

use std::io::{self, BufReader};
use std::panic::{self, AssertUnwindSafe};
use std::time::Instant;

use crate::protocol::{Event, Request, Status};

/// The result of running one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The case ran to completion, with an optional one-line summary.
    Passed(Option<String>),
    /// The case did not run, for the given reason (an unmet precondition).
    Skipped(String),
    /// The case ran and failed, for the given reason.
    Failed(String),
}

impl From<String> for Outcome {
    fn from(summary: String) -> Self {
        Self::Passed(Some(summary))
    }
}

impl From<()> for Outcome {
    fn from((): ()) -> Self {
        Self::Passed(None)
    }
}

/// Serves cases from the runner until it asks this worker to stop or closes the channel.
///
/// `handler` receives a case name and returns its [`Outcome`]. A panic inside `handler` is caught
/// and reported as [`Outcome::Failed`], so one bad case cannot take the worker down and cost every
/// case queued behind it.
///
/// # Errors
/// Propagates an I/O error on the control streams, which means the runner went away.
pub fn serve<F>(mut handler: F) -> io::Result<()>
where
    F: FnMut(&str) -> Outcome,
{
    let mut input = BufReader::new(io::stdin());
    while let Some(request) = Request::read_from(&mut input)? {
        match request {
            Request::Quit => break,
            Request::Run(name) => run_one(&mut handler, &name)?,
        }
    }
    Ok(())
}

/// Runs one case, bracketing it with the frames the runner uses to attribute output and timing.
fn run_one<F>(handler: &mut F, name: &str) -> io::Result<()>
where
    F: FnMut(&str) -> Outcome,
{
    let mut out = io::stdout();
    Event::Start(name.to_owned()).write_to(&mut out)?;

    let started = Instant::now();
    // `AssertUnwindSafe` because a caught panic ends this case and nothing observes the handler's
    // state afterwards except the next, independent case.
    let caught = panic::catch_unwind(AssertUnwindSafe(|| handler(name)));
    let millis = started.elapsed().as_millis() as u64;

    let (status, message) = match caught {
        Ok(Outcome::Passed(summary)) => (Status::Passed, summary.unwrap_or_default()),
        Ok(Outcome::Skipped(reason)) => (Status::Skipped, reason),
        Ok(Outcome::Failed(reason)) => (Status::Failed, reason),
        Err(payload) => (Status::Failed, panic_message(&*payload)),
    };

    Event::End {
        status,
        millis,
        message,
    }
    .write_to(&mut out)
}

/// Runs `body` and inverts the verdict, for a case whose panic is the thing being asserted.
///
/// `expected` is a substring the panic message must contain, or empty to accept any panic. This
/// mirrors libtest's `#[should_panic]`, and lives here rather than in a harness so the rule and
/// [`panic_message`] cannot disagree about what a payload says.
#[must_use]
pub fn expecting_panic(expected: &str, body: impl FnOnce() + panic::UnwindSafe) -> Outcome {
    match panic::catch_unwind(body) {
        Ok(()) => Outcome::Failed("expected a panic, but the case returned".to_owned()),
        Err(payload) => {
            let message = panic_message(&*payload);
            if expected.is_empty() || message.contains(expected) {
                Outcome::Passed(None)
            } else {
                Outcome::Failed(format!(
                    "panicked with {message:?}, which does not contain {expected:?}"
                ))
            }
        }
    }
}

/// The best available text for a caught panic payload.
///
/// Public because a harness that implements `should_panic` has to inspect the message itself, and
/// the two must agree on what a payload's text is.
#[must_use]
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panicked".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn summaries_convert_into_a_pass() {
        assert!(Outcome::from("ok".to_owned()) == Outcome::Passed(Some("ok".to_owned())));
        assert!(Outcome::from(()) == Outcome::Passed(None));
    }

    #[test]
    fn an_expected_panic_passes_when_the_message_matches() {
        assert!(expecting_panic("boom", || panic!("boom at 0x40")) == Outcome::Passed(None));
        // An empty expectation accepts any panic, which is bare `should_panic`.
        assert!(expecting_panic("", || panic!("anything")) == Outcome::Passed(None));
    }

    #[test]
    fn an_expected_panic_fails_on_the_wrong_message_or_none_at_all() {
        // The point of matching: a case that panics for an unrelated reason has not proven the
        // thing it claims to.
        let wrong = expecting_panic("bad address", || panic!("out of memory"));
        assert!(matches!(wrong, Outcome::Failed(ref why) if why.contains("out of memory")));

        let quiet = expecting_panic("bad address", || {});
        assert!(matches!(quiet, Outcome::Failed(ref why) if why.contains("expected a panic")));
    }

    #[test]
    fn panic_payloads_yield_their_text() {
        let caught = panic::catch_unwind(|| panic!("boom")).expect_err("it panicked");
        assert!(panic_message(&*caught) == "boom");

        let caught =
            panic::catch_unwind(|| panic!("{}", String::from("owned"))).expect_err("it panicked");
        assert!(panic_message(&*caught) == "owned");
    }
}
