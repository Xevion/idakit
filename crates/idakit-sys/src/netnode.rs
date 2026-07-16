//! `MAXSPECSIZE`, the object-size cap shared by netnode value/sup/hash storage (`netnode.hpp`).

/// The maximum byte length of one netnode value, sup, or hash object.
///
/// `MAXSPECSIZE` from `netnode.hpp` (IDA 9.3). The facade enforces the SDK constant itself; this
/// mirrors its value on the Rust side, redundant by design rather than shared codegen.
pub const MAXSPECSIZE: usize = 1024;

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::MAXSPECSIZE;

    /// Pulls `const int <name> = <value>;` out of SDK header text.
    fn header_const(text: &str, name: &str) -> Option<usize> {
        let needle = format!("{name} = ");
        let start = text.find(&needle)? + needle.len();
        let end = start + text[start..].find(';')?;
        text[start..end].trim().parse().ok()
    }

    // Pins the mirror to the SDK header's own value, so a version bump that changes the cap
    // fails here instead of silently overreading a stack buffer. Kernel-free; skips when
    // IDA_SDK_INCLUDE (this crate's own build script output) is unset.
    #[test]
    fn maxspecsize_matches_the_sdk_header() {
        let Some(dir) = option_env!("IDA_SDK_INCLUDE") else {
            eprintln!(
                "skipping: IDA_SDK_INCLUDE unset (no SDK headers to check MAXSPECSIZE against)"
            );
            return;
        };
        let header = std::path::Path::new(dir).join("netnode.hpp");
        let text = std::fs::read_to_string(&header)
            .unwrap_or_else(|e| panic!("read {}: {e}", header.display()));
        let value = header_const(&text, "MAXSPECSIZE")
            .unwrap_or_else(|| panic!("MAXSPECSIZE declaration not found in {}", header.display()));
        assert!(value == MAXSPECSIZE);
    }
}
