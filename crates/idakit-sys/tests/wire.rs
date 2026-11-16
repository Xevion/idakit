//! Checks that every address-domain value leaving the facade widens through `ea_wire`.
//!
//! A plain widening cast zero-extends a 32-bit `ea_t`'s all-ones `BADADDR` into a value Rust
//! accepts as a real address (`facade/wire.h` has the detail). Nothing in the C++ types forces the
//! right spelling, so this scans the hand-written facade instead:
//!
//! - no bare `static_cast` to a 64-bit unsigned type outside `wire.h`, so every explicit widening
//!   names itself as `ea_wire` (address) or `widen` (anything else);
//! - every `return` in a `Custom` body whose codegen spec returns `Scalar::Address` goes through
//!   `ea_wire`, which also catches the implicit `return some_ea;` the first rule cannot see;
//! - every assignment to a shared-struct field the spec types as `Scalar::Address` does too.
//!
//! Kernel-free: it reads source text and the codegen spec, never the SDK or a runtime.

use std::fs;
use std::path::Path;

use assert2::assert;

/// The one header allowed to spell the raw cast, since it defines the helpers.
const WIRE_HEADER: &str = "wire.h";

/// Widening casts that bypass `ea_wire`/`widen`. `uint64` is the SDK's own typedef.
const BARE_CASTS: &[&str] = &[
    "static_cast<uint64_t>",
    "static_cast<std::uint64_t>",
    "static_cast<uint64>",
];

struct Source {
    name: String,
    /// The file with comments blanked out, line structure kept so offsets map to lines.
    code: String,
}

impl Source {
    fn line_of(&self, offset: usize) -> usize {
        self.code[..offset].matches('\n').count() + 1
    }
}

fn facade_sources() -> Vec<Source> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("facade");
    let mut out: Vec<Source> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("facade dir entry").path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("cpp" | "h")))
        .map(|p| {
            let text =
                fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()));
            Source {
                name: p.file_name().unwrap().to_string_lossy().into_owned(),
                code: strip_comments(&text),
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Blank out `//` and `/* */` comments (newlines kept), leaving string literals intact.
fn strip_comments(src: &str) -> String {
    let bytes = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1)) {
            (b'"' | b'\'', _) => {
                let quote = bytes[i];
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != quote {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(bytes.len());
                out.push_str(&src[start..i]);
            }
            (b'/', Some(b'/')) => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                let end = src[i + 2..].find("*/").map_or(src.len(), |e| i + 2 + e + 2);
                out.extend(src[i..end].chars().filter(|&c| c == '\n'));
                i = end;
            }
            _ => {
                let ch = src[i..].chars().next().unwrap();
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The text between the `{` opening at `open` and its matching `}`.
fn braced_body(code: &str, open: usize) -> &str {
    let mut depth = 0usize;
    for (i, b) in code.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &code[open + 1..i];
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces from offset {open}");
}

/// Each `return ...;` expression in `body`, `return` keyword excluded.
fn returns(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    body.match_indices("return")
        .filter(|&(i, _)| {
            let before = i.checked_sub(1).map(|j| bytes[j]);
            let after = bytes.get(i + "return".len()).copied();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .map(|(i, _)| {
            let rest = &body[i + "return".len()..];
            rest[..rest.find(';').unwrap_or(rest.len())].trim()
        })
        .collect()
}

#[test]
fn no_bare_widening_cast() {
    let mut hits = Vec::new();
    for src in facade_sources().iter().filter(|s| s.name != WIRE_HEADER) {
        for cast in BARE_CASTS {
            for (offset, _) in src.code.match_indices(cast) {
                hits.push(format!("{}:{}: {cast}", src.name, src.line_of(offset)));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "widen through ea_wire (an address, node id, or selector) or widen (anything else):\n{}",
        hits.join("\n")
    );
}

#[test]
fn custom_address_returns_widen() {
    let crossings = idakit_sys_codegen::address_crossings();
    assert!(
        crossings.custom_returns.len() > 10,
        "the spec query found almost no address returns, so this check would pass vacuously"
    );
    let sources = facade_sources();
    let mut problems = Vec::new();
    for name in &crossings.custom_returns {
        let signature = format!("\nuint64_t {name}(");
        let defs: Vec<_> = sources
            .iter()
            .flat_map(|s| {
                s.code
                    .match_indices(&signature)
                    .map(move |(i, _)| (s, i + 1))
            })
            .collect();
        let [(src, def)] = defs[..] else {
            problems.push(format!(
                "{name}: expected one hand-written definition, found {}",
                defs.len()
            ));
            continue;
        };
        let open = def + src.code[def..].find('{').expect("definition has a body");
        for expr in returns(braced_body(&src.code, open)) {
            if !expr.starts_with("ea_wire(") {
                problems.push(format!(
                    "{}:{}: {name} returns `{expr}` without ea_wire",
                    src.name,
                    src.line_of(def)
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn address_fields_widen() {
    let crossings = idakit_sys_codegen::address_crossings();
    assert!(
        crossings.fields.contains(&"target"),
        "the spec query lost a known address field, so this check would pass vacuously"
    );
    let mut problems = Vec::new();
    for src in &facade_sources() {
        let bytes = src.code.as_bytes();
        for field in &crossings.fields {
            for (i, _) in src.code.match_indices(field) {
                let member =
                    (i >= 1 && bytes[i - 1] == b'.') || (i >= 2 && &bytes[i - 2..i] == b"->");
                let end = i + field.len();
                if !member || bytes.get(end).copied().is_some_and(is_ident) {
                    continue;
                }
                let rest = src.code[end..].trim_start();
                if !rest.starts_with('=') || rest.starts_with("==") {
                    continue;
                }
                let rhs = rest[1..rest.find(';').unwrap_or(rest.len())].trim();
                if !rhs.starts_with("ea_wire(") {
                    problems.push(format!(
                        "{}:{}: .{field} = `{rhs}` without ea_wire",
                        src.name,
                        src.line_of(i)
                    ));
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn strip_comments_keeps_code_and_line_count() {
    let src = "a // static_cast<uint64_t>(x)\n/* static_cast<uint64_t>\n */ b \"// kept\"\n";
    let out = strip_comments(src);
    assert!(!out.contains("static_cast"));
    assert!(out.contains("\"// kept\""));
    assert!(out.matches('\n').count() == src.matches('\n').count());
}

#[test]
fn returns_finds_every_return_expression() {
    let body = " if (x) return ea_wire(a); int returned = 0; return b ; ";
    assert!(returns(body) == ["ea_wire(a)", "b"]);
}
