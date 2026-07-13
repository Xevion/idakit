//! The netnode domain, matrix-generated rather than hand-typed on both sides of the bridge.
//!
//! A netnode is a value type over a single `nodeidx_t`; its persistent arrays form a combinatorial
//! matrix of {alt, sup, hash, char, blob} families crossed with {default, `_ea`, `_idx8`} keyings
//! and {get, set, del, iterate, shift} operations. Each cell is one mechanical `netnode n(node);
//! return n.<member>(...);` body, so [`domain`] emits both the [`FnSpec`] (feeding the shared bridge
//! engine in [`super`]) and its rendered C++ body from one small emitter. The irregular lifecycle
//! and node-value functions stay hand-written [`FnSpec`]s with `Custom` bodies in
//! `facade/netnode_custom.cc`; only the five array families are generated.

use std::sync::OnceLock;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::super::model::{Arg, ArgTy, BodyKind, Domain, FnSpec, RetKind};

/// C++ helpers the generated bodies and the hand-written `custom_tu` both call, emitted `inline`
/// into the domain header so both translation units share one definition.
const BODY_HELPERS: &str = "\
// Copy a filled qstring / byte buffer out as the owning Rust type in one crossing.
inline rust::String to_rust_string(const qstring &s) { return rust::String(s.c_str(), s.length()); }

inline rust::Vec<uint8_t> to_rust_bytes(const uint8_t *data, size_t n) {
  rust::Vec<uint8_t> out;
  out.reserve(n);
  for (size_t i = 0; i < n; i++)
    out.push_back(data[i]);
  return out;
}
";

/// A rendered netnode body: reconstruct `n` from the `node` id, then run `stmts` (each line already
/// indented and newline-terminated). Every generated body opens the same way.
fn nn_body(stmts: &str) -> String {
    format!("  netnode n((nodeidx_t)node);\n{stmts}")
}

/// A one-line netnode body returning `expr`, the common shape for the scalar array accessors.
fn nn_return(expr: &str) -> String {
    nn_body(&format!("  return {expr};\n"))
}

/// A string-keyed netnode body: copy `key` into a `std::string k`, reconstruct `n`, then run
/// `stmts`. The hash family keys by string, so every keyed hash body opens this way.
fn nn_key_body(stmts: &str) -> String {
    format!("  std::string k(key);\n{}", nn_body(stmts))
}

/// A one-line string-keyed netnode body returning `expr`.
fn nn_key_return(expr: &str) -> String {
    nn_key_body(&format!("  return {expr};\n"))
}

/// One keying axis over the array families: how its index argument is named, typed, cast, and
/// described in docs. The SDK member name gains `suffix` (`""`, `"_ea"`, `"_idx8"`).
#[derive(Clone, Copy)]
struct Key {
    suffix: &'static str,
    idx_name: &'static str,
    idx_ty: ArgTy,
    idx_cast: &'static str,
    at: &'static str,
    bit8: &'static str,
}

const DEF: Key = Key {
    suffix: "",
    idx_name: "idx",
    idx_ty: ArgTy::U64,
    idx_cast: "(nodeidx_t)",
    at: "at `idx`",
    bit8: "",
};
const EA: Key = Key {
    suffix: "_ea",
    idx_name: "ea",
    idx_ty: ArgTy::U64,
    idx_cast: "(ea_t)",
    at: "keyed by address `ea`",
    bit8: "",
};
const IDX8: Key = Key {
    suffix: "_idx8",
    idx_name: "idx",
    idx_ty: ArgTy::U32,
    idx_cast: "(uchar)",
    at: "at 8-bit index `idx`",
    bit8: "8-bit ",
};

/// The four iteration ops (first/next/last/prev) shared by the alt and sup families, over one
/// keying. All return a `u64` index (`BADNODE` sentinel folded in by the caller).
fn iteration(v: &mut Vec<FnSpec>, fam: &str, k: Key) {
    let suf = k.suffix;
    let bit8 = k.bit8;
    let cast = k.idx_cast;
    v.push(FnSpec::rendered(
        format!("netnode_{fam}first{suf}"),
        vec![Arg::new("node", ArgTy::U64), Arg::new("tag", ArgTy::U32)],
        RetKind::U64,
        format!(
            "Lowest populated {bit8}{fam} index under `tag`, or `BADNODE` when the array is empty."
        ),
        nn_return(&format!("(uint64_t)n.{fam}first{suf}((uchar)tag)")),
    ));
    v.push(FnSpec::rendered(
        format!("netnode_{fam}next{suf}"),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("cur", k.idx_ty),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::U64,
        format!(
            "Next populated {bit8}{fam} index after `cur` under `tag`, or `BADNODE` when none."
        ),
        nn_return(&format!(
            "(uint64_t)n.{fam}next{suf}({cast}cur, (uchar)tag)"
        )),
    ));
    v.push(FnSpec::rendered(
        format!("netnode_{fam}last{suf}"),
        vec![Arg::new("node", ArgTy::U64), Arg::new("tag", ArgTy::U32)],
        RetKind::U64,
        format!(
            "Highest populated {bit8}{fam} index under `tag`, or `BADNODE` when the array is empty."
        ),
        nn_return(&format!("(uint64_t)n.{fam}last{suf}((uchar)tag)")),
    ));
    v.push(FnSpec::rendered(
        format!("netnode_{fam}prev{suf}"),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("cur", k.idx_ty),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::U64,
        format!(
            "Previous populated {bit8}{fam} index before `cur` under `tag`, or `BADNODE` when none."
        ),
        nn_return(&format!(
            "(uint64_t)n.{fam}prev{suf}({cast}cur, (uchar)tag)"
        )),
    ));
}

/// `<fam>shift(from, to, size, tag)`: move a run of elements; returns the count moved.
fn shift(fam: &str) -> FnSpec {
    FnSpec::rendered(
        format!("netnode_{fam}shift"),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("from", ArgTy::U64),
            Arg::new("to", ArgTy::U64),
            Arg::new("size", ArgTy::U64),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::Usize,
        format!("Shift the {fam} array under `tag`; the number of elements moved."),
        nn_return(&format!(
            "n.{fam}shift((nodeidx_t)from, (nodeidx_t)to, (nodeidx_t)size, (uchar)tag)"
        )),
    )
}

/// `<fam>del_all(tag)`: drop the entire array under one tag.
fn del_all(fam: &str) -> FnSpec {
    FnSpec::rendered(
        format!("netnode_{fam}del_all"),
        vec![Arg::new("node", ArgTy::U64), Arg::new("tag", ArgTy::U32)],
        RetKind::Bool,
        format!("Delete the entire {fam} array under `tag`."),
        nn_return(&format!("n.{fam}del_all((uchar)tag)")),
    )
}

/// Alt values: a sparse `u64` array (tag `atag`); unset reads as `0`.
fn alt(v: &mut Vec<FnSpec>) {
    for k in [DEF, EA, IDX8] {
        let (suf, cast, idx, at) = (k.suffix, k.idx_cast, k.idx_name, k.at);
        v.push(FnSpec::rendered(
            format!("netnode_altval{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::U64,
            format!("Alt value {at} under `tag`, or `0` when unset."),
            nn_return(&format!("(uint64_t)n.altval{suf}({cast}{idx}, (uchar)tag)")),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_altset{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("value", ArgTy::U64),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Set the alt value {at} under `tag` to `value`."),
            nn_return(&format!(
                "n.altset{suf}({cast}{idx}, (nodeidx_t)value, (uchar)tag)"
            )),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_altdel{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Delete the alt value {at} under `tag`."),
            nn_return(&format!("n.altdel{suf}({cast}{idx}, (uchar)tag)")),
        ));
    }
    iteration(v, "alt", DEF);
    iteration(v, "alt", IDX8);
    v.push(shift("alt"));
    v.push(del_all("alt"));
}

/// Sup values: arbitrary byte objects (tag `stag`), readable as bytes or as a string.
fn sup(v: &mut Vec<FnSpec>) {
    for k in [DEF, EA, IDX8] {
        let (suf, cast, idx, at) = (k.suffix, k.idx_cast, k.idx_name, k.at);
        v.push(FnSpec::rendered(
            format!("netnode_supval{suf}"),
            vec![Arg::new("node", ArgTy::U64), Arg::new(idx, k.idx_ty), Arg::new("tag", ArgTy::U32)],
            RetKind::ResultVecU8,
            format!("Sup value {at} under `tag` as raw bytes; `Err` when unset."),
            nn_body(&format!("  uint8_t buf[MAXSPECSIZE];\n  ssize_t r = n.supval{suf}({cast}{idx}, buf, sizeof(buf), (uchar)tag);\n  if (r < 0)\n    throw std::runtime_error(\"sup value is unset\");\n  return to_rust_bytes(buf, (size_t)r);\n")),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_supstr{suf}"),
            vec![Arg::new("node", ArgTy::U64), Arg::new(idx, k.idx_ty), Arg::new("tag", ArgTy::U32)],
            RetKind::ResultString,
            format!("Sup value {at} under `tag` as a string; `Err` when unset."),
            nn_body(&format!("  qstring out;\n  if (n.supstr{suf}(&out, {cast}{idx}, (uchar)tag) < 0)\n    throw std::runtime_error(\"sup value is unset\");\n  return to_rust_string(out);\n")),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_supset{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("value", ArgTy::Bytes),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Set the sup value {at} under `tag` (max `MAXSPECSIZE` bytes)."),
            nn_return(&format!(
                "n.supset{suf}({cast}{idx}, value.data(), value.size(), (uchar)tag)"
            )),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_supdel{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Delete the sup value {at} under `tag`."),
            nn_return(&format!("n.supdel{suf}({cast}{idx}, (uchar)tag)")),
        ));
    }
    iteration(v, "sup", DEF);
    iteration(v, "sup", IDX8);
    v.push(FnSpec::rendered(
        "netnode_lower_bound".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("cur", ArgTy::U64),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::U64,
        "Lowest populated sup index `>= cur` under `tag`, or `BADNODE` when none.".into(),
        nn_return("(uint64_t)n.lower_bound((nodeidx_t)cur, (uchar)tag)"),
    ));
    v.push(FnSpec::rendered(
        "netnode_lower_bound_idx8".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("idx", ArgTy::U32),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::U64,
        "Lowest populated 8-bit sup index at or after `idx` under `tag`, or `BADNODE` when none."
            .into(),
        nn_return("(uint64_t)n.lower_bound_idx8((uchar)idx, (uchar)tag)"),
    ));
    v.push(shift("sup"));
    v.push(FnSpec::rendered(
        "netnode_supdel_range".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("idx1", ArgTy::U64),
            Arg::new("idx2", ArgTy::U64),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::I32,
        "Delete sup elements in `[idx1, idx2)` under `tag`; the number deleted.".into(),
        nn_return("(int32_t)n.supdel_range((nodeidx_t)idx1, (nodeidx_t)idx2, (uchar)tag)"),
    ));
    v.push(del_all("sup"));
}

/// Hash values: string-keyed (tag `htag`); iteration returns the key. Default keying only.
fn hash(v: &mut Vec<FnSpec>) {
    let key = || {
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("key", ArgTy::Str),
            Arg::new("tag", ArgTy::U32),
        ]
    };
    v.push(FnSpec::rendered(
        "netnode_hashval".into(),
        key(),
        RetKind::ResultVecU8,
        "Hash value for `key` under `tag` as raw bytes; `Err` when the key is unset.".into(),
        nn_key_body("  uint8_t buf[MAXSPECSIZE];\n  ssize_t r = n.hashval(k.c_str(), buf, sizeof(buf), (uchar)tag);\n  if (r < 0)\n    throw std::runtime_error(\"hash key is unset\");\n  return to_rust_bytes(buf, (size_t)r);\n"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashstr".into(),
        key(),
        RetKind::ResultString,
        "Hash value for `key` under `tag` as a string; `Err` when the key is unset.".into(),
        nn_key_body("  qstring out;\n  if (n.hashstr(&out, k.c_str(), (uchar)tag) < 0)\n    throw std::runtime_error(\"hash key is unset\");\n  return to_rust_string(out);\n"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashval_long".into(),
        key(),
        RetKind::U64,
        "Hash value for `key` under `tag` decoded as an integer, or `0` when unset.".into(),
        nn_key_return("(uint64_t)n.hashval_long(k.c_str(), (uchar)tag)"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashset".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("key", ArgTy::Str),
            Arg::new("value", ArgTy::Bytes),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::Bool,
        "Set the hash value for `key` under `tag` (max `MAXSPECSIZE` bytes).".into(),
        nn_key_return("n.hashset(k.c_str(), value.data(), value.size(), (uchar)tag)"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashset_long".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("key", ArgTy::Str),
            Arg::new("value", ArgTy::U64),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::Bool,
        "Set the hash value for `key` under `tag` to the integer `value`.".into(),
        nn_key_return("n.hashset(k.c_str(), (nodeidx_t)value, (uchar)tag)"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashdel".into(),
        key(),
        RetKind::Bool,
        "Delete the hash value for `key` under `tag`.".into(),
        nn_key_return("n.hashdel(k.c_str(), (uchar)tag)"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashfirst".into(),
        vec![Arg::new("node", ArgTy::U64), Arg::new("tag", ArgTy::U32)],
        RetKind::ResultString,
        "Lexically first hash key under `tag`; `Err` when the hash is empty.".into(),
        nn_body("  qstring out;\n  if (n.hashfirst(&out, (uchar)tag) < 0)\n    throw std::runtime_error(\"hash is empty\");\n  return to_rust_string(out);\n"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashnext".into(),
        key(),
        RetKind::ResultString,
        "Hash key after `key` under `tag`; `Err` when `key` is the last.".into(),
        nn_key_body("  qstring out;\n  if (n.hashnext(&out, k.c_str(), (uchar)tag) < 0)\n    throw std::runtime_error(\"no next hash key\");\n  return to_rust_string(out);\n"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashlast".into(),
        vec![Arg::new("node", ArgTy::U64), Arg::new("tag", ArgTy::U32)],
        RetKind::ResultString,
        "Lexically last hash key under `tag`; `Err` when the hash is empty.".into(),
        nn_body("  qstring out;\n  if (n.hashlast(&out, (uchar)tag) < 0)\n    throw std::runtime_error(\"hash is empty\");\n  return to_rust_string(out);\n"),
    ));
    v.push(FnSpec::rendered(
        "netnode_hashprev".into(),
        key(),
        RetKind::ResultString,
        "Hash key before `key` under `tag`; `Err` when `key` is the first.".into(),
        nn_key_body("  qstring out;\n  if (n.hashprev(&out, k.c_str(), (uchar)tag) < 0)\n    throw std::runtime_error(\"no previous hash key\");\n  return to_rust_string(out);\n"),
    ));
    v.push(del_all("hash"));
}

/// Char values: 8-bit, sharing sup storage; unset reads as `0`.
fn char_vals(v: &mut Vec<FnSpec>) {
    for k in [DEF, EA, IDX8] {
        let (suf, cast, idx, at) = (k.suffix, k.idx_cast, k.idx_name, k.at);
        v.push(FnSpec::rendered(
            format!("netnode_charval{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::U32,
            format!("Char value {at} under `tag` (0..255), or `0` when unset."),
            nn_return(&format!(
                "(uint32_t)n.charval{suf}({cast}{idx}, (uchar)tag)"
            )),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_charset{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("value", ArgTy::U32),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Set the char value {at} under `tag` (low 8 bits of `value`)."),
            nn_return(&format!(
                "n.charset{suf}({cast}{idx}, (uchar)value, (uchar)tag)"
            )),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_chardel{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(idx, k.idx_ty),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Delete the char value {at} under `tag`."),
            nn_return(&format!("n.chardel{suf}({cast}{idx}, (uchar)tag)")),
        ));
    }
    v.push(shift("char"));
}

/// Blobs: unlimited size, chained across sup slots under any tag. Default and address keyings.
fn blob(v: &mut Vec<FnSpec>) {
    for k in [DEF, EA] {
        let suf = k.suffix;
        let (name, cast, desc) = if suf.is_empty() {
            ("start", "(nodeidx_t)", "index `start`")
        } else {
            ("ea", "(ea_t)", "address `ea`")
        };
        v.push(FnSpec::rendered(
            format!("netnode_blobsize{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new(name, ArgTy::U64),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Usize,
            format!("Byte length of the blob based at {desc} under `tag`, or `0` when absent."),
            nn_return(&format!("n.blobsize{suf}({cast}{name}, (uchar)tag)")),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_getblob{suf}"),
            vec![Arg::new("node", ArgTy::U64), Arg::new(name, ArgTy::U64), Arg::new("tag", ArgTy::U32)],
            RetKind::ResultVecU8,
            format!("The blob based at {desc} under `tag` as owned bytes; `Err` when absent."),
            nn_body(&format!("  bytevec_t blob;\n  ssize_t r = n.getblob{suf}(&blob, {cast}{name}, (uchar)tag);\n  if (r < 0)\n    throw std::runtime_error(\"blob does not exist\");\n  return to_rust_bytes(blob.begin(), blob.size());\n")),
        ));
        v.push(FnSpec::rendered(
            format!("netnode_setblob{suf}"),
            vec![
                Arg::new("node", ArgTy::U64),
                Arg::new("value", ArgTy::Bytes),
                Arg::new(name, ArgTy::U64),
                Arg::new("tag", ArgTy::U32),
            ],
            RetKind::Bool,
            format!("Store `value` as the blob based at {desc} under `tag`."),
            nn_return(&format!(
                "n.setblob{suf}(value.data(), value.size(), {cast}{name}, (uchar)tag)"
            )),
        ));
    }
    v.push(FnSpec::rendered(
        "netnode_delblob".into(),
        vec![
            Arg::new("node", ArgTy::U64),
            Arg::new("start", ArgTy::U64),
            Arg::new("tag", ArgTy::U32),
        ],
        RetKind::I32,
        "Delete the blob based at index `start` under `tag`; the number of slots freed.".into(),
        nn_return("(int32_t)n.delblob((nodeidx_t)start, (uchar)tag)"),
    ));
    v.push(shift("blob"));
}

/// The generated array-family functions in family order.
fn family_fns() -> Vec<FnSpec> {
    let mut v = Vec::new();
    alt(&mut v);
    sup(&mut v);
    hash(&mut v);
    char_vals(&mut v);
    blob(&mut v);
    v
}

/// The irregular lifecycle and node-value functions, kept hand-written with `Custom` bodies in
/// `facade/netnode_custom.cc`.
const CUSTOM_FNS: &[FnSpec] = fns! {
    // Lifecycle.
    "Resolve the netnode named `name`, creating it when `create`; the node id, or `BADNODE` when it \
     is absent and `create` is false."
        netnode_by_name(name: Str, create: Bool) -> U64;
    "Whether `node` has any information attached (a named or non-empty node)."
        netnode_exists(node: U64) -> Bool;
    "Whether a netnode named `name` exists, without creating it."
        netnode_exists_name(name: Str) -> Bool;
    "Delete `node` and every array attached to it."
        netnode_kill(node: U64);
    "Name of `node`; `Err` when it is unnamed."
        netnode_get_name(node: U64) -> ResultString;
    "Rename `node` to `name` (empty clears the name); `false` when `name` is taken."
        netnode_rename(node: U64, name: Str) -> Bool;
    "Lowest-id existing netnode, or `BADNODE` when the database has none."
        netnode_first() -> U64;
    "Highest-id existing netnode, or `BADNODE` when the database has none."
        netnode_last() -> U64;
    "Next existing netnode after `cur`, or `BADNODE` when `cur` is the last."
        netnode_next(cur: U64) -> U64;
    "Previous existing netnode before `cur`, or `BADNODE` when `cur` is the first."
        netnode_prev(cur: U64) -> U64;
    "Copy (or move, when `move_`) `count` nodes starting at `node` onto `target`; the number of \
     nodes affected."
        netnode_copyto(node: U64, count: U64, target: U64, move_: Bool) -> Usize;
    // Node value (vtag).
    "The node value of `node` as raw bytes; `Err` when no value is set."
        netnode_value(node: U64) -> ResultVecU8;
    "The node value of `node` as a string; `Err` when no value is set."
        netnode_value_str(node: U64) -> ResultString;
    "Set the node value of `node` (max `MAXSPECSIZE` bytes)."
        netnode_set_value(node: U64, value: Bytes) -> Bool;
    "Delete the node value of `node`."
        netnode_del_value(node: U64) -> Bool;
};

/// The netnode [`Domain`], built once: the hand-written lifecycle/value functions followed by the
/// matrix-generated array families.
pub fn domain() -> &'static Domain {
    static DOMAIN: OnceLock<Domain> = OnceLock::new();
    DOMAIN.get_or_init(|| {
        let mut fns = CUSTOM_FNS.to_vec();
        fns.extend(family_fns());
        Domain {
            name: "netnode",
            sdk_includes: &["<netnode.hpp>", "<string>", "<stdexcept>"],
            externs: &[],
            structs: &[],
            body_helpers: Some(BODY_HELPERS),
            custom_tu: Some("facade/netnode_custom.cc"),
            fns: Box::leak(fns.into_boxed_slice()),
        }
    })
}

/// The `netnode::<member>` SDK identifier a raw `netnode_*` binding maps to, for a `#[doc(alias)]`
/// that lets a reader of the IDA SDK find the flat binding. `None` where the binding backs a free
/// function or existence probe with no matching member (its own name is already the SDK symbol).
/// Most names strip the `netnode_` prefix to the member verbatim; the arms hold the divergences.
fn sdk_alias(fn_name: &str) -> Option<String> {
    let member: &str = match fn_name {
        "netnode_exists" | "netnode_exists_name" => return None,
        "netnode_value" => "valobj",
        "netnode_value_str" => "valstr",
        "netnode_set_value" => "set",
        "netnode_del_value" => "delvalue",
        "netnode_hashset_long" => "hashset",
        "netnode_first" => "start",
        "netnode_last" => "end",
        "netnode_by_name" => "netnode",
        other => other.strip_prefix("netnode_")?,
    };
    Some(format!("netnode::{member}"))
}

/// The crate-root re-exports for netnode, each carrying a `#[doc(alias)]` naming its SDK member.
/// cxx rejects `#[doc(alias)]` inside the bridge (only `#[doc = ...]` and `#[doc(hidden)]` pass), so
/// the alias rides the re-export instead; it survives the crate's glob re-export into rustdoc search.
/// The generator owns these names, so they are dropped from `bridge_gen.rs`'s hand-written group.
pub fn reexport_tokens() -> TokenStream {
    let uses = domain().fns.iter().map(|f| {
        let name = format_ident!("{}", f.name);
        match sdk_alias(f.name) {
            Some(alias) => quote! {
                #[doc(alias = #alias)]
                pub use ffi::#name;
            },
            None => quote! {
                pub use ffi::#name;
            },
        }
    });
    quote! { #(#uses)* }
}
