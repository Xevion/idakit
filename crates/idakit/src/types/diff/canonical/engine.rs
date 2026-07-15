//! The diff algorithm: [`TypeDiff`], its [`Change`]s, and the walk that produces them.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::Type;

use super::model::{CanonicalMember, CanonicalType};

/// An ordered list of [`Change`]s describing the structural difference between two
/// [`CanonicalType`]s, empty when the two are identical.
///
/// Produced by [`CanonicalType::diff`] / [`Type::diff`].
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct TypeDiff {
    changes: Vec<Change>,
}

impl TypeDiff {
    /// The changes, in reading order (aggregate size first, then members in declaration order).
    #[inline]
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// Whether the two types are structurally identical (no changes).
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Total number of changes: a rough magnitude for ranking diffs (a two-field retype ranks below
    /// a wholesale rework).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// How many members or constants exist only on the right (additions).
    #[must_use]
    pub fn added(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| matches!(c.kind, ChangeKind::Added(_) | ChangeKind::ConstantAdded(_)))
            .count()
    }

    /// How many members or constants exist only on the left (removals).
    #[must_use]
    pub fn removed(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    ChangeKind::Removed(_) | ChangeKind::ConstantRemoved(_)
                )
            })
            .count()
    }

    /// How many kept slots changed in place: a retype, rename, move, bitfield-width, or
    /// constant-value change. The aggregate's own size is reported separately by
    /// [`size_change`](Self::size_change) and not counted here, so `added + removed + changed` plus
    /// the optional size change partition [`len`](Self::len).
    #[must_use]
    pub fn changed(&self) -> usize {
        self.changes
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    ChangeKind::Retyped { .. }
                        | ChangeKind::Renamed(_)
                        | ChangeKind::Moved { .. }
                        | ChangeKind::BitfieldChanged { .. }
                        | ChangeKind::ConstantChanged { .. }
                )
            })
            .count()
    }

    /// The aggregate's own `(before, after)` byte size if it changed at the root, else `None`.
    #[must_use]
    pub fn size_change(&self) -> Option<(Option<u64>, Option<u64>)> {
        self.changes.iter().find_map(|c| match c.kind {
            ChangeKind::SizeChanged { left, right } if c.path.is_empty() => Some((left, right)),
            _ => None,
        })
    }
}

/// One difference, anchored at a dotted `path` from the compared root (`""` at the root itself,
/// `Tail.Overlay` for a nested member).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Change {
    /// Dotted path from the root to the differing node.
    pub path: String,
    /// What differs there.
    pub kind: ChangeKind,
}

/// The nature of a single [`Change`].
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ChangeKind {
    /// A member present only on the right (added).
    Added(CanonicalType),
    /// A member present only on the left (removed).
    Removed(CanonicalType),
    /// The same slot holds a different type on each side.
    Retyped {
        /// The left (self) type.
        left: CanonicalType,
        /// The right (other) type.
        right: CanonicalType,
    },
    /// A member kept its offset and type but was renamed; the new name is the change
    /// [`path`](Change::path), the old name is carried here.
    Renamed(String),
    /// A member kept its name and type but moved to a different bit offset (a repack that no
    /// insertion or removal explains).
    Moved {
        /// The left bit offset.
        from: u64,
        /// The right bit offset.
        to: u64,
    },
    /// A member's bitfield width changed (`None` for an ordinary, non-bitfield field).
    BitfieldChanged {
        /// The left width.
        from: Option<u32>,
        /// The right width.
        to: Option<u32>,
    },
    /// An aggregate's byte size differs.
    SizeChanged {
        /// The left size.
        left: Option<u64>,
        /// The right size.
        right: Option<u64>,
    },
    /// An enum constant present only on the right; its name is the change [`path`](Change::path).
    ConstantAdded(u64),
    /// An enum constant present only on the left.
    ConstantRemoved(u64),
    /// An enum constant whose value changed.
    ConstantChanged {
        /// The left value.
        left: u64,
        /// The right value.
        right: u64,
    },
}

impl Type {
    /// The structural [`TypeDiff`] from `self` to `other` under the strict (ABI-exact) policy,
    /// empty when the two types are identical.
    ///
    /// The ergonomic form of [`CanonicalType::diff`], for types resolved from two different
    /// databases.
    #[must_use]
    pub fn diff(&self, other: &Self) -> TypeDiff {
        self.canonical().diff(&other.canonical())
    }
}

impl CanonicalType {
    /// The structural [`TypeDiff`] from `self` to `other`, empty exactly when the two are equal.
    ///
    /// Aggregates of the same kind and tag decompose member-by-member. Members pair first by name,
    /// then (among the leftovers) by a shared, unique bit offset, which reads as a rename; anything
    /// still unpaired is an add or a remove. A paired member reports a type change, a bitfield-width
    /// change, and, when no add or remove could explain it, an offset move. Enums of the same tag
    /// decompose by constant name (added, removed, or value-changed). Every other inequality
    /// (different kind, different tag, a scalar, a pointer, a function) is one whole-node
    /// [`Retyped`](ChangeKind::Retyped). The walk stops at [`Named`](CanonicalType::Named) cuts, so a
    /// referenced type's own drift surfaces only when *it* is diffed as a root. A pure offset cascade
    /// (the shift an inserted field imposes on its followers) is deliberately not spelled out, since
    /// the size change and the inserted member already carry it.
    ///
    /// ```
    /// use idakit::prelude::*;
    /// let a = CanonicalType::Int { bytes: Some(4), signed: true };
    /// let b = CanonicalType::Int { bytes: Some(8), signed: true };
    /// assert!(!a.diff(&b).is_empty());
    /// assert!(a.diff(&a).is_empty()); // a type never differs from itself
    /// ```
    #[must_use]
    pub fn diff(&self, other: &Self) -> TypeDiff {
        let mut changes = Vec::new();
        self.diff_into(String::new(), other, &mut changes);
        TypeDiff { changes }
    }

    /// Append the changes turning `self` into `other` under `path` to `out`.
    fn diff_into(&self, path: String, other: &Self, out: &mut Vec<Change>) {
        if self == other {
            return;
        }
        match (self, other) {
            (
                Self::Aggregate {
                    tag: lt,
                    kind: lk,
                    members: lm,
                    size: ls,
                },
                Self::Aggregate {
                    tag: rt,
                    kind: rk,
                    members: rm,
                    size: rs,
                },
            ) if lk == rk && lt == rt => {
                if ls != rs {
                    out.push(Change {
                        path: path.clone(),
                        kind: ChangeKind::SizeChanged {
                            left: *ls,
                            right: *rs,
                        },
                    });
                }
                diff_members(&path, lm, rm, out);
            }
            (
                Self::Enum {
                    tag: lt,
                    underlying: lu,
                    members: lm,
                    size: ls,
                },
                Self::Enum {
                    tag: rt,
                    underlying: ru,
                    members: rm,
                    size: rs,
                },
            ) if lt == rt => {
                lu.diff_into(join(&path, "underlying"), ru, out);
                if ls != rs {
                    out.push(Change {
                        path: path.clone(),
                        kind: ChangeKind::SizeChanged {
                            left: *ls,
                            right: *rs,
                        },
                    });
                }
                diff_constants(&path, lm, rm, out);
            }
            // Transparent wrappers recurse into the part that actually differs, so a nested leaf
            // change reads as one short line instead of two spelled-out subtrees. Only when the
            // wrapper's own shape changes (pointer width, array length, arity/varargs) does it fall
            // through to a whole retype below.
            (
                Self::Ptr {
                    pointee: lp,
                    width: lw,
                },
                Self::Ptr {
                    pointee: rp,
                    width: rw,
                },
            ) if lw == rw => lp.diff_into(path, rp, out),
            (Self::Array { elem: le, len: ll }, Self::Array { elem: re, len: rl }) if ll == rl => {
                le.diff_into(path, re, out);
            }
            (
                Self::Function {
                    ret: lret,
                    params: lp,
                    varargs: lv,
                },
                Self::Function {
                    ret: rret,
                    params: rp,
                    varargs: rv,
                },
            ) if lv == rv && lp.len() == rp.len() => {
                lret.diff_into(join(&path, "return"), rret, out);
                for (i, (a, b)) in lp.iter().zip(rp).enumerate() {
                    a.diff_into(join(&path, &format!("arg{i}")), b, out);
                }
            }
            // Everything else (a scalar, a different aggregate kind or tag, a reshaped wrapper, a
            // mismatched pair) is one whole-node retype. Listed exhaustively so a new variant must
            // be handled.
            (
                Self::Void
                | Self::Bool
                | Self::Int { .. }
                | Self::Float { .. }
                | Self::Ptr { .. }
                | Self::Array { .. }
                | Self::Named { .. }
                | Self::Aggregate { .. }
                | Self::Enum { .. }
                | Self::Function { .. }
                | Self::Typedef { .. }
                | Self::Opaque(_)
                | Self::BackRef(_),
                _,
            ) => out.push(Change {
                path,
                kind: ChangeKind::Retyped {
                    left: self.clone(),
                    right: other.clone(),
                },
            }),
        }
    }
}

impl CanonicalMember {
    /// This member's path under `parent`: its name appended, or just `parent` when anonymous.
    fn path_in(&self, parent: &str) -> String {
        if self.name.is_empty() {
            parent.to_owned()
        } else {
            join(parent, &self.name)
        }
    }

    /// Append the changes turning `self` into `other` (already matched to the same slot) to `out`.
    /// `report_move` gates offset-move reporting, suppressed during an add/remove cascade.
    fn diff_against(&self, other: &Self, parent: &str, report_move: bool, out: &mut Vec<Change>) {
        let at = other.path_in(parent);
        self.ty.diff_into(at.clone(), &other.ty, out);
        if self.bitfield_width != other.bitfield_width {
            out.push(Change {
                path: at.clone(),
                kind: ChangeKind::BitfieldChanged {
                    from: self.bitfield_width,
                    to: other.bitfield_width,
                },
            });
        }
        // A move is reported only when nothing was inserted or removed to explain it; otherwise it
        // is the derivable cascade of that insertion, not an independent change.
        if report_move
            && let (Some(from), Some(to)) = (self.bit_offset, other.bit_offset)
            && from != to
        {
            out.push(Change {
                path: at,
                kind: ChangeKind::Moved { from, to },
            });
        }
    }
}

/// Diff two aggregates' members, pairing by name, then by unique offset (rename), then add/remove.
fn diff_members(path: &str, lm: &[CanonicalMember], rm: &[CanonicalMember], out: &mut Vec<Change>) {
    let mut l_used = vec![false; lm.len()];
    let mut r_used = vec![false; rm.len()];
    // (left index, right index, whether the pairing crossed a name change).
    let mut pairs: Vec<(usize, usize, bool)> = Vec::new();

    // Pass 1: exact name matches (skipping anonymous members, which pair by offset below).
    for (li, l) in lm.iter().enumerate() {
        if l.name.is_empty() {
            continue;
        }
        if let Some(ri) = (0..rm.len()).find(|&ri| !r_used[ri] && rm[ri].name == l.name) {
            l_used[li] = true;
            r_used[ri] = true;
            pairs.push((li, ri, false));
        }
    }
    // Pass 2: unpaired members sharing one unambiguous bit offset, read as a rename in place.
    for li in 0..lm.len() {
        if l_used[li] {
            continue;
        }
        let Some(off) = lm[li].bit_offset else {
            continue;
        };
        let mut at_off = (0..rm.len()).filter(|&ri| !r_used[ri] && rm[ri].bit_offset == Some(off));
        if let (Some(ri), None) = (at_off.next(), at_off.next()) {
            l_used[li] = true;
            r_used[ri] = true;
            pairs.push((li, ri, true));
        }
    }

    let structural = l_used.iter().any(|u| !u) || r_used.iter().any(|u| !u);
    for (li, ri, renamed) in pairs {
        let (l, r) = (&lm[li], &rm[ri]);
        if renamed && l.name != r.name {
            out.push(Change {
                path: r.path_in(path),
                kind: ChangeKind::Renamed(l.name.clone()),
            });
        }
        l.diff_against(r, path, !structural, out);
    }
    for l in lm
        .iter()
        .enumerate()
        .filter(|&(li, _)| !l_used[li])
        .map(|(_, l)| l)
    {
        out.push(Change {
            path: l.path_in(path),
            kind: ChangeKind::Removed(l.ty.clone()),
        });
    }
    for r in rm
        .iter()
        .enumerate()
        .filter(|&(ri, _)| !r_used[ri])
        .map(|(_, r)| r)
    {
        out.push(Change {
            path: r.path_in(path),
            kind: ChangeKind::Added(r.ty.clone()),
        });
    }
}

/// Diff two enums' constants, paired by name (both sides are name-sorted by canonicalization).
fn diff_constants(path: &str, lm: &[(String, u64)], rm: &[(String, u64)], out: &mut Vec<Change>) {
    for (name, value) in lm {
        match rm.iter().find(|(rn, _)| rn == name) {
            Some((_, rv)) if rv != value => out.push(Change {
                path: join(path, name),
                kind: ChangeKind::ConstantChanged {
                    left: *value,
                    right: *rv,
                },
            }),
            Some(_) => {}
            None => out.push(Change {
                path: join(path, name),
                kind: ChangeKind::ConstantRemoved(*value),
            }),
        }
    }
    for (name, value) in rm {
        if !lm.iter().any(|(ln, _)| ln == name) {
            out.push(Change {
                path: join(path, name),
                kind: ChangeKind::ConstantAdded(*value),
            });
        }
    }
}

/// Extend a dotted path with a child name (`""`.`x` -> `x`, `a`.`b` -> `a.b`).
fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_owned()
    } else {
        format!("{path}.{name}")
    }
}

/// Render an optional byte size as hex (`?` when unknown, e.g. under a size-abstracted key).
fn size_str(size: Option<u64>) -> String {
    size.map_or_else(|| "?".to_owned(), |v| format!("{v:#x}"))
}

/// Render a bit offset as a byte offset in hex when byte-aligned, else with a `+Nb` bit remainder.
fn off_str(bits: u64) -> String {
    match bits % 8 {
        0 => format!("{:#x}", bits / 8),
        rem => format!("{:#x}+{rem}b", bits / 8),
    }
}

/// Render an optional bitfield width (`none` for an ordinary field).
fn bits_str(width: Option<u32>) -> String {
    width.map_or_else(|| "none".to_owned(), |w| w.to_string())
}

/// Split a dotted path into `(parent, leaf)`: everything before the last `.`, and the final
/// segment. `("", path)` when the path has no dot.
fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('.') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

/// One [`Change`] flattened into the three columns the verb-led rendering aligns on: a `verb`
/// naming the facet that changed, the `path` to it (empty at the root, or when the verb's own
/// values carry the name), and a `before` value plus an optional `after`. The `after` is absent
/// for an add or remove, present as a `before → after` pair for a change.
struct DiffRow {
    verb: &'static str,
    path: String,
    before: String,
    after: Option<String>,
}

impl Change {
    /// This change as a [`DiffRow`]: the verb, path, and before/after the display aligns and folds.
    fn row(&self) -> DiffRow {
        let path = self.path.clone();
        match &self.kind {
            ChangeKind::Added(t) => DiffRow::single("Add", path, format!("{t:#}")),
            ChangeKind::Removed(t) => DiffRow::single("Remove", path, format!("{t:#}")),
            ChangeKind::ConstantAdded(v) => DiffRow::single("Add", path, format!("{v:#x}")),
            ChangeKind::ConstantRemoved(v) => DiffRow::single("Remove", path, format!("{v:#x}")),
            ChangeKind::Retyped { left, right } => DiffRow::pair(
                "Change type",
                path,
                format!("{left:#}"),
                format!("{right:#}"),
            ),
            ChangeKind::BitfieldChanged { from, to } => {
                DiffRow::pair("Change width", path, bits_str(*from), bits_str(*to))
            }
            ChangeKind::ConstantChanged { left, right } => DiffRow::pair(
                "Change value",
                path,
                format!("{left:#x}"),
                format!("{right:#x}"),
            ),
            ChangeKind::SizeChanged { left, right } => {
                DiffRow::pair("Resize", path, size_str(*left), size_str(*right))
            }
            ChangeKind::Moved { from, to } => {
                DiffRow::pair("Move", path, off_str(*from), off_str(*to))
            }
            // The path is the new full name; show its location in the path column and the rename as
            // `old → new` in the value, so it lines up with every other before/after change.
            ChangeKind::Renamed(from) => {
                let (parent, leaf) = split_parent(&self.path);
                DiffRow::pair("Rename", parent.to_owned(), from.clone(), leaf.to_owned())
            }
        }
    }
}

impl DiffRow {
    fn single(verb: &'static str, path: String, before: String) -> Self {
        Self {
            verb,
            path,
            before,
            after: None,
        }
    }

    fn pair(verb: &'static str, path: String, before: String, after: String) -> Self {
        Self {
            verb,
            path,
            before,
            after: Some(after),
        }
    }

    /// The value column inline: `before`, or `before → after`.
    fn value(&self) -> String {
        match &self.after {
            Some(after) => format!("{} → {}", self.before, after),
            None => self.before.clone(),
        }
    }

    /// Render this row. `verb_w`/`path_w` are the diff's column widths; `has_path` is whether any
    /// row carries a path (so an empty path still reserves the column and values stay aligned).
    /// When the assembled line exceeds `budget`, the value folds onto its own indented lines rather
    /// than overflowing the width.
    fn write(
        &self,
        f: &mut fmt::Formatter<'_>,
        verb_w: usize,
        has_path: bool,
        path_w: usize,
        budget: Option<usize>,
    ) -> fmt::Result {
        let head = if has_path {
            format!("{:verb_w$}  {:path_w$}", self.verb, self.path)
        } else {
            format!("{:verb_w$}", self.verb)
        };
        let line = format!("{head}  {}", self.value());
        if budget.is_none_or(|b| line.chars().count() <= b) {
            return f.write_str(line.trim_end());
        }
        // Too wide: keep just verb + path on the head line, fold the value beneath it.
        if has_path && !self.path.is_empty() {
            write!(f, "{:verb_w$}  {}", self.verb, self.path)?;
        } else {
            f.write_str(self.verb)?;
        }
        match &self.after {
            Some(after) => write!(f, "\n      {}\n    → {}", self.before, after),
            None => write!(f, "\n      {}", self.before),
        }
    }
}

impl fmt::Display for TypeDiff {
    /// Verb-led and column-aligned: each change is `<verb>  <path>  <before> → <after>`, the verb
    /// and path padded to per-diff column widths so facets line up (an add or remove has no
    /// `after`; a resize or a root retype has no path). A line too wide for `f.width()`, when a
    /// caller sets one, folds its value onto indented lines rather than being clipped.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.changes.is_empty() {
            return f.write_str("(identical)");
        }
        let rows: Vec<DiffRow> = self.changes.iter().map(Change::row).collect();
        let verb_w = rows.iter().map(|r| r.verb.len()).max().unwrap_or(0);
        let has_path = rows.iter().any(|r| !r.path.is_empty());
        let path_w = rows
            .iter()
            .map(|r| r.path.chars().count())
            .max()
            .unwrap_or(0);
        let budget = f.width();

        for (i, r) in rows.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            r.write(f, verb_w, has_path, path_w, budget)?;
        }
        Ok(())
    }
}
