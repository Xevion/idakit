//! The canonical type model: [`CanonicalType`] and the [`canonicalize`] walk that produces it.

use std::fmt;
use std::hash::Hash;

use serde::{Deserialize, Serialize};
use siphasher::sip128::{Hasher128, SipHasher13};

use crate::types::{Type, TypeId, TypeShape, TypeTable};

/// The tag namespace of a tagged aggregate, giving a named [`struct`](AggregateKind::Struct),
/// [`union`](AggregateKind::Union), or [`enum`](AggregateKind::Enum) its nominal identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum AggregateKind {
    /// A `struct`.
    Struct,
    /// A `union`.
    Union,
    /// An `enum`.
    Enum,
}

impl AggregateKind {
    /// The C keyword for this aggregate, used in the canonical string.
    #[inline]
    #[must_use]
    pub const fn keyword(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
        }
    }
}

impl fmt::Display for AggregateKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.keyword())
    }
}

/// One field of a canonical aggregate.
///
/// Layout facets (`bit_offset`) are present only when [`CanonicalOptions`] folds sizes in;
/// `bitfield_width` is declared structure, always kept.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CanonicalMember {
    /// The field's name; empty if IDA gave none.
    pub name: String,
    /// Bit offset from the start of the aggregate, or `None` under a size-abstracted key.
    pub bit_offset: Option<u64>,
    /// Bitfield width in bits, or `None` for an ordinary field.
    pub bitfield_width: Option<u32>,
    /// The field's type, inlined by value (a named aggregate is a [`Named`](CanonicalType::Named) cut).
    pub ty: CanonicalType,
}

/// A table-free structural form of a type.
///
/// Children are inlined by value; a named aggregate is a [`Named`](CanonicalType::Named) reference
/// rather than a nested body, so two databases produce equal values for equal types. A closed
/// mirror of [`TypeShape`], with the table-relative [`TypeId`] handles resolved away.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum CanonicalType {
    /// `void`.
    Void,
    /// `bool`.
    Bool,
    /// An integer; `bytes` is `None` under a size-abstracted key.
    Int {
        /// Width in bytes, or `None` when sizes are abstracted away.
        bytes: Option<u8>,
        /// Whether it is signed.
        signed: bool,
    },
    /// A floating-point type; `bytes` is `None` under a size-abstracted key.
    Float {
        /// Width in bytes, or `None` when sizes are abstracted away.
        bytes: Option<u8>,
    },
    /// `T *`. `width` is the pointer's own byte size, `None` under a size-abstracted key.
    Ptr {
        /// The addressed type.
        pointee: Box<Self>,
        /// The pointer's own width in bytes, or `None` when sizes are abstracted away.
        width: Option<u8>,
    },
    /// `T[len]`.
    Array {
        /// The element type.
        elem: Box<Self>,
        /// Number of elements.
        len: u64,
    },
    /// A nominal reference to a named aggregate: its identity is the tag, its body deliberately
    /// omitted so recursion terminates and cross-database comparison keys on the name.
    Named {
        /// The aggregate's tag.
        tag: String,
        /// Whether it is a struct, union, or enum.
        kind: AggregateKind,
    },
    /// A fully spelled struct or union: either anonymous, or the root definition whose body is
    /// being compared (nested references to it are [`Named`](CanonicalType::Named) cuts).
    Aggregate {
        /// The tag, or `None` if anonymous (or synthetically named).
        tag: Option<String>,
        /// Struct or union.
        kind: AggregateKind,
        /// Fields in declaration order.
        members: Vec<CanonicalMember>,
        /// Size in bytes, or `None` under a size-abstracted key.
        size: Option<u64>,
    },
    /// A fully spelled enum.
    Enum {
        /// The tag, or `None` if anonymous.
        tag: Option<String>,
        /// The underlying integer type.
        underlying: Box<Self>,
        /// The `(name, value)` constants in declaration order.
        members: Vec<(String, u64)>,
        /// Size in bytes, or `None` under a size-abstracted key.
        size: Option<u64>,
    },
    /// A function prototype.
    Function {
        /// Return type.
        ret: Box<Self>,
        /// Parameter types, in order.
        params: Vec<Self>,
        /// Whether the prototype is variadic.
        varargs: bool,
    },
    /// A typedef: its alias name plus the aliased type. A typedef rename is a diff, so the name
    /// is kept rather than resolved through.
    Typedef {
        /// The alias name.
        name: String,
        /// The aliased type.
        underlying: Box<Self>,
    },
    /// A named type with no available body: a forward declaration or unresolved reference.
    /// Nominal-only, its identity is known but its structure is not.
    Opaque(String),
    /// A De Bruijn back-reference to an enclosing aggregate `n` levels up, closing a cycle that
    /// the nominal cut did not (a synthetic-named or anonymous recursive type).
    BackRef(usize),
}

/// A stable 128-bit fingerprint of a [`CanonicalType`].
///
/// Equal types hash equal on any machine and any run (SipHash-1-3 guarantees cross-platform
/// stability), so it keys a `HashMap` spanning databases or a persisted type index. At 128 bits a
/// collision is negligible, so an equal key can be treated as an equal type.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct TypeKey(pub u128);

impl fmt::Display for TypeKey {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// The nominal identity of a type, the name that pairs it with a type from another database
/// before their bodies are compared.
///
/// `None` for an anonymous or purely structural type, which has no cross-database name to pair on.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum TypeIdentity {
    /// A tagged aggregate, identified by tag and kind.
    Tagged {
        /// The aggregate's tag.
        tag: String,
        /// Whether it is a struct, union, or enum.
        kind: AggregateKind,
    },
    /// A typedef, identified by its alias name.
    Alias {
        /// The alias name.
        name: String,
    },
}

/// How much of a type's layout the canonical form folds in.
///
/// [`strict`](Self::strict) keys on the exact ABI (widths, offsets), the right lens for a
/// same-architecture diff. [`logical`](Self::logical) drops those, matching a type by shape across
/// architectures where `long` and pointers change width.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CanonicalOptions {
    /// Fold concrete byte widths and bit offsets into the key.
    pub include_sizes: bool,
}

impl CanonicalOptions {
    /// ABI-exact, with widths and offsets part of the key. The same-architecture diff lens.
    #[inline]
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            include_sizes: true,
        }
    }

    /// Size-abstracted, dropping widths and offsets so a type matches by shape across
    /// architectures. Coarser, and it collapses same-shape scalars of different widths.
    #[inline]
    #[must_use]
    pub const fn logical() -> Self {
        Self {
            include_sizes: false,
        }
    }

    /// A scalar's width under this policy.
    #[inline]
    fn width(self, bytes: u8) -> Option<u8> {
        self.include_sizes.then_some(bytes)
    }

    /// A pointer's own width under this policy (dropped, or narrowed from the recorded size).
    #[inline]
    fn ptr_width(self, size: Option<u64>) -> Option<u8> {
        self.include_sizes
            .then(|| size.and_then(|s| u8::try_from(s).ok()))
            .flatten()
    }

    /// A member's bit offset under this policy.
    #[inline]
    fn offset(self, bits: u64) -> Option<u64> {
        self.include_sizes.then_some(bits)
    }

    /// An aggregate's size under this policy.
    #[inline]
    fn size(self, size: Option<u64>) -> Option<u64> {
        self.include_sizes.then_some(size).flatten()
    }
}

impl Default for CanonicalOptions {
    #[inline]
    fn default() -> Self {
        Self::strict()
    }
}

impl CanonicalType {
    /// The stable 128-bit [`TypeKey`] for this canonical form.
    ///
    /// ```
    /// use idakit::prelude::*;
    /// let t = CanonicalType::Int { bytes: Some(4), signed: true };
    /// assert_eq!(t.to_string(), "i32");
    /// assert_eq!(t.key(), t.key()); // stable across calls
    /// ```
    #[must_use]
    pub fn key(&self) -> TypeKey {
        // Zero-keyed SipHash-1-3: the point is a fixed, cross-run/platform-stable digest, not
        // keyed-MAC secrecy, so a constant key is correct here.
        let mut hasher = SipHasher13::new();
        self.hash(&mut hasher);
        TypeKey(hasher.finish128().as_u128())
    }

    /// The nominal [`identity`](TypeIdentity) of this type, or `None` when it is anonymous or
    /// purely structural.
    ///
    /// Reads only the root, since pairing happens before bodies are compared.
    ///
    /// ```
    /// use idakit::prelude::*;
    /// let named = CanonicalType::Named { tag: "point".into(), kind: AggregateKind::Struct };
    /// assert!(named.identity().is_some());
    /// assert!(CanonicalType::Int { bytes: Some(4), signed: true }.identity().is_none());
    /// ```
    #[must_use]
    pub fn identity(&self) -> Option<TypeIdentity> {
        match self {
            Self::Named { tag, kind }
            | Self::Aggregate {
                tag: Some(tag),
                kind,
                ..
            } => Some(TypeIdentity::Tagged {
                tag: tag.clone(),
                kind: *kind,
            }),
            Self::Enum { tag: Some(tag), .. } => Some(TypeIdentity::Tagged {
                tag: tag.clone(),
                kind: AggregateKind::Enum,
            }),
            Self::Typedef { name, .. } => Some(TypeIdentity::Alias { name: name.clone() }),
            _ => None,
        }
    }
}

/// Whether a tag is IDA-synthetic and thus not stable across databases. IDA names anonymous or
/// compiler-generated types `$AB1234`; keying on such a name would reintroduce the mismatch the
/// canonical form removes, so a synthetic tag is treated as anonymous. Heuristic: the `$` prefix
/// is IDA's marker (an empty tag is likewise no identity).
fn is_synthetic(tag: &str) -> bool {
    tag.is_empty() || tag.starts_with('$')
}

/// Walks a `(table, root)` into a table-free [`CanonicalType`] under `opts`.
///
/// Backs [`Type::canonical`]; a ctree or frame holding its own `(table, id)` pair canonicalizes
/// the same way.
#[must_use]
pub fn canonicalize(table: &TypeTable, root: TypeId, opts: CanonicalOptions) -> CanonicalType {
    let mut stack = Vec::new();
    canon(table, root, opts, &mut stack, true)
}

/// The recursive core. `spell_named` is true only for the root. A named aggregate spells its body
/// at the root (the definition being compared) and cuts to [`Named`](CanonicalType::Named)
/// everywhere else. `stack` holds the aggregate ids currently being spelled, so a cycle the
/// nominal cut misses closes as a [`BackRef`](CanonicalType::BackRef).
fn canon(
    table: &TypeTable,
    id: TypeId,
    opts: CanonicalOptions,
    stack: &mut Vec<TypeId>,
    spell_named: bool,
) -> CanonicalType {
    let value = table.get(id);
    match &value.shape {
        TypeShape::Void => CanonicalType::Void,
        TypeShape::Bool => CanonicalType::Bool,
        TypeShape::Int { bytes, signed } => CanonicalType::Int {
            bytes: opts.width(*bytes),
            signed: *signed,
        },
        TypeShape::Float { bytes } => CanonicalType::Float {
            bytes: opts.width(*bytes),
        },
        TypeShape::Ptr(inner) => CanonicalType::Ptr {
            pointee: Box::new(canon(table, *inner, opts, stack, false)),
            width: opts.ptr_width(value.size),
        },
        TypeShape::Array { elem, len } => CanonicalType::Array {
            elem: Box::new(canon(table, *elem, opts, stack, false)),
            len: *len,
        },
        TypeShape::Struct { name, members } => aggregate(
            table,
            id,
            AggregateKind::Struct,
            name.as_deref(),
            members,
            value.size,
            opts,
            stack,
            spell_named,
        ),
        TypeShape::Union { name, members } => aggregate(
            table,
            id,
            AggregateKind::Union,
            name.as_deref(),
            members,
            value.size,
            opts,
            stack,
            spell_named,
        ),
        TypeShape::Enum {
            name,
            underlying,
            members,
            // Not part of canonical structural identity: only the tag, underlying type, and
            // constants distinguish two enums for diffing.
            is_bitmask: _,
            repr: _,
        } => {
            if let Some(cut) = nominal_cut(name.as_deref(), AggregateKind::Enum, spell_named) {
                return cut;
            }
            // Constant order carries no meaning, so sort by name: two databases that list the
            // same constants in a different order must produce one canonical value (and key).
            let mut constants: Vec<(String, u64)> =
                members.iter().map(|m| (m.name.clone(), m.value)).collect();
            constants.sort_by(|a, b| a.0.cmp(&b.0));
            CanonicalType::Enum {
                tag: real_tag(name.as_deref()),
                underlying: Box::new(canon(table, *underlying, opts, stack, false)),
                members: constants,
                size: opts.size(value.size),
            }
        }
        TypeShape::Function {
            ret,
            params,
            varargs,
        } => CanonicalType::Function {
            ret: Box::new(canon(table, *ret, opts, stack, false)),
            params: params
                .iter()
                .map(|p| canon(table, *p, opts, stack, false))
                .collect(),
            varargs: *varargs,
        },
        TypeShape::Typedef { name, underlying } => CanonicalType::Typedef {
            name: name.clone(),
            underlying: Box::new(canon(table, *underlying, opts, stack, false)),
        },
        TypeShape::Opaque(name) => CanonicalType::Opaque(name.clone()),
        // A valid `Type` rejects unfilled placeholders at build time, so this is unreachable in
        // practice; surface it as an opaque marker rather than panicking.
        TypeShape::Unknown => CanonicalType::Opaque("<unfilled>".to_owned()),
    }
}

/// The real, cross-database-stable tag of a maybe-named aggregate: `None` for anonymous or
/// synthetic names.
fn real_tag(name: Option<&str>) -> Option<String> {
    name.filter(|n| !is_synthetic(n)).map(str::to_owned)
}

/// The nominal cut for a named aggregate referenced away from the root: `Some(Named)` when it has
/// a stable tag and is not the root definition, else `None` (spell it structurally).
fn nominal_cut(
    name: Option<&str>,
    kind: AggregateKind,
    spell_named: bool,
) -> Option<CanonicalType> {
    match real_tag(name) {
        Some(tag) if !spell_named => Some(CanonicalType::Named { tag, kind }),
        _ => None,
    }
}

/// Canonicalize a struct or union, cutting to [`Named`](CanonicalType::Named) if referenced, or
/// else spelling the body and closing any residual cycle with a [`BackRef`](CanonicalType::BackRef).
#[expect(
    clippy::too_many_arguments,
    reason = "the plumbing (table/id/stack/opts) is inherent to a walk"
)]
fn aggregate(
    table: &TypeTable,
    id: TypeId,
    kind: AggregateKind,
    name: Option<&str>,
    members: &[crate::types::TypeMember],
    size: Option<u64>,
    opts: CanonicalOptions,
    stack: &mut Vec<TypeId>,
    spell_named: bool,
) -> CanonicalType {
    if let Some(cut) = nominal_cut(name, kind, spell_named) {
        return cut;
    }
    if let Some(pos) = stack.iter().rposition(|x| *x == id) {
        return CanonicalType::BackRef(stack.len() - pos);
    }
    stack.push(id);
    let mut members: Vec<CanonicalMember> = members
        .iter()
        .map(|m| CanonicalMember {
            name: m.name.clone(),
            bit_offset: opts.offset(m.bit_offset),
            bitfield_width: m.bitfield_width,
            ty: canon(table, m.ty, opts, stack, false),
        })
        .collect();
    stack.pop();
    // A union's members all sit at offset 0, so their order carries no meaning; sort by name so a
    // reordered union is one canonical value. A struct's order *is* its layout, so leave it.
    if kind == AggregateKind::Union {
        members.sort_by(|a, b| a.name.cmp(&b.name));
    }
    CanonicalType::Aggregate {
        tag: real_tag(name),
        kind,
        members,
        size: opts.size(size),
    }
}

impl Type {
    /// This type's [`CanonicalType`] under the strict (ABI-exact) policy.
    #[must_use]
    pub fn canonical(&self) -> CanonicalType {
        canonicalize(self.types(), self.root(), CanonicalOptions::strict())
    }

    /// This type's [`CanonicalType`] under an explicit [`CanonicalOptions`].
    #[must_use]
    pub fn canonical_with(&self, opts: CanonicalOptions) -> CanonicalType {
        canonicalize(self.types(), self.root(), opts)
    }

    /// This type's nominal [`identity`](TypeIdentity), or `None` when anonymous or structural.
    #[must_use]
    pub fn identity(&self) -> Option<TypeIdentity> {
        self.canonical().identity()
    }
}

impl fmt::Display for CanonicalType {
    /// Two renderings of one type. The default (`{}`) is the canonical key form: total,
    /// deterministic, and self-delimiting, so equal values print equal strings and the string is
    /// itself a stable key (`ptr:8(struct:node)`). The alternate (`{:#}`) is a compact, C-ish form
    /// for humans reading a diff, with widths, offsets, and typedef bodies dropped and aggregates
    /// shown by header only (`node *`, `i32(i8*, ...)`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.write_compact(f)
        } else {
            self.write_canonical(f)
        }
    }
}

impl CanonicalType {
    /// A scalar's spelling, shared by both renderings (`i32`, `u8`, `f64`, `iint`).
    fn write_scalar(&self, f: &mut fmt::Formatter<'_>) -> Option<fmt::Result> {
        Some(match self {
            Self::Void => f.write_str("void"),
            Self::Bool => f.write_str("bool"),
            Self::Int { bytes, signed } => {
                let sign = if *signed { "i" } else { "u" };
                match bytes {
                    Some(b) => write!(f, "{sign}{}", u32::from(*b) * 8),
                    None => write!(f, "{sign}int"),
                }
            }
            Self::Float { bytes } => match bytes {
                Some(b) => write!(f, "f{}", u32::from(*b) * 8),
                None => f.write_str("float"),
            },
            Self::BackRef(n) => write!(f, "#{n}"),
            _ => return None,
        })
    }

    /// The canonical key form (see [`fmt`](CanonicalType::fmt)).
    fn write_canonical(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scalar) = self.write_scalar(f) {
            return scalar;
        }
        match self {
            Self::Ptr { pointee, width } => {
                f.write_str("ptr")?;
                if let Some(w) = width {
                    write!(f, ":{w}")?;
                }
                write!(f, "({pointee})")
            }
            Self::Array { elem, len } => write!(f, "[{elem};{len}]"),
            Self::Named { tag, kind } => write!(f, "{}:{tag}", kind.keyword()),
            Self::Aggregate {
                tag,
                kind,
                members,
                size,
            } => {
                f.write_str(kind.keyword())?;
                if let Some(t) = tag {
                    write!(f, ":{t}")?;
                }
                f.write_str("{")?;
                for (i, m) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    f.write_str(&m.name)?;
                    if let Some(o) = m.bit_offset {
                        write!(f, "@{o}")?;
                    }
                    if let Some(w) = m.bitfield_width {
                        write!(f, ":{w}")?;
                    }
                    write!(f, "={}", m.ty)?;
                }
                f.write_str("}")?;
                if let Some(s) = size {
                    write!(f, "={s}")?;
                }
                Ok(())
            }
            Self::Enum {
                tag,
                underlying,
                members,
                size,
            } => {
                f.write_str("enum")?;
                if let Some(t) = tag {
                    write!(f, ":{t}")?;
                }
                write!(f, "({underlying}){{")?;
                for (i, (n, v)) in members.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{n}={v}")?;
                }
                f.write_str("}")?;
                if let Some(s) = size {
                    write!(f, "={s}")?;
                }
                Ok(())
            }
            Self::Function {
                ret,
                params,
                varargs,
            } => {
                f.write_str("fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{p}")?;
                }
                if *varargs {
                    if !params.is_empty() {
                        f.write_str(",")?;
                    }
                    f.write_str("...")?;
                }
                write!(f, ")->{ret}")
            }
            Self::Typedef { name, underlying } => write!(f, "typedef {name}={underlying}"),
            Self::Opaque(name) => write!(f, "opaque:{name}"),
            // Scalars and back-refs handled by `write_scalar` above.
            Self::Void | Self::Bool | Self::Int { .. } | Self::Float { .. } | Self::BackRef(_) => {
                unreachable!("scalars written above")
            }
        }
    }

    /// The compact, C-ish form for diff display (see [`fmt`](CanonicalType::fmt)).
    fn write_compact(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scalar) = self.write_scalar(f) {
            return scalar;
        }
        match self {
            Self::Ptr { pointee, .. } => write!(f, "{pointee:#}*"),
            Self::Array { elem, len } => write!(f, "{elem:#}[{len}]"),
            Self::Named { tag, .. } => f.write_str(tag),
            Self::Aggregate { tag, kind, .. } => {
                f.write_str(kind.keyword())?;
                match tag {
                    Some(t) => write!(f, " {t}"),
                    None => f.write_str(" {...}"),
                }
            }
            Self::Enum { tag, .. } => match tag {
                Some(t) => write!(f, "enum {t}"),
                None => f.write_str("enum {...}"),
            },
            Self::Function {
                ret,
                params,
                varargs,
            } => {
                write!(f, "{ret:#}(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{p:#}")?;
                }
                if *varargs {
                    if !params.is_empty() {
                        f.write_str(", ")?;
                    }
                    f.write_str("...")?;
                }
                f.write_str(")")
            }
            Self::Typedef { name, .. } | Self::Opaque(name) => f.write_str(name),
            Self::Void | Self::Bool | Self::Int { .. } | Self::Float { .. } | Self::BackRef(_) => {
                unreachable!("scalars written above")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use assert2::assert;

    use super::*;

    #[test]
    fn canonical_type_serde_round_trips() {
        let ty = CanonicalType::Aggregate {
            tag: Some("point".to_owned()),
            kind: AggregateKind::Struct,
            members: vec![CanonicalMember {
                name: "x".to_owned(),
                bit_offset: Some(0),
                bitfield_width: None,
                ty: CanonicalType::Int {
                    bytes: Some(4),
                    signed: true,
                },
            }],
            size: Some(8),
        };
        let json = serde_json::to_string(&ty).unwrap();
        let back: CanonicalType = serde_json::from_str(&json).unwrap();
        assert!(back == ty);
    }

    #[test]
    fn type_key_serde_round_trips() {
        let key = TypeKey(0x1234_5678_9abc_def0_1122_3344_5566_7788);
        let json = serde_json::to_string(&key).unwrap();
        let back: TypeKey = serde_json::from_str(&json).unwrap();
        assert!(back == key);
    }

    #[test]
    fn type_identity_serde_round_trips() {
        let identity = TypeIdentity::Tagged {
            tag: "point".to_owned(),
            kind: AggregateKind::Struct,
        };
        let json = serde_json::to_string(&identity).unwrap();
        let back: TypeIdentity = serde_json::from_str(&json).unwrap();
        assert!(back == identity);
    }

    #[test]
    fn canonical_options_serde_round_trips() {
        let opts = CanonicalOptions::logical();
        let json = serde_json::to_string(&opts).unwrap();
        let back: CanonicalOptions = serde_json::from_str(&json).unwrap();
        assert!(back == opts);
    }

    #[test]
    fn canonical_options_hash_distinguishes_strict_and_logical() {
        let mut set = HashSet::new();
        set.insert(CanonicalOptions::strict());
        set.insert(CanonicalOptions::logical());
        set.insert(CanonicalOptions::strict());
        assert!(set.len() == 2);
    }

    #[test]
    fn aggregate_kind_display() {
        assert!(AggregateKind::Struct.to_string() == "struct");
        assert!(AggregateKind::Union.to_string() == "union");
        assert!(AggregateKind::Enum.to_string() == "enum");
    }
}
