//! Reduces a type to [`CanonicalType`], a table-free structural form, and diffs two canonical
//! types into a [`TypeDiff`].
//!
//! A [`TypeValue`](crate::types::TypeValue) references its children by [`TypeId`], an arena index that
//! only means something within its own [`TypeTable`]. So the derived `PartialEq` answers "same type
//! *in this database*" and nothing more. The type-diff workflow asks a harder question: is this
//! type the same as one from *another* database? That needs a representation carrying no table.
//! [`canonicalize`] walks a `(table, id)` into a [`CanonicalType`] whose children are inlined by
//! value, cutting each named aggregate to a nominal reference ([`Named`](CanonicalType::Named)).
//! Recursion bottoms out on that cut, or on a De Bruijn [`BackRef`](CanonicalType::BackRef).
//!
//! The nominal cut is both correct C semantics (a named aggregate *is* its tag) and what makes the
//! walk terminate, since C recursion almost always passes through a named aggregate. The De Bruijn
//! guard covers the rest: the rare synthetic-named or anonymous cycle. Termination is total either
//! way.
//!
//! Four projections fall out of the one value: structural equality (the derive), a stable 128-bit
//! [`key`](CanonicalType::key) for map and dedup use, a canonical [`Display`] string for reading a
//! diff, and a nominal [`identity`](CanonicalType::identity) for pairing types across databases
//! before comparing their bodies.

use std::fmt;
use std::hash::Hash;

use siphasher::sip128::{Hasher128, SipHasher13};

use crate::types::{Type, TypeId, TypeShape, TypeTable};

/// The tag namespace of a tagged aggregate, giving a named [`struct`](AggregateKind::Struct),
/// [`union`](AggregateKind::Union), or [`enum`](AggregateKind::Enum) its nominal identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
            AggregateKind::Struct => "struct",
            AggregateKind::Union => "union",
            AggregateKind::Enum => "enum",
        }
    }
}

/// One field of a canonical aggregate.
///
/// Layout facets (`bit_offset`) are present only when [`CanonicalOptions`] folds sizes in;
/// `bitfield_width` is declared structure, always kept.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
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
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
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
        pointee: Box<CanonicalType>,
        /// The pointer's own width in bytes, or `None` when sizes are abstracted away.
        width: Option<u8>,
    },
    /// `T[len]`.
    Array {
        /// The element type.
        elem: Box<CanonicalType>,
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
        underlying: Box<CanonicalType>,
        /// The `(name, value)` constants in declaration order.
        members: Vec<(String, u64)>,
        /// Size in bytes, or `None` under a size-abstracted key.
        size: Option<u64>,
    },
    /// A function prototype.
    Function {
        /// Return type.
        ret: Box<CanonicalType>,
        /// Parameter types, in order.
        params: Vec<CanonicalType>,
        /// Whether the prototype is variadic.
        varargs: bool,
    },
    /// A typedef: its alias name plus the aliased type. A typedef rename is a diff, so the name
    /// is kept rather than resolved through.
    Typedef {
        /// The alias name.
        name: String,
        /// The aliased type.
        underlying: Box<CanonicalType>,
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
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
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
            CanonicalType::Named { tag, kind } => Some(TypeIdentity::Tagged {
                tag: tag.clone(),
                kind: *kind,
            }),
            CanonicalType::Aggregate {
                tag: Some(tag),
                kind,
                ..
            } => Some(TypeIdentity::Tagged {
                tag: tag.clone(),
                kind: *kind,
            }),
            CanonicalType::Enum { tag: Some(tag), .. } => Some(TypeIdentity::Tagged {
                tag: tag.clone(),
                kind: AggregateKind::Enum,
            }),
            CanonicalType::Typedef { name, .. } => Some(TypeIdentity::Alias { name: name.clone() }),
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
#[allow(clippy::too_many_arguments)] // the plumbing (table/id/stack/opts) is inherent to a walk
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

    /// The structural [`TypeDiff`] from `self` to `other` under the strict (ABI-exact) policy,
    /// empty when the two types are identical.
    ///
    /// The ergonomic form of [`CanonicalType::diff`], for types resolved from two different
    /// databases.
    #[must_use]
    pub fn diff(&self, other: &Type) -> TypeDiff {
        self.canonical().diff(&other.canonical())
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
            CanonicalType::Void => f.write_str("void"),
            CanonicalType::Bool => f.write_str("bool"),
            CanonicalType::Int { bytes, signed } => {
                let sign = if *signed { "i" } else { "u" };
                match bytes {
                    Some(b) => write!(f, "{sign}{}", u32::from(*b) * 8),
                    None => write!(f, "{sign}int"),
                }
            }
            CanonicalType::Float { bytes } => match bytes {
                Some(b) => write!(f, "f{}", u32::from(*b) * 8),
                None => f.write_str("float"),
            },
            CanonicalType::BackRef(n) => write!(f, "#{n}"),
            _ => return None,
        })
    }

    /// The canonical key form (see [`fmt`](CanonicalType::fmt)).
    fn write_canonical(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scalar) = self.write_scalar(f) {
            return scalar;
        }
        match self {
            CanonicalType::Ptr { pointee, width } => {
                f.write_str("ptr")?;
                if let Some(w) = width {
                    write!(f, ":{w}")?;
                }
                write!(f, "({pointee})")
            }
            CanonicalType::Array { elem, len } => write!(f, "[{elem};{len}]"),
            CanonicalType::Named { tag, kind } => write!(f, "{}:{tag}", kind.keyword()),
            CanonicalType::Aggregate {
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
            CanonicalType::Enum {
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
            CanonicalType::Function {
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
            CanonicalType::Typedef { name, underlying } => write!(f, "typedef {name}={underlying}"),
            CanonicalType::Opaque(name) => write!(f, "opaque:{name}"),
            // Scalars and back-refs handled by `write_scalar` above.
            CanonicalType::Void
            | CanonicalType::Bool
            | CanonicalType::Int { .. }
            | CanonicalType::Float { .. }
            | CanonicalType::BackRef(_) => unreachable!("scalars written above"),
        }
    }

    /// The compact, C-ish form for diff display (see [`fmt`](CanonicalType::fmt)).
    fn write_compact(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(scalar) = self.write_scalar(f) {
            return scalar;
        }
        match self {
            CanonicalType::Ptr { pointee, .. } => write!(f, "{pointee:#}*"),
            CanonicalType::Array { elem, len } => write!(f, "{elem:#}[{len}]"),
            CanonicalType::Named { tag, .. } => f.write_str(tag),
            CanonicalType::Aggregate { tag, kind, .. } => {
                f.write_str(kind.keyword())?;
                match tag {
                    Some(t) => write!(f, " {t}"),
                    None => f.write_str(" {...}"),
                }
            }
            CanonicalType::Enum { tag, .. } => match tag {
                Some(t) => write!(f, "enum {t}"),
                None => f.write_str("enum {...}"),
            },
            CanonicalType::Function {
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
            CanonicalType::Typedef { name, .. } => f.write_str(name),
            CanonicalType::Opaque(name) => f.write_str(name),
            CanonicalType::Void
            | CanonicalType::Bool
            | CanonicalType::Int { .. }
            | CanonicalType::Float { .. }
            | CanonicalType::BackRef(_) => unreachable!("scalars written above"),
        }
    }
}

/// An ordered list of [`Change`]s describing the structural difference between two
/// [`CanonicalType`]s, empty when the two are identical.
///
/// Produced by [`CanonicalType::diff`] / [`Type::diff`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
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
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    /// Dotted path from the root to the differing node.
    pub path: String,
    /// What differs there.
    pub kind: ChangeKind,
}

/// The nature of a single [`Change`].
#[derive(Clone, PartialEq, Eq, Debug)]
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
    pub fn diff(&self, other: &CanonicalType) -> TypeDiff {
        let mut changes = Vec::new();
        self.diff_into(String::new(), other, &mut changes);
        TypeDiff { changes }
    }

    /// Append the changes turning `self` into `other` under `path` to `out`.
    fn diff_into(&self, path: String, other: &CanonicalType, out: &mut Vec<Change>) {
        if self == other {
            return;
        }
        match (self, other) {
            (
                CanonicalType::Aggregate {
                    tag: lt,
                    kind: lk,
                    members: lm,
                    size: ls,
                },
                CanonicalType::Aggregate {
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
                CanonicalType::Enum {
                    tag: lt,
                    underlying: lu,
                    members: lm,
                    size: ls,
                },
                CanonicalType::Enum {
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
                CanonicalType::Ptr {
                    pointee: lp,
                    width: lw,
                },
                CanonicalType::Ptr {
                    pointee: rp,
                    width: rw,
                },
            ) if lw == rw => lp.diff_into(path, rp, out),
            (
                CanonicalType::Array { elem: le, len: ll },
                CanonicalType::Array { elem: re, len: rl },
            ) if ll == rl => le.diff_into(path, re, out),
            (
                CanonicalType::Function {
                    ret: lret,
                    params: lp,
                    varargs: lv,
                },
                CanonicalType::Function {
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
                CanonicalType::Void
                | CanonicalType::Bool
                | CanonicalType::Int { .. }
                | CanonicalType::Float { .. }
                | CanonicalType::Ptr { .. }
                | CanonicalType::Array { .. }
                | CanonicalType::Named { .. }
                | CanonicalType::Aggregate { .. }
                | CanonicalType::Enum { .. }
                | CanonicalType::Function { .. }
                | CanonicalType::Typedef { .. }
                | CanonicalType::Opaque(_)
                | CanonicalType::BackRef(_),
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
    fn diff_against(
        &self,
        other: &CanonicalMember,
        parent: &str,
        report_move: bool,
        out: &mut Vec<Change>,
    ) {
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

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;
    use crate::types::{EnumMember, TypeMember, TypeValue};

    fn scalar(table: &mut TypeTable, bytes: u8, signed: bool) -> TypeId {
        table.intern(TypeValue {
            shape: TypeShape::Int { bytes, signed },
            size: Some(u64::from(bytes)),
        })
    }

    fn ptr(table: &mut TypeTable, to: TypeId, width: u64) -> TypeId {
        table.intern(TypeValue {
            shape: TypeShape::Ptr(to),
            size: Some(width),
        })
    }

    fn member(name: &str, bit_offset: u64, ty: TypeId) -> TypeMember {
        TypeMember {
            name: name.to_owned(),
            bit_offset,
            ty,
            bitfield_width: None,
        }
    }

    /// A named `struct point { int x; int y; }` built into `table`, returning its handle.
    fn point(table: &mut TypeTable) -> TypeId {
        let int = scalar(table, 4, true);
        table.intern(TypeValue {
            shape: TypeShape::Struct {
                name: Some("point".to_owned()),
                members: vec![member("x", 0, int), member("y", 32, int)],
            },
            size: Some(8),
        })
    }

    #[test]
    fn scalar_projects_to_all_forms() {
        let mut table = TypeTable::new();
        let id = scalar(&mut table, 4, true);
        let c = canonicalize(&table, id, CanonicalOptions::strict());
        assert!(
            c == CanonicalType::Int {
                bytes: Some(4),
                signed: true
            }
        );
        assert!(c.to_string() == "i32");
        assert!(c.identity().is_none());
        // the key is deterministic
        assert!(c.key() == c.key());
    }

    #[test]
    fn identical_types_in_separate_tables_share_every_projection() {
        // The whole point: two independent tables (two databases) produce equal canonical forms,
        // keys, and strings for the same type, which the table-local `TypeId` equality cannot do.
        let mut a = TypeTable::new();
        let root_a = point(&mut a);
        let ca = canonicalize(&a, root_a, CanonicalOptions::strict());

        let mut b = TypeTable::new();
        let root_b = point(&mut b);
        let cb = canonicalize(&b, root_b, CanonicalOptions::strict());

        assert!(ca == cb);
        assert!(ca.key() == cb.key());
        assert!(ca.to_string() == cb.to_string());
        assert!(ca.identity() == cb.identity());
    }

    #[test]
    fn a_changed_member_keeps_identity_but_changes_the_fingerprint() {
        let mut a = TypeTable::new();
        let root_a = point(&mut a);
        let ca = canonicalize(&a, root_a, CanonicalOptions::strict());

        // point with an extra field: same tag (same identity), different body (different key).
        let mut b = TypeTable::new();
        let int = scalar(&mut b, 4, true);
        let root_b = b.intern(TypeValue {
            shape: TypeShape::Struct {
                name: Some("point".to_owned()),
                members: vec![
                    member("x", 0, int),
                    member("y", 32, int),
                    member("z", 64, int),
                ],
            },
            size: Some(12),
        });
        let cb = canonicalize(&b, root_b, CanonicalOptions::strict());

        assert!(ca.identity() == cb.identity());
        assert!(
            ca.identity()
                == Some(TypeIdentity::Tagged {
                    tag: "point".to_owned(),
                    kind: AggregateKind::Struct,
                })
        );
        assert!(ca != cb);
        assert!(ca.key() != cb.key());
    }

    #[test]
    fn a_named_aggregate_is_spelled_at_root_and_cut_when_referenced() {
        // struct node { node *next; }: the recursive pointer cuts to a nominal reference, so the
        // walk terminates without a back-edge.
        let mut table = TypeTable::new();
        let node = table.alloc_placeholder();
        let node_ptr = ptr(&mut table, node, 8);
        table.fill(
            node,
            TypeValue {
                shape: TypeShape::Struct {
                    name: Some("node".to_owned()),
                    members: vec![member("next", 0, node_ptr)],
                },
                size: Some(8),
            },
        );

        let c = canonicalize(&table, node, CanonicalOptions::strict());
        let CanonicalType::Aggregate { members, .. } = &c else {
            panic!("root spells its body");
        };
        assert!(
            members[0].ty
                == CanonicalType::Ptr {
                    pointee: Box::new(CanonicalType::Named {
                        tag: "node".to_owned(),
                        kind: AggregateKind::Struct,
                    }),
                    width: Some(8),
                }
        );
    }

    #[test]
    fn a_synthetic_named_cycle_closes_with_a_backref() {
        // A `$`-named (synthetic) self-referential struct has no stable tag to cut on, so the De
        // Bruijn guard is what makes it terminate.
        let mut table = TypeTable::new();
        let anon = table.alloc_placeholder();
        let anon_ptr = ptr(&mut table, anon, 8);
        table.fill(
            anon,
            TypeValue {
                shape: TypeShape::Struct {
                    name: Some("$A".to_owned()),
                    members: vec![member("self", 0, anon_ptr)],
                },
                size: Some(8),
            },
        );

        let c = canonicalize(&table, anon, CanonicalOptions::strict());
        let CanonicalType::Aggregate { tag, members, .. } = &c else {
            panic!("a synthetic tag is spelled structurally");
        };
        assert!(tag.is_none()); // synthetic name -> treated as anonymous
        assert!(
            members[0].ty
                == CanonicalType::Ptr {
                    pointee: Box::new(CanonicalType::BackRef(1)),
                    width: Some(8),
                }
        );
    }

    #[test]
    fn the_size_knob_separates_abi_from_logical() {
        // Two structs differing only in field width: an ABI key distinguishes them, a logical key
        // does not (the cross-architecture case).
        let mut a = TypeTable::new();
        let i32t = scalar(&mut a, 4, true);
        let root_a = a.intern(TypeValue {
            shape: TypeShape::Struct {
                name: None,
                members: vec![member("v", 0, i32t)],
            },
            size: Some(4),
        });

        let mut b = TypeTable::new();
        let i64t = scalar(&mut b, 8, true);
        let root_b = b.intern(TypeValue {
            shape: TypeShape::Struct {
                name: None,
                members: vec![member("v", 0, i64t)],
            },
            size: Some(8),
        });

        let strict_a = canonicalize(&a, root_a, CanonicalOptions::strict());
        let strict_b = canonicalize(&b, root_b, CanonicalOptions::strict());
        assert!(strict_a.key() != strict_b.key());

        let logical_a = canonicalize(&a, root_a, CanonicalOptions::logical());
        let logical_b = canonicalize(&b, root_b, CanonicalOptions::logical());
        assert!(logical_a == logical_b);
        assert!(logical_a.key() == logical_b.key());
        assert!(logical_a.to_string() == "struct{v=iint}");
    }

    #[test]
    fn bitfields_ride_along_in_the_member() {
        let mut table = TypeTable::new();
        let u32t = scalar(&mut table, 4, false);
        let root = table.intern(TypeValue {
            shape: TypeShape::Struct {
                name: Some("flags".to_owned()),
                members: vec![TypeMember {
                    name: "lo".to_owned(),
                    bit_offset: 0,
                    ty: u32t,
                    bitfield_width: Some(3),
                }],
            },
            size: Some(4),
        });
        let c = canonicalize(&table, root, CanonicalOptions::strict());
        let CanonicalType::Aggregate { members, .. } = &c else {
            panic!("struct");
        };
        assert!(members[0].bitfield_width == Some(3));
        assert!(c.to_string() == "struct:flags{lo@0:3=u32}=4");
    }

    #[test]
    fn an_enum_spells_at_root_and_cuts_when_referenced() {
        let mut table = TypeTable::new();
        let int = scalar(&mut table, 4, false);
        let color = table.intern(TypeValue {
            shape: TypeShape::Enum {
                name: Some("color".to_owned()),
                underlying: int,
                members: vec![
                    EnumMember {
                        name: "red".to_owned(),
                        value: 0,
                    },
                    EnumMember {
                        name: "green".to_owned(),
                        value: 1,
                    },
                ],
                is_bitmask: false,
            },
            size: Some(4),
        });

        // referenced through a pointer -> nominal cut
        let color_ptr = ptr(&mut table, color, 8);
        let referenced = canonicalize(&table, color_ptr, CanonicalOptions::strict());
        assert!(
            referenced
                == CanonicalType::Ptr {
                    pointee: Box::new(CanonicalType::Named {
                        tag: "color".to_owned(),
                        kind: AggregateKind::Enum,
                    }),
                    width: Some(8),
                }
        );

        // at the root -> spelled
        let defined = canonicalize(&table, color, CanonicalOptions::strict());
        assert!(
            defined.identity()
                == Some(TypeIdentity::Tagged {
                    tag: "color".to_owned(),
                    kind: AggregateKind::Enum,
                })
        );
        // Constants render name-sorted (green before red), not in insertion order, so a reordered
        // enum is one canonical value.
        assert!(defined.to_string() == "enum:color(u32){green=1,red=0}=4");
    }

    #[test]
    fn a_function_prototype_canonicalizes() {
        let mut table = TypeTable::new();
        let int = scalar(&mut table, 4, true);
        let cstr = {
            let ch = table.intern(TypeValue {
                shape: TypeShape::Int {
                    bytes: 1,
                    signed: true,
                },
                size: Some(1),
            });
            ptr(&mut table, ch, 8)
        };
        let proto = table.intern(TypeValue {
            shape: TypeShape::Function {
                ret: int,
                params: vec![cstr],
                varargs: true,
            },
            size: None,
        });
        let c = canonicalize(&table, proto, CanonicalOptions::strict());
        assert!(c.to_string() == "fn(ptr:8(i8),...)->i32");
        assert!(c.identity().is_none());
    }

    #[test]
    fn a_typedef_keeps_its_alias_as_identity() {
        let mut table = TypeTable::new();
        let int = scalar(&mut table, 4, false);
        let alias = table.intern(TypeValue {
            shape: TypeShape::Typedef {
                name: "u32".to_owned(),
                underlying: int,
            },
            size: Some(4),
        });
        let c = canonicalize(&table, alias, CanonicalOptions::strict());
        assert!(
            c.identity()
                == Some(TypeIdentity::Alias {
                    name: "u32".to_owned(),
                })
        );
        assert!(c.to_string() == "typedef u32=u32");
    }

    #[test]
    fn identical_types_diff_to_nothing() {
        let mut t = TypeTable::new();
        let p = point(&mut t);
        let c = canonicalize(&t, p, CanonicalOptions::strict());
        let d = c.diff(&c);
        assert!(d.is_empty());
        assert!(d.to_string() == "(identical)");
    }

    #[test]
    fn a_scalar_retype_is_a_root_change() {
        let a = CanonicalType::Int {
            bytes: Some(4),
            signed: true,
        };
        let b = CanonicalType::Int {
            bytes: Some(8),
            signed: true,
        };
        let d = a.diff(&b);
        assert!(d.changes().len() == 1);
        assert!(d.to_string() == "Change type  i32 → i64");
    }

    #[test]
    fn drift_reports_retype_add_and_size() {
        // point {x:i32, y:i32}=8  ->  point {x:i32, y:i64, z:i32}=16.
        let mut a = TypeTable::new();
        let p = point(&mut a);
        let ca = canonicalize(&a, p, CanonicalOptions::strict());

        let mut b = TypeTable::new();
        let i32t = scalar(&mut b, 4, true);
        let i64t = scalar(&mut b, 8, true);
        let root = b.intern(TypeValue {
            shape: TypeShape::Struct {
                name: Some("point".to_owned()),
                members: vec![
                    member("x", 0, i32t),
                    member("y", 32, i64t),
                    member("z", 96, i32t),
                ],
            },
            size: Some(16),
        });
        let cb = canonicalize(&b, root, CanonicalOptions::strict());

        let d = ca.diff(&cb);
        let s = d.to_string();
        assert!(!d.is_empty());
        assert!(s.contains("Resize"));
        assert!(s.contains("0x8 → 0x10"));
        assert!(s.contains("Change type"));
        assert!(s.contains("i32 → i64"));
        assert!(s.contains("Add"));
        // Metrics: y retyped, z added, root resized, and added+removed+changed plus the size
        // change partition len().
        assert!(d.len() == 3);
        assert!(d.added() == 1);
        assert!(d.removed() == 0);
        assert!(d.changed() == 1);
        assert!(d.size_change() == Some((Some(8), Some(16))));
    }

    #[test]
    fn a_nested_member_change_uses_a_dotted_path() {
        // struct outer { struct { i32 v } in; } with `v` widened on the right.
        let build = |vbytes: u8| {
            let mut t = TypeTable::new();
            let v = scalar(&mut t, vbytes, true);
            let inner = t.intern(TypeValue {
                shape: TypeShape::Struct {
                    name: None,
                    members: vec![member("v", 0, v)],
                },
                size: Some(u64::from(vbytes)),
            });
            let outer = t.intern(TypeValue {
                shape: TypeShape::Struct {
                    name: Some("outer".to_owned()),
                    members: vec![member("in", 0, inner)],
                },
                size: Some(u64::from(vbytes)),
            });
            canonicalize(&t, outer, CanonicalOptions::strict())
        };
        let d = build(4).diff(&build(8));
        let s = d.to_string();
        assert!(s.contains("in.v"));
        assert!(s.contains("i32 → i64"));
    }

    fn cint(bytes: u8, signed: bool) -> CanonicalType {
        CanonicalType::Int {
            bytes: Some(bytes),
            signed,
        }
    }

    fn cfield(name: &str, off: u64, ty: CanonicalType) -> CanonicalMember {
        CanonicalMember {
            name: name.to_owned(),
            bit_offset: Some(off),
            bitfield_width: None,
            ty,
        }
    }

    fn cstruct(tag: &str, members: Vec<CanonicalMember>, size: u64) -> CanonicalType {
        CanonicalType::Aggregate {
            tag: Some(tag.to_owned()),
            kind: AggregateKind::Struct,
            members,
            size: Some(size),
        }
    }

    /// A named enum built into `table`, in the given constant order.
    fn enum_of(table: &mut TypeTable, tag: &str, consts: &[(&str, u64)]) -> TypeId {
        let underlying = scalar(table, 4, false);
        table.intern(TypeValue {
            shape: TypeShape::Enum {
                name: Some(tag.to_owned()),
                underlying,
                members: consts
                    .iter()
                    .map(|(n, v)| EnumMember {
                        name: (*n).to_owned(),
                        value: *v,
                    })
                    .collect(),
                is_bitmask: false,
            },
            size: Some(4),
        })
    }

    #[test]
    fn an_enum_reordered_is_the_same_type() {
        // The LogMark regression: the same constants in a different order must be one canonical
        // value, one key, and an empty diff, not a "drifted" phantom.
        let mut a = TypeTable::new();
        let ea = enum_of(&mut a, "E", &[("A", 1), ("B", 2), ("C", 3)]);
        let ca = canonicalize(&a, ea, CanonicalOptions::strict());
        let mut b = TypeTable::new();
        let eb = enum_of(&mut b, "E", &[("C", 3), ("A", 1), ("B", 2)]);
        let cb = canonicalize(&b, eb, CanonicalOptions::strict());

        assert!(ca == cb);
        assert!(ca.key() == cb.key());
        assert!(ca.diff(&cb).is_empty());
    }

    #[test]
    fn a_union_reordered_is_the_same_type() {
        let build = |order: &[&str]| {
            let mut t = TypeTable::new();
            let i = scalar(&mut t, 4, true);
            let f = scalar(&mut t, 8, false);
            let by_name = |n: &str| TypeMember {
                name: n.to_owned(),
                bit_offset: 0,
                ty: if n == "i" { i } else { f },
                bitfield_width: None,
            };
            let root = t.intern(TypeValue {
                shape: TypeShape::Union {
                    name: Some("U".to_owned()),
                    members: order.iter().map(|n| by_name(n)).collect(),
                },
                size: Some(8),
            });
            canonicalize(&t, root, CanonicalOptions::strict())
        };
        let ca = build(&["i", "f"]);
        let cb = build(&["f", "i"]);
        assert!(ca == cb);
        assert!(ca.diff(&cb).is_empty());
    }

    #[test]
    fn a_renamed_field_is_detected_not_add_remove() {
        let a = cstruct("S", vec![cfield("old", 0, cint(4, true))], 4);
        let b = cstruct("S", vec![cfield("new", 0, cint(4, true))], 4);
        let d = a.diff(&b);
        assert!(d.changes().len() == 1);
        assert!(d.to_string() == "Rename  old → new");
    }

    #[test]
    fn a_repacked_field_moves() {
        // Same members and types, one field at a new offset, no insert/remove -> a Move.
        let a = cstruct(
            "S",
            vec![
                cfield("x", 0, cint(4, true)),
                cfield("y", 64, cint(4, true)),
            ],
            16,
        );
        let b = cstruct(
            "S",
            vec![
                cfield("x", 0, cint(4, true)),
                cfield("y", 96, cint(4, true)),
            ],
            16,
        );
        let d = a.diff(&b);
        assert!(d.to_string() == "Move  y  0x8 → 0xc");
    }

    #[test]
    fn an_inserted_field_does_not_report_the_offset_cascade() {
        // Inserting `mid` shifts `y`; the diff shows the insertion and size, not y's forced move.
        let a = cstruct(
            "S",
            vec![
                cfield("x", 0, cint(4, true)),
                cfield("y", 32, cint(4, true)),
            ],
            8,
        );
        let b = cstruct(
            "S",
            vec![
                cfield("x", 0, cint(4, true)),
                cfield("mid", 32, cint(4, true)),
                cfield("y", 64, cint(4, true)),
            ],
            12,
        );
        let d = a.diff(&b);
        let s = d.to_string();
        assert!(s.contains("Add"));
        assert!(s.contains("mid"));
        assert!(s.contains("Resize"));
        assert!(s.contains("0x8 → 0xc"));
        assert!(!s.contains("Move")); // y's shift is the derivable cascade, suppressed
    }

    #[test]
    fn a_bitfield_width_change_is_flagged() {
        let bf = |w: u32| CanonicalType::Aggregate {
            tag: Some("F".to_owned()),
            kind: AggregateKind::Struct,
            members: vec![CanonicalMember {
                name: "b".to_owned(),
                bit_offset: Some(0),
                bitfield_width: Some(w),
                ty: cint(4, false),
            }],
            size: Some(4),
        };
        let d = bf(3).diff(&bf(5));
        assert!(d.to_string() == "Change width  b  3 → 5");
    }

    #[test]
    fn a_different_tag_is_a_whole_retype() {
        let a = cstruct("A", vec![cfield("x", 0, cint(4, true))], 4);
        let b = cstruct("B", vec![cfield("x", 0, cint(4, true))], 4);
        let d = a.diff(&b);
        assert!(d.changes().len() == 1);
        assert!(let ChangeKind::Retyped { .. } = &d.changes()[0].kind);
    }

    #[test]
    fn a_struct_and_union_of_one_body_still_differ() {
        let s = cstruct("X", vec![cfield("a", 0, cint(4, true))], 4);
        let u = CanonicalType::Aggregate {
            tag: Some("X".to_owned()),
            kind: AggregateKind::Union,
            members: vec![cfield("a", 0, cint(4, true))],
            size: Some(4),
        };
        let d = s.diff(&u);
        assert!(let ChangeKind::Retyped { .. } = &d.changes()[0].kind);
    }

    #[test]
    fn enum_constants_add_remove_and_change() {
        let en = |consts: &[(&str, u64)]| CanonicalType::Enum {
            tag: Some("E".to_owned()),
            underlying: Box::new(cint(4, false)),
            members: consts.iter().map(|(n, v)| ((*n).to_owned(), *v)).collect(),
            size: Some(4),
        };
        let a = en(&[("A", 1), ("B", 2)]);
        let b = en(&[("A", 9), ("C", 3)]); // A changed, B removed, C added
        let d = a.diff(&b);
        let s = d.to_string();
        assert!(s.contains("Change value"));
        assert!(s.contains("0x1 → 0x9"));
        assert!(s.contains("Remove"));
        assert!(s.contains("0x2"));
        assert!(s.contains("Add"));
        assert!(s.contains("0x3"));
        // Constant add/remove/change fold into the same metrics as members; no size change here.
        assert!(d.added() == 1);
        assert!(d.removed() == 1);
        assert!(d.changed() == 1);
        assert!(d.size_change().is_none());
    }
}

/// Property tests: the diff must be *complete*, empty exactly when the two canonical values are
/// equal. A missed difference (a false "identical") fails here with a counterexample.
#[cfg(test)]
mod property {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;

    fn field_name() -> impl Strategy<Value = String> {
        prop_oneof![Just("a"), Just("b"), Just("c"), Just("d")].prop_map(str::to_owned)
    }

    fn const_name() -> impl Strategy<Value = String> {
        prop_oneof![Just("K0"), Just("K1"), Just("K2")].prop_map(str::to_owned)
    }

    fn tag_name() -> impl Strategy<Value = String> {
        prop_oneof![Just("T"), Just("U")].prop_map(str::to_owned)
    }

    fn opt_tag() -> impl Strategy<Value = Option<String>> {
        prop_oneof![Just(None), tag_name().prop_map(Some)]
    }

    fn opt_size() -> impl Strategy<Value = Option<u64>> {
        prop_oneof![Just(None), (0u64..64).prop_map(Some)]
    }

    fn opt_bitfield() -> impl Strategy<Value = Option<u32>> {
        prop_oneof![Just(None), (1u32..8).prop_map(Some)]
    }

    fn agg_kind() -> impl Strategy<Value = AggregateKind> {
        prop_oneof![
            Just(AggregateKind::Struct),
            Just(AggregateKind::Union),
            Just(AggregateKind::Enum),
        ]
    }

    /// Assemble members respecting the canonicalization invariants: distinct names, struct offsets
    /// strictly increasing, union offsets all zero and name-sorted.
    fn build_members(
        kind: AggregateKind,
        raw: Vec<(String, Option<u32>, CanonicalType)>,
    ) -> Vec<CanonicalMember> {
        let mut seen = HashSet::new();
        let mut out: Vec<CanonicalMember> = Vec::new();
        for (name, bitfield_width, ty) in raw {
            if seen.insert(name.clone()) {
                let bit_offset = Some(if kind == AggregateKind::Union {
                    0
                } else {
                    out.len() as u64 * 64
                });
                out.push(CanonicalMember {
                    name,
                    bit_offset,
                    bitfield_width,
                    ty,
                });
            }
        }
        if kind == AggregateKind::Union {
            out.sort_by(|a, b| a.name.cmp(&b.name));
        }
        out
    }

    fn constants() -> impl Strategy<Value = Vec<(String, u64)>> {
        prop::collection::vec((const_name(), any::<u64>()), 0..4).prop_map(|raw| {
            let mut seen = HashSet::new();
            let mut out: Vec<(String, u64)> = Vec::new();
            for (name, value) in raw {
                if seen.insert(name.clone()) {
                    out.push((name, value));
                }
            }
            out.sort_by(|a, b| a.0.cmp(&b.0));
            out
        })
    }

    /// A generator for invariant-respecting canonical types, bounded in depth.
    fn canonical() -> impl Strategy<Value = CanonicalType> {
        let leaf = prop_oneof![
            Just(CanonicalType::Void),
            Just(CanonicalType::Bool),
            (
                prop_oneof![Just(1u8), Just(2u8), Just(4u8), Just(8u8)],
                any::<bool>()
            )
                .prop_map(|(bytes, signed)| CanonicalType::Int {
                    bytes: Some(bytes),
                    signed
                }),
            prop_oneof![Just(4u8), Just(8u8)].prop_map(|b| CanonicalType::Float { bytes: Some(b) }),
            (tag_name(), agg_kind()).prop_map(|(tag, kind)| CanonicalType::Named { tag, kind }),
            tag_name().prop_map(CanonicalType::Opaque),
            (0usize..3).prop_map(CanonicalType::BackRef),
        ];
        leaf.prop_recursive(4, 40, 4, |inner| {
            let members = move |kind: AggregateKind, inner: BoxedStrategy<CanonicalType>| {
                prop::collection::vec((field_name(), opt_bitfield(), inner), 0..4)
                    .prop_map(move |raw| build_members(kind, raw))
            };
            let inner = inner.boxed();
            prop_oneof![
                (
                    inner.clone(),
                    prop_oneof![Just(None), Just(Some(4u8)), Just(Some(8u8))]
                )
                    .prop_map(|(p, width)| CanonicalType::Ptr {
                        pointee: Box::new(p),
                        width
                    }),
                (inner.clone(), 0u64..4).prop_map(|(e, len)| CanonicalType::Array {
                    elem: Box::new(e),
                    len
                }),
                (
                    opt_tag(),
                    members(AggregateKind::Struct, inner.clone()),
                    opt_size()
                )
                    .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                        tag,
                        kind: AggregateKind::Struct,
                        members,
                        size
                    }),
                (
                    opt_tag(),
                    members(AggregateKind::Union, inner.clone()),
                    opt_size()
                )
                    .prop_map(|(tag, members, size)| CanonicalType::Aggregate {
                        tag,
                        kind: AggregateKind::Union,
                        members,
                        size
                    }),
                (opt_tag(), inner.clone(), constants(), opt_size()).prop_map(
                    |(tag, underlying, members, size)| CanonicalType::Enum {
                        tag,
                        underlying: Box::new(underlying),
                        members,
                        size
                    }
                ),
                (tag_name(), inner.clone()).prop_map(|(name, u)| CanonicalType::Typedef {
                    name,
                    underlying: Box::new(u)
                }),
                (
                    inner.clone(),
                    prop::collection::vec(inner, 0..3),
                    any::<bool>()
                )
                    .prop_map(|(ret, params, varargs)| CanonicalType::Function {
                        ret: Box::new(ret),
                        params,
                        varargs
                    }),
            ]
        })
    }

    proptest! {
        /// The core guarantee: diff is empty *iff* the values are equal. This catches any missed
        /// difference (a false "identical"), the class of bug the enum-reorder case exposed.
        #[test]
        fn diff_is_empty_iff_equal(a in canonical(), b in canonical()) {
            prop_assert_eq!(a.diff(&b).is_empty(), a == b);
        }

        /// A value never differs from itself, at any shape.
        #[test]
        fn self_diff_is_empty(a in canonical()) {
            prop_assert!(a.diff(&a).is_empty());
        }
    }
}
