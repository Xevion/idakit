//! Constructs [`TypeExpr`], the owned recipe a type write applies.
//!
//! A `TypeExpr` is the *constructor intent* for a type: what to apply, built off the kernel thread
//! and infallibly, with every parse or resolution deferred to the one apply call. It is a small
//! recursive algebra: scalar leaves ([`int32`], [`void`], and so on), a named-type reference
//! ([`named`]), a raw C declaration ([`decl`]), a function prototype ([`function`]), and the
//! transforms that wrap an inner recipe ([`pointer`](TypeExpr::pointer),
//! [`array`](TypeExpr::array), [`const_`](TypeExpr::const_)). The shape follows one rule: a free
//! function is a root, a method is a transform. Passing a bare `&str` classifies it: a name that
//! could exist routes by-name, a keyword or a declarator is parsed.
//!
//! ```
//! use idakit::types::expr;
//!
//! // A reference to an existing type, resolved by name at apply time.
//! let by_name = expr::named("Widget");
//! // A declaration, parsed against the database's type library at apply time.
//! let by_decl = expr::decl("Widget *");
//!
//! // `&str` classifies itself: a name that could exist is by-name, a keyword or declarator is a
//! // declaration.
//! use idakit::types::TypeExpr;
//! assert!(TypeExpr::from("Widget") == by_name);
//! assert!(TypeExpr::from("Widget *") == by_decl);
//! assert!(TypeExpr::from("int").is_decl()); // a builtin keyword parses; it is not a named type
//!
//! // The combinators build a composite by wrapping an inner recipe.
//! let pp = expr::named("Widget").pointer().pointer(); // Widget **
//! assert!(pp.as_pointer().unwrap().is_pointer());
//! ```

use std::fmt;

use idakit_sys as sys;

/// An owned, `Send`, table-free recipe for a type to apply.
///
/// The write-side analog of a resolved [`Type`](crate::types::Type): un-lifetimed, it names *what
/// to apply* without touching the kernel, so it is built anywhere and applied at one fallible call.
/// `Ord` lets a batch of recipes sort, group, and dedup.
///
/// Every form lowers to a `tinfo_t` at apply time: a [`Named`](Self::Named) reference resolves in
/// the local type library, a [`Decl`](Self::Decl) is parsed, and a scalar leaf or composite is
/// built bottom-up through the facade from a postfix serialization.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum TypeExpr {
    /// The `void` type.
    Void,
    /// The boolean type.
    Bool,
    /// An integer type.
    Int {
        /// Width in bytes.
        bytes: u8,
        /// Signed rather than unsigned.
        signed: bool,
    },
    /// A floating-point type.
    Float {
        /// Width in bytes.
        bytes: u8,
    },
    /// A C declaration, parsed against the database's type library at apply time.
    Decl(String),
    /// A reference to an existing named type, resolved at apply time.
    Named(String),
    /// A pointer to the inner recipe.
    Pointer(Box<TypeExpr>),
    /// An array of the inner recipe.
    Array {
        /// The element type.
        elem: Box<TypeExpr>,
        /// The element count.
        len: u64,
    },
    /// The inner recipe qualified `const`.
    Const(Box<TypeExpr>),
    /// The inner recipe qualified `volatile`.
    Volatile(Box<TypeExpr>),
    /// A function prototype: a return type, ordered parameters, and a varargs flag.
    Function {
        /// The return type.
        ret: Box<TypeExpr>,
        /// The parameters, in order.
        params: Vec<Param>,
        /// Whether the prototype ends in `...`.
        varargs: bool,
    },
}

/// One parameter of a [`function`] recipe: an optional name and its type.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Param {
    /// The parameter name, or `None` for an unnamed slot.
    pub name: Option<String>,
    /// The parameter type.
    pub ty: TypeExpr,
}

/// A reference to the existing named type `name`, resolved at apply time.
///
/// The explicit by-name root: unlike `TypeExpr::from("Foo")`, it forces the name path even for a
/// spelling a declaration parser would also accept, so an absent type reports
/// [`TypeNotFound`](crate::error::Error::TypeNotFound) rather than a parse error.
#[must_use]
pub fn named(name: impl Into<String>) -> TypeExpr {
    TypeExpr::Named(name.into())
}

/// A C declaration recipe, parsed against the database's type library at apply time.
///
/// The explicit declaration root. Use it for anything with a declarator (`"Widget *"`,
/// `"int[8]"`), a keyword group (`"struct pt"`), or a builtin (`"unsigned int"`), and to force
/// the declaration parser over the by-name path for a bare identifier.
#[must_use]
pub fn decl(text: impl Into<String>) -> TypeExpr {
    TypeExpr::Decl(text.into())
}

/// Begins a function-prototype recipe with return type `ret`.
///
/// The root of the from-scratch prototype builder: chain [`arg`](FunctionExpr::arg) /
/// [`named_arg`](FunctionExpr::named_arg) / [`variadic`](FunctionExpr::variadic), then
/// [`build`](FunctionExpr::build) (or pass the builder straight to an [`Into<TypeExpr>`] sink like
/// [`set_type`](crate::LocationMut::set_type), which accepts it directly).
///
/// ```
/// use idakit::types::expr;
///
/// // int f(int, unsigned int, ...)
/// let f = expr::function(expr::int32())
///     .arg(expr::int32())
///     .named_arg("flags", expr::uint32())
///     .variadic()
///     .build();
/// assert!(f.is_function());
/// ```
#[must_use]
pub fn function(ret: impl Into<TypeExpr>) -> FunctionExpr {
    FunctionExpr {
        ret: Box::new(ret.into()),
        params: Vec::new(),
        varargs: false,
    }
}

/// A fluent builder for a [`TypeExpr::Function`], from [`function`].
///
/// Accumulates parameters left to right, then lowers to a [`TypeExpr`] via
/// [`build`](Self::build) or the [`From`] conversion. Every method takes `self` by value, so a
/// prototype reads as one chain.
#[derive(Clone, Debug)]
pub struct FunctionExpr {
    ret: Box<TypeExpr>,
    params: Vec<Param>,
    varargs: bool,
}

impl FunctionExpr {
    /// Appends an unnamed parameter of type `ty`.
    #[must_use]
    pub fn arg(mut self, ty: impl Into<TypeExpr>) -> Self {
        self.params.push(Param {
            name: None,
            ty: ty.into(),
        });
        self
    }

    /// Appends a parameter named `name` of type `ty`.
    #[must_use]
    pub fn named_arg(mut self, name: impl Into<String>, ty: impl Into<TypeExpr>) -> Self {
        self.params.push(Param {
            name: Some(name.into()),
            ty: ty.into(),
        });
        self
    }

    /// Marks the prototype variadic, so it ends in `...`.
    #[must_use]
    pub fn variadic(mut self) -> Self {
        self.varargs = true;
        self
    }

    /// Finishes the builder into a [`TypeExpr::Function`].
    #[must_use]
    pub fn build(self) -> TypeExpr {
        TypeExpr::Function {
            ret: self.ret,
            params: self.params,
            varargs: self.varargs,
        }
    }
}

impl From<FunctionExpr> for TypeExpr {
    #[inline]
    fn from(builder: FunctionExpr) -> Self {
        builder.build()
    }
}

/// The `void` leaf.
#[must_use]
pub fn void() -> TypeExpr {
    TypeExpr::Void
}

/// The boolean leaf.
#[must_use]
pub fn bool_() -> TypeExpr {
    TypeExpr::Bool
}

/// The signed 8-bit character leaf.
#[must_use]
pub fn char_() -> TypeExpr {
    TypeExpr::Int {
        bytes: 1,
        signed: true,
    }
}

/// The signed 8-bit integer leaf.
#[must_use]
pub fn int8() -> TypeExpr {
    TypeExpr::Int {
        bytes: 1,
        signed: true,
    }
}

/// The signed 16-bit integer leaf.
#[must_use]
pub fn int16() -> TypeExpr {
    TypeExpr::Int {
        bytes: 2,
        signed: true,
    }
}

/// The signed 32-bit integer leaf.
#[must_use]
pub fn int32() -> TypeExpr {
    TypeExpr::Int {
        bytes: 4,
        signed: true,
    }
}

/// The signed 64-bit integer leaf.
#[must_use]
pub fn int64() -> TypeExpr {
    TypeExpr::Int {
        bytes: 8,
        signed: true,
    }
}

/// The unsigned 8-bit integer leaf.
#[must_use]
pub fn uint8() -> TypeExpr {
    TypeExpr::Int {
        bytes: 1,
        signed: false,
    }
}

/// The unsigned 16-bit integer leaf.
#[must_use]
pub fn uint16() -> TypeExpr {
    TypeExpr::Int {
        bytes: 2,
        signed: false,
    }
}

/// The unsigned 32-bit integer leaf.
#[must_use]
pub fn uint32() -> TypeExpr {
    TypeExpr::Int {
        bytes: 4,
        signed: false,
    }
}

/// The unsigned 64-bit integer leaf.
#[must_use]
pub fn uint64() -> TypeExpr {
    TypeExpr::Int {
        bytes: 8,
        signed: false,
    }
}

/// The 32-bit float leaf.
#[must_use]
pub fn float32() -> TypeExpr {
    TypeExpr::Float { bytes: 4 }
}

/// The 64-bit float leaf.
#[must_use]
pub fn float64() -> TypeExpr {
    TypeExpr::Float { bytes: 8 }
}

impl TypeExpr {
    /// Wraps this recipe in a pointer: `T` becomes `T *`.
    ///
    /// Pointers stack rather than toggle, so `named("T").pointer().pointer()` is `T **`;
    /// [`deref`](Self::deref) peels one layer back.
    #[inline]
    #[must_use]
    pub fn pointer(self) -> TypeExpr {
        TypeExpr::Pointer(Box::new(self))
    }

    /// Wraps this recipe in an array of `len` elements: `T` becomes `T[len]`.
    #[inline]
    #[must_use]
    pub fn array(self, len: u64) -> TypeExpr {
        TypeExpr::Array {
            elem: Box::new(self),
            len,
        }
    }

    /// Qualifies this recipe `const`.
    ///
    /// Idempotent: an already-`const` recipe is returned unchanged. Order is preserved, so
    /// `x.const_().pointer()` (`const T *`) differs structurally from `x.pointer().const_()`
    /// (`T * const`).
    #[inline]
    #[must_use]
    pub fn const_(self) -> TypeExpr {
        if matches!(self, TypeExpr::Const(_)) {
            self
        } else {
            TypeExpr::Const(Box::new(self))
        }
    }

    /// Qualifies this recipe `volatile`.
    ///
    /// Idempotent: an already-`volatile` recipe is returned unchanged.
    #[inline]
    #[must_use]
    pub fn volatile_(self) -> TypeExpr {
        if matches!(self, TypeExpr::Volatile(_)) {
            self
        } else {
            TypeExpr::Volatile(Box::new(self))
        }
    }

    /// Peels one pointer or array layer: `T *` and `T[n]` become `T`.
    ///
    /// The inverse of [`pointer`](Self::pointer) and [`array`](Self::array), and a no-op on any
    /// other recipe (there is nothing to peel).
    #[inline]
    #[must_use]
    pub fn deref(self) -> TypeExpr {
        match self {
            TypeExpr::Pointer(inner) => *inner,
            TypeExpr::Array { elem, .. } => *elem,
            other => other,
        }
    }

    /// Whether this is a [`named`] reference.
    #[inline]
    #[must_use]
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named(_))
    }

    /// The referenced type name, or `None` if this is not a [`named`] reference.
    #[inline]
    #[must_use]
    pub fn as_named(&self) -> Option<&str> {
        match self {
            Self::Named(s) => Some(s),
            _ => None,
        }
    }

    /// Whether this is a [`decl`] recipe.
    #[inline]
    #[must_use]
    pub fn is_decl(&self) -> bool {
        matches!(self, Self::Decl(_))
    }

    /// The declaration text, or `None` if this is not a [`decl`] recipe.
    #[inline]
    #[must_use]
    pub fn as_decl(&self) -> Option<&str> {
        match self {
            Self::Decl(s) => Some(s),
            _ => None,
        }
    }

    /// Whether this is a [`pointer`](Self::pointer).
    #[inline]
    #[must_use]
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// The pointee, or `None` if this is not a pointer.
    #[inline]
    #[must_use]
    pub fn as_pointer(&self) -> Option<&TypeExpr> {
        match self {
            Self::Pointer(inner) => Some(inner),
            _ => None,
        }
    }

    /// Whether this is an [`array`](Self::array).
    #[inline]
    #[must_use]
    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array { .. })
    }

    /// The element type and length, or `None` if this is not an array.
    #[inline]
    #[must_use]
    pub fn as_array(&self) -> Option<(&TypeExpr, u64)> {
        match self {
            Self::Array { elem, len } => Some((elem, *len)),
            _ => None,
        }
    }

    /// Whether this recipe is `const`-qualified at its outermost layer.
    #[inline]
    #[must_use]
    pub fn is_const(&self) -> bool {
        matches!(self, Self::Const(_))
    }

    /// Whether this recipe is `volatile`-qualified at its outermost layer.
    #[inline]
    #[must_use]
    pub fn is_volatile(&self) -> bool {
        matches!(self, Self::Volatile(_))
    }

    /// Whether this is the `void` leaf.
    #[inline]
    #[must_use]
    pub fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Whether this is a scalar leaf: `void`, `bool`, an integer, or a float.
    #[inline]
    #[must_use]
    pub fn is_scalar(&self) -> bool {
        matches!(
            self,
            Self::Void | Self::Bool | Self::Int { .. } | Self::Float { .. }
        )
    }

    /// Whether this is a [`function`] prototype.
    #[inline]
    #[must_use]
    pub fn is_function(&self) -> bool {
        matches!(self, Self::Function { .. })
    }

    /// The return type, parameters, and varargs flag, or `None` if this is not a function.
    #[inline]
    #[must_use]
    pub fn as_function(&self) -> Option<(&TypeExpr, &[Param], bool)> {
        match self {
            Self::Function {
                ret,
                params,
                varargs,
            } => Some((ret, params, *varargs)),
            _ => None,
        }
    }

    /// Serializes this recipe into the facade's postfix bytecode.
    ///
    /// Children are emitted before their parent, so the facade rebuilds the type with one stack: a
    /// leaf pushes, a transform pops one and pushes its wrap. The wire behind
    /// [`set_type`](crate::LocationMut::set_type) and `idakit_apply_type_recipe`.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Void => buf.push(sys::IDAKIT_RECIPE_VOID),
            Self::Bool => buf.push(sys::IDAKIT_RECIPE_BOOL),
            Self::Int { bytes, signed } => {
                buf.push(sys::IDAKIT_RECIPE_INT);
                buf.push(*bytes);
                buf.push(u8::from(*signed));
            }
            Self::Float { bytes } => {
                buf.push(sys::IDAKIT_RECIPE_FLOAT);
                buf.push(*bytes);
            }
            Self::Named(name) => encode_str(buf, sys::IDAKIT_RECIPE_NAMED, name),
            Self::Decl(text) => encode_str(buf, sys::IDAKIT_RECIPE_DECL, text),
            Self::Pointer(inner) => {
                inner.encode(buf);
                buf.push(sys::IDAKIT_RECIPE_PTR);
            }
            Self::Array { elem, len } => {
                elem.encode(buf);
                buf.push(sys::IDAKIT_RECIPE_ARRAY);
                buf.extend_from_slice(&len.to_le_bytes());
            }
            Self::Const(inner) => {
                inner.encode(buf);
                buf.push(sys::IDAKIT_RECIPE_CONST);
            }
            Self::Volatile(inner) => {
                inner.encode(buf);
                buf.push(sys::IDAKIT_RECIPE_VOLATILE);
            }
            Self::Function {
                ret,
                params,
                varargs,
            } => {
                // Return pushed first, then each parameter type, so the facade pops the params off
                // the top and finds the return just below them.
                ret.encode(buf);
                for p in params {
                    p.ty.encode(buf);
                }
                buf.push(sys::IDAKIT_RECIPE_FUNCTION);
                let count = u32::try_from(params.len()).unwrap_or(u32::MAX);
                buf.extend_from_slice(&count.to_le_bytes());
                buf.push(u8::from(*varargs));
                buf.extend_from_slice(&0u16.to_le_bytes()); // calling convention, unset until surgery
                for p in params.iter().take(count as usize) {
                    encode_len_prefixed(buf, p.name.as_deref().unwrap_or(""));
                }
            }
        }
    }
}

/// Emits a little-endian `u32` byte length then that many bytes, the length prefix a name or
/// declaration string carries in the recipe wire format.
fn encode_len_prefixed(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&bytes[..len as usize]);
}

/// Emits a length-prefixed string opcode: the op byte, then the length-prefixed bytes. A name or
/// declaration long enough to overflow `u32` is not a real type.
fn encode_str(buf: &mut Vec<u8>, op: u8, s: &str) {
    buf.push(op);
    encode_len_prefixed(buf, s);
}

/// Classifies a `&str` by shape, routing a name that could exist to [`named`] and everything else
/// (a keyword or a declarator) to [`decl`].
impl From<&str> for TypeExpr {
    fn from(s: &str) -> Self {
        if is_bare_type_name(s) {
            Self::Named(s.to_owned())
        } else {
            Self::Decl(s.to_owned())
        }
    }
}

/// Classifies an owned `String` like [`From<&str>`](TypeExpr::from), reusing its allocation.
impl From<String> for TypeExpr {
    fn from(s: String) -> Self {
        if is_bare_type_name(&s) {
            Self::Named(s)
        } else {
            Self::Decl(s)
        }
    }
}

/// A readable, C-ish rendering, primarily for diagnostics.
///
/// It is not guaranteed valid C for every nesting: a pointer-to-array or a qualified pointer needs
/// declarator parentheses this does not add. The authoritative form is the `tinfo_t` the lowering
/// facade builds from the structure, never this string.
impl fmt::Display for TypeExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => f.write_str("void"),
            Self::Bool => f.write_str("bool"),
            Self::Int { bytes, signed } => {
                write!(
                    f,
                    "{}int{}",
                    if *signed { "" } else { "u" },
                    u32::from(*bytes) * 8
                )
            }
            Self::Float { bytes } => write!(f, "float{}", u32::from(*bytes) * 8),
            Self::Named(s) | Self::Decl(s) => f.write_str(s),
            Self::Pointer(inner) => write!(f, "{inner} *"),
            Self::Array { elem, len } => write!(f, "{elem}[{len}]"),
            Self::Const(inner) => write!(f, "const {inner}"),
            Self::Volatile(inner) => write!(f, "volatile {inner}"),
            Self::Function {
                ret,
                params,
                varargs,
            } => {
                write!(f, "{ret} (")?;
                for (i, p) in params.iter().enumerate() {
                    if i != 0 {
                        f.write_str(", ")?;
                    }
                    match &p.name {
                        Some(name) => write!(f, "{} {name}", p.ty)?,
                        None => write!(f, "{}", p.ty)?,
                    }
                }
                if *varargs {
                    f.write_str(if params.is_empty() { "..." } else { ", ..." })?;
                }
                f.write_str(")")
            }
        }
    }
}

/// Whether `s` could name an existing type: a single, optionally `::`-qualified, C identifier that
/// is not a builtin type keyword.
///
/// This is the test that routes a `&str` to the by-name apply path: `"Widget"` and `"ns::Inner"`
/// name an existing type, while `"Widget *"` (declarator), `"struct pt"` (keyword group), `"int"`
/// (a builtin keyword, which no til stores as a named type), and `""` are declarations. It is
/// deliberately strict: any surrounding or interior whitespace disqualifies the fast path and falls
/// through to the declaration parser, which still applies the type, just without the clean
/// not-found error.
fn is_bare_type_name(s: &str) -> bool {
    !s.is_empty() && !is_builtin_type_keyword(s) && s.split("::").all(is_c_identifier)
}

/// Whether `s` is a single C builtin type keyword (`int`, `char`, `__int64`, and so on).
///
/// These are lexical identifiers but never named types, so they route to the declaration parser
/// instead of the by-name path, where `set_type("int")` would otherwise miss and report a spurious
/// not-found. Multi-word builtins (`unsigned int`) already carry whitespace and take the
/// declaration path anyway.
fn is_builtin_type_keyword(s: &str) -> bool {
    matches!(
        s,
        "void"
            | "bool"
            | "_Bool"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "signed"
            | "unsigned"
            | "wchar_t"
            | "__int8"
            | "__int16"
            | "__int32"
            | "__int64"
            | "__int128"
    )
}

/// Whether `s` is a non-empty C identifier: a leading letter or `_`, then letters/digits/`_`.
fn is_c_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    const fn assert_send<T: Send>() {}
    // A recipe owns its strings, so it travels off the kernel thread to be built anywhere.
    const _: () = assert_send::<TypeExpr>();

    #[rstest]
    // bare names -> by-name path
    #[case("Widget", true)]
    #[case("_hidden", true)]
    #[case("my_struct_t", true)]
    #[case("Foo123", true)]
    #[case("ns::Inner", true)]
    #[case("a::b::c", true)]
    #[case("int_t", true)]
    // merely starts like a keyword; still a full identifier
    // builtin keywords -> declaration path (no til stores them as named types)
    #[case("int", false)]
    #[case("char", false)]
    #[case("void", false)]
    #[case("unsigned", false)]
    #[case("__int64", false)]
    #[case("bool", false)]
    // declarators / groups / junk -> declaration path
    #[case("Widget *", false)]
    #[case("int[8]", false)]
    #[case("struct pt", false)]
    #[case("unsigned int", false)]
    #[case("123Foo", false)]
    #[case("", false)]
    #[case("Widget ", false)]
    #[case(" Widget", false)]
    #[case("::Foo", false)]
    #[case("a::", false)]
    #[case("a:::b", false)]
    fn classifies_bare_names_against_declarations(#[case] input: &str, #[case] bare: bool) {
        assert!(is_bare_type_name(input) == bare);
    }

    #[rstest]
    #[case("Widget", TypeExpr::Named("Widget".into()))]
    #[case("ns::Inner", TypeExpr::Named("ns::Inner".into()))]
    #[case("Widget *", TypeExpr::Decl("Widget *".into()))]
    #[case("struct pt", TypeExpr::Decl("struct pt".into()))]
    #[case("int", TypeExpr::Decl("int".into()))]
    fn from_str_routes_by_classification(#[case] input: &str, #[case] expected: TypeExpr) {
        assert!(TypeExpr::from(input) == expected);
    }

    #[test]
    fn from_owned_string_matches_str_classification() {
        assert!(TypeExpr::from("Widget".to_owned()) == TypeExpr::from("Widget"));
        assert!(TypeExpr::from("Widget *".to_owned()) == TypeExpr::from("Widget *"));
    }

    #[test]
    fn explicit_roots_bypass_classification() {
        // `decl` forces the declaration path even for a bare identifier; `named` forces by-name
        // even for a spelling the parser would accept.
        assert!(decl("Widget") == TypeExpr::Decl("Widget".into()));
        assert!(named("Widget") == TypeExpr::Named("Widget".into()));
    }

    #[test]
    fn scalar_roots_construct_leaves() {
        assert!(void() == TypeExpr::Void);
        assert!(bool_() == TypeExpr::Bool);
        assert!(
            int32()
                == TypeExpr::Int {
                    bytes: 4,
                    signed: true
                }
        );
        assert!(
            uint8()
                == TypeExpr::Int {
                    bytes: 1,
                    signed: false
                }
        );
        assert!(float64() == TypeExpr::Float { bytes: 8 });
        assert!(int32().is_scalar() && void().is_void());
        assert!(!named("X").is_scalar());
    }

    #[test]
    fn pointer_and_array_stack_and_deref_peels() {
        // pointers stack (not a toggle)
        let pp = named("Foo").pointer().pointer();
        assert!(pp.is_pointer());
        assert!(pp.as_pointer() == Some(&named("Foo").pointer()));
        // deref peels one layer, the inverse of pointer
        assert!(pp.deref() == named("Foo").pointer());
        // array carries its length; deref peels it
        let a = int32().array(8);
        assert!(a.as_array() == Some((&int32(), 8)));
        assert!(a.deref() == int32());
        // deref on a leaf is a no-op
        assert!(named("Foo").deref() == named("Foo"));
    }

    #[test]
    fn qualifiers_are_idempotent_and_ordered() {
        assert!(named("Foo").const_().const_() == named("Foo").const_());
        assert!(int32().volatile_().volatile_() == int32().volatile_());
        assert!(named("Foo").const_().is_const());
        // order is preserved structurally: const-of-pointer differs from pointer-of-const
        assert!(named("Foo").const_().pointer() != named("Foo").pointer().const_());
    }

    #[test]
    fn projections_match_shape() {
        let n = named("Widget");
        assert!(n.is_named() && !n.is_decl());
        assert!(n.as_named() == Some("Widget"));
        assert!(n.as_decl().is_none());
        assert!(n.as_pointer().is_none());

        let d = decl("Widget *");
        assert!(d.is_decl() && d.as_decl() == Some("Widget *"));

        let p = named("Foo").pointer();
        assert!(p.as_pointer() == Some(&named("Foo")));
        assert!(p.as_array().is_none());
    }

    #[test]
    fn recipe_opcodes_pin_the_facade_mirror() {
        // The opcode values are a wire contract with the facade; pin the Rust mirror so a drift
        // trips here (the facade side is pinned by the write-path round-trip test).
        assert!(sys::IDAKIT_RECIPE_VOID == 0);
        assert!(sys::IDAKIT_RECIPE_BOOL == 1);
        assert!(sys::IDAKIT_RECIPE_INT == 2);
        assert!(sys::IDAKIT_RECIPE_FLOAT == 3);
        assert!(sys::IDAKIT_RECIPE_NAMED == 4);
        assert!(sys::IDAKIT_RECIPE_DECL == 5);
        assert!(sys::IDAKIT_RECIPE_PTR == 6);
        assert!(sys::IDAKIT_RECIPE_ARRAY == 7);
        assert!(sys::IDAKIT_RECIPE_CONST == 8);
        assert!(sys::IDAKIT_RECIPE_VOLATILE == 9);
    }

    // A leaf emits its op then inline operands; a composite is postfix (inner before its wrap op); a
    // name/decl carries a little-endian u32 length then its bytes; an array's u64 length follows the
    // op. The final pair shows qualifier order survives: const-of-pointer and pointer-of-const
    // differ only by their trailing op sequence.
    #[rstest]
    #[case(void(), vec![0])]
    #[case(bool_(), vec![1])]
    #[case(int32(), vec![2, 4, 1])]
    #[case(uint8(), vec![2, 1, 0])]
    #[case(float64(), vec![3, 8])]
    #[case(named("Foo"), vec![4, 3, 0, 0, 0, b'F', b'o', b'o'])]
    #[case(decl("T"), vec![5, 1, 0, 0, 0, b'T'])]
    #[case(named("Foo").pointer(), vec![4, 3, 0, 0, 0, b'F', b'o', b'o', 6])]
    #[case(int32().array(8), vec![2, 4, 1, 7, 8, 0, 0, 0, 0, 0, 0, 0])]
    #[case(named("Foo").const_(), vec![4, 3, 0, 0, 0, b'F', b'o', b'o', 8])]
    #[case(named("Foo").volatile_(), vec![4, 3, 0, 0, 0, b'F', b'o', b'o', 9])]
    #[case(named("Foo").const_().pointer(), vec![4, 3, 0, 0, 0, b'F', b'o', b'o', 8, 6])]
    #[case(named("Foo").pointer().const_(), vec![4, 3, 0, 0, 0, b'F', b'o', b'o', 6, 8])]
    // A function pushes its return then each param, then FUNCTION (10) with a u32 count, a u8
    // varargs flag, a u16 cc (0 here), then one u32-length-prefixed name per param.
    #[case(function(void()).build(), vec![0, 10, 0, 0, 0, 0, 0, 0, 0])]
    #[case(function(int32()).arg(int32()).build(),
        vec![2, 4, 1, 2, 4, 1, 10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])]
    #[case(function(int32()).named_arg("a", uint8()).variadic().build(),
        vec![2, 4, 1, 2, 1, 0, 10, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, b'a'])]
    fn serializes_to_postfix_bytecode(#[case] recipe: TypeExpr, #[case] expected: Vec<u8>) {
        assert!(recipe.serialize() == expected);
    }

    // Best-effort C rendering: scalar leaves name their width, a pointer stacks a ` *`, an array its
    // `[len]`, a qualifier its keyword. Not guaranteed valid C for every nesting.
    #[rstest]
    #[case(void(), "void")]
    #[case(bool_(), "bool")]
    #[case(int32(), "int32")]
    #[case(int64(), "int64")]
    #[case(uint8(), "uint8")]
    #[case(uint32(), "uint32")]
    #[case(float64(), "float64")]
    #[case(named("Foo"), "Foo")]
    #[case(decl("Widget *"), "Widget *")]
    #[case(named("Foo").pointer(), "Foo *")]
    #[case(named("Foo").pointer().pointer(), "Foo * *")]
    #[case(int32().array(8), "int32[8]")]
    #[case(named("Foo").const_(), "const Foo")]
    #[case(named("Foo").volatile_(), "volatile Foo")]
    #[case(function(void()).build(), "void ()")]
    #[case(function(int32()).variadic().build(), "int32 (...)")]
    #[case(function(named("Foo").pointer()).arg(int32()).build(), "Foo * (int32)")]
    #[case(
        function(int32()).arg(int32()).named_arg("flags", uint32()).variadic().build(),
        "int32 (int32, uint32 flags, ...)"
    )]
    fn display_renders_readable_c(#[case] recipe: TypeExpr, #[case] expected: &str) {
        assert!(format!("{recipe}") == expected);
    }

    #[test]
    fn function_builder_accumulates_params_and_flags() {
        let f = function(int32())
            .arg(int32())
            .named_arg("flags", uint32())
            .variadic()
            .build();
        let (ret, params, varargs) = f.as_function().expect("a function");
        assert!(ret == &int32());
        assert!(varargs);
        assert!(params.len() == 2);
        assert!(
            params[0]
                == Param {
                    name: None,
                    ty: int32()
                }
        );
        assert!(
            params[1]
                == Param {
                    name: Some("flags".into()),
                    ty: uint32(),
                }
        );
        // A void-returning, paramless prototype is the degenerate case.
        let g = function(void()).build();
        assert!(g.as_function() == Some((&void(), &[][..], false)));
        assert!(g.is_function() && !int32().is_function());
    }

    #[test]
    fn function_builder_into_typeexpr_needs_no_build() {
        // The builder is `Into<TypeExpr>`, so an `impl Into<TypeExpr>` sink takes it directly.
        let via_into: TypeExpr = function(void()).arg(int32()).into();
        assert!(via_into == function(void()).arg(int32()).build());
    }
}
