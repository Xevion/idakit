//! The spec data vocabulary: every struct/enum a domain or the visitor bridge is authored from,
//! plus pure constructors/accessors that need no token/string emission. The emitters that turn
//! this data into `TokenStream`/`String` live in [`super::emit`].

/// The C++ namespace every generated bridge function lives in.
pub const NAMESPACE: &str = "gen";

/// One slice of the facade: its own C++ header and body TU, the SDK types it binds, the shared
/// structs it returns, and its functions. All domains feed one unified bridge module.
pub struct Domain {
    /// Short identifier, e.g. `"seg"`. Names the generated `gen_<name>.h` / `gen_<name>_bodies.cc`.
    pub name: &'static str,
    /// SDK headers the body TU must include (e.g. `"<segment.hpp>"`), plus `<stdexcept>` when a
    /// body throws. `<pro.h>`/`<ida.hpp>` are always included.
    pub sdk_includes: &'static [&'static str],
    /// SDK types this domain binds as `cxx` `ExternType`s (POD by value, or opaque behind a handle).
    pub externs: &'static [ExternTy],
    /// `cxx` shared structs this domain declares and returns by value.
    pub structs: &'static [SharedStruct],
    /// Integer sentinels this domain declares, emitted as both a bare Rust `pub const` and a C++
    /// `constexpr` in the domain header.
    pub consts: &'static [ConstDef],
    /// The domain's functions.
    pub fns: &'static [FnSpec],
    /// The hand-written TUs defining this domain's [`BodyKind::Custom`] bodies. A domain may split
    /// its bodies across several TUs (empty when it has none).
    pub custom_tus: &'static [&'static str],
}

impl Domain {
    pub(crate) fn header(&self) -> String {
        format!("gen_{}.h", self.name)
    }
    pub(crate) fn bodies_file(&self) -> String {
        format!("gen_{}_bodies.cc", self.name)
    }
    pub(crate) fn has_templated_body(&self) -> bool {
        self.fns.iter().any(|f| f.body_source().is_some())
    }
}

/// An SDK type bound as a `cxx` [`ExternType`](cxx::ExternType), so `cxx` glue can pass it without
/// redeclaring it: the impl names the real C++ symbol by `type_id!`.
pub struct ExternTy {
    /// The Rust-side name (e.g. `"RangeT"`).
    pub rust_name: &'static str,
    /// The real C++ symbol (e.g. `"range_t"`), emitted as `::range_t` and used in `type_id!`.
    pub cxx_name: &'static str,
    /// Trivial (crosses by value) or Opaque (only behind a reference or `UniquePtr`).
    pub kind: ExternKind,
    /// One-line summary for the generated Rust type's doc comment.
    pub doc: &'static str,
    /// The `// SAFETY:` justification for the `unsafe impl ExternType`.
    pub safety: &'static str,
}

/// Whether an [`ExternTy`] is trivially relocatable (crosses by value) or opaque.
pub enum ExternKind {
    /// `#[repr(C)]` mirror crossing by value; the fields mirror the SDK POD's layout.
    Trivial(&'static [Field]),
    /// Zero-sized opaque body; only ever behind `&T` / `UniquePtr<T>`.
    Opaque,
}

/// A `cxx` shared struct: one POD declared once, generated into both languages, crossed by value.
pub struct SharedStruct {
    /// The struct's name (e.g. `"ChunkInfo"`).
    pub name: &'static str,
    /// One-line summary for its doc comment.
    pub doc: &'static str,
    /// Its fields, in declaration order.
    pub fields: &'static [Field],
}

/// One generated integer sentinel, emitted to both faces from one spec: a bare Rust `pub const`
/// (crate-root re-exported) and a C++ `constexpr` in the `gen` namespace of the domain
/// header.
pub struct ConstDef {
    /// Bare name, no `IDAKIT_` prefix, e.g. `"FLOW_CALL"`.
    pub name: &'static str,
    /// The const's integer width and signedness.
    pub ty: ConstTy,
    /// The value, wide enough to hold `u64::MAX` or a negative `i32`.
    pub value: i128,
    /// One-line summary for the generated Rust `pub const`'s doc comment.
    pub doc: &'static str,
}

/// The integer width/signedness a [`ConstDef`] may declare.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum ConstTy {
    U8,
    U16,
    U32,
    U64,
    Usize,
    I32,
    I64,
}

/// One field of a [`SharedStruct`] or a `Trivial` [`ExternTy`] mirror.
pub struct Field {
    /// Field name.
    pub name: &'static str,
    /// Field type.
    pub ty: FieldTy,
    /// Terse noun-phrase doc fragment (renders in a generated table).
    pub doc: &'static str,
}

/// The field types a shared struct or POD mirror may carry.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
pub enum FieldTy {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    Usize,
    Bool,
    /// An owned string (`String` in Rust, `rust::String` in C++).
    Str,
    /// A by-value `Trivial` `ExternType`, named by its Rust name (e.g. `"RangeT"`).
    Extern(&'static str),
    /// A nested shared struct by value, by name (e.g. `"RegisterData"`); `cxx` lays it inline.
    Struct(&'static str),
    /// An owned `Vec` of a shared struct, by name (e.g. `"OperandData"`).
    VecStruct(&'static str),
}

/// One facade function: its shared name, optional `self:` receiver, arguments, return shape, and
/// how its C++ body is produced. `name` is used verbatim for the Rust bridge fn and the C++ symbol.
#[derive(Clone)]
pub struct FnSpec {
    pub name: &'static str,
    /// `Some(extern rust_name)` for a `self: &T` member call; `None` for a free function.
    pub receiver: Option<&'static str>,
    pub args: &'static [Arg],
    pub ret: RetKind,
    pub body: BodyKind,
    pub doc: &'static str,
    /// The SDK member this binding mirrors (e.g. `"netnode::altval"`), for a `#[doc(alias)]` a
    /// reader of the IDA SDK can search by. `None` when the binding needs no alias (its own name
    /// already reads as the SDK symbol, or it has none).
    pub sdk_alias: Option<&'static str>,
}

impl FnSpec {
    /// One free function with a rendered C++ body, built from owned strings and leaked to `'static`
    /// for the engine. The imperative constructor a matrix-built domain uses per cell of its own
    /// family x keying x op grid (see `domains::netnode`, the one domain built this way).
    pub(crate) fn rendered(
        name: String,
        args: Vec<Arg>,
        ret: RetKind,
        doc: String,
        body: String,
    ) -> Self {
        Self {
            name: name.leak(),
            receiver: None,
            args: args.leak(),
            ret,
            body: BodyKind::Rendered(body.leak()),
            doc: doc.leak(),
            sdk_alias: None,
        }
    }
}

/// A bridge-function argument.
pub struct Arg {
    pub name: &'static str,
    pub ty: ArgTy,
}

impl Arg {
    /// One argument from a `(name, ty)` pair. The runtime twin of the [`args!`] macro, for
    /// imperatively built specs (dynamic names via `format!`) a literal-ident macro can't reach.
    pub(crate) const fn new(name: &'static str, ty: ArgTy) -> Self {
        Self { name, ty }
    }
}

/// The argument shapes the spec can express. Each is a (Rust type, C++ type) pair.
// The allow covers taxonomy slots no current spec constructs.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum ArgTy {
    I32,
    U32,
    U64,
    Usize,
    Bool,
    /// A borrowed string (`&str` / `rust::Str`).
    Str,
    /// An owned lenient-decoded string (`String` / `rust::String`), built facade-side (any
    /// undecodable unit is U+FFFD). Used where a name/literal may not be pristine UTF-8, so a
    /// zero-copy `&str` borrow would be unsound.
    String,
    /// A borrowed byte slice (`&[u8]` / `rust::Slice<const uint8_t>`).
    Bytes,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    /// A borrowed `ExternType` (`&T` / `const ::cxx_name&`), by Rust name.
    ExternRef(&'static str),
    /// A borrowed `f64` (`f64` / `double`).
    F64,
    /// A borrowed `i64` (`i64` / `int64_t`).
    I64,
    /// A borrowed `u32` slice (`&[u32]` / `rust::Slice<const uint32_t>`).
    SliceU32,
    /// A borrowed `u64` slice (`&[u64]` / `rust::Slice<const uint64_t>`).
    SliceU64,
    /// A borrowed slice of a shared struct, by name (`&[Name]` / `rust::Slice<const Name>`).
    SliceStruct(&'static str),
    /// A borrowed mutable reference to an `extern "Rust"` opaque visitor, by name (`&mut Name` /
    /// `Name &`).
    VisitorMut(&'static str),
}

/// The value shape a return carries, independent of whether the call may throw (see [`RetKind`]).
#[derive(Clone)]
pub enum RetShape {
    Unit,
    Bool,
    I32,
    U8,
    U16,
    U32,
    U64,
    Usize,
    String,
    /// A by-value `Trivial` `ExternType`, by Rust name.
    Extern(&'static str),
    /// A shared struct by value, by name.
    Shared(&'static str),
    /// `UniquePtr<T>` over an opaque `ExternType`, by Rust name.
    UniquePtr(&'static str),
    /// An owned `Vec` of a `Trivial` `ExternType` or a shared struct, by name.
    Vec(&'static str),
    /// An owned `Vec` of a scalar (`u32`).
    VecU32,
    /// An owned `Vec<u8>` (a raw byte-range snapshot, or an alignment-id list).
    VecU8,
}

/// A function's return: a [`RetShape`] plus whether the call may throw a C++ exception, surfaced
/// as a Rust `Err`. `cxx` maps a throwing fn's C++ return type straight to the `Ok` payload's
/// type, so a shape's C++ spelling serves both variants alike; only the Rust side diverges,
/// wrapping `Fallible`'s shape in a `Result`.
#[derive(Clone)]
pub enum RetKind {
    /// An infallible call; the Rust return is the shape itself.
    Value(RetShape),
    /// A call that may throw; the Rust return is `Result<Shape>`.
    Fallible(RetShape),
}

impl RetKind {
    /// The value shape, independent of fallibility.
    pub(crate) fn shape(&self) -> &RetShape {
        match self {
            Self::Value(s) | Self::Fallible(s) => s,
        }
    }

    /// Whether the Rust return conveys a value worth a `#[must_use]`: only an infallible,
    /// non-`()` value. A `Fallible` return is always `Result<_>`, already `#[must_use]` itself.
    pub(crate) fn is_must_use(&self) -> bool {
        matches!(self, Self::Value(shape) if !matches!(shape, RetShape::Unit))
    }
}

/// How a function's C++ body is produced. The templated variants exist for segment's trivial
/// scalar/string shapes; the netnode matrix supplies its own [`Rendered`](BodyKind::Rendered)
/// bodies; every other body is [`Custom`](BodyKind::Custom) and hand-written in one of the
/// domain's `custom_tus`.
#[derive(Clone)]
pub enum BodyKind {
    /// Nullary scalar passthrough: `return (ret)CALL;`.
    ScalarCall { call: &'static str },
    /// A fully-rendered body (the lines between the braces), supplied by a matrix emitter that owns
    /// both the function's signature and its body. Emitted into the domain's `gen_<name>_bodies.cc`.
    Rendered(&'static str),
    /// `getnseg(n)`, then read scalar `s->ACCESSOR`, returning `SENTINEL` when null.
    SegScalar {
        accessor: &'static str,
        null_sentinel: &'static str,
    },
    /// `getnseg(n)`, then fill a `qstring` via `GETTER(&out, s)`; throw when null, and (when
    /// `require_positive`) throw when the getter returns `<= 0`.
    SegString {
        getter: &'static str,
        require_positive: bool,
    },
    /// Declaration only; the body is hand-written in one of the domain's `custom_tus`.
    Custom,
}

/// One `extern "Rust"` opaque-visitor sub-bridge: a sink trait plus the opaque visitor that
/// forwards every call into it. [`visitors::VISITOR_BRIDGE`] pairs two of these (ctree,
/// tinfo type walk) into one shared bridge module.
pub struct VisitorSink {
    /// The sink trait's name, e.g. `"CtreeSink"`.
    pub sink_name: &'static str,
    /// The sink trait's doc comment.
    pub sink_doc: &'static str,
    /// The opaque visitor's name, e.g. `"CtreeVisitor"`.
    pub visitor_name: &'static str,
    /// The opaque visitor's doc comment.
    pub visitor_doc: &'static str,
    /// The sink's methods, in declaration order.
    pub methods: &'static [VisitorMethod],
}

/// One sink-trait method, emitted three times from this one spec: the trait declaration, the
/// opaque visitor's forwarding `impl`, and the bridge's `extern "Rust"` fn decl.
pub struct VisitorMethod {
    pub name: &'static str,
    pub doc: &'static str,
    pub args: &'static [Arg],
    pub ret: RetKind,
}

/// One `extern "C++"` driver fn in the visitor bridge's shared block: a hand-written entry point
/// (`facade/ctree_bridge.cpp` / `facade/typewalk_bridge.cpp`) that drives a visitor over a ctree or tinfo.
pub struct VisitorDriverFn {
    pub name: &'static str,
    pub doc: &'static str,
    pub args: &'static [Arg],
    pub ret: RetKind,
    /// Whether the caller must uphold an invariant `cxx` can't check (surfaces as `unsafe fn` plus
    /// a `#[allow(clippy::missing_safety_doc)]`, since the obligation is documented on the
    /// hand-written shim, not regenerated per call).
    pub unsafe_: bool,
}

/// The whole visitor bridge: its shared structs, its sink/visitor pairs, and the `extern "C++"`
/// driver block that shares the `CFunc` extern type with the `gen` bridge's `hexrays`
/// domain.
pub struct VisitorBridge {
    pub structs: &'static [SharedStruct],
    pub sinks: &'static [VisitorSink],
    pub drivers: &'static [VisitorDriverFn],
}
