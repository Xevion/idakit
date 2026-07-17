//! The `macro_rules!` authoring DSL for [`super::domains`]/[`super::visitors`]: terse row syntax
//! that expands into the [`super::model`] spec types.

/// `&[Arg]` from `name: Variant` pairs; a `("Name")` suffix supplies a tuple variant's payload
/// (`args!(id: U32, members: SliceStruct("MemberInfo"))`). The one authoring primitive for a
/// bridge's argument list, shared by [`FnSpec`], [`VisitorMethod`], and [`VisitorDriverFn`].
///
/// Expands with bare `Arg`/`ArgTy` names, so each caller keeps them in scope (every spec module
/// already `use super::{Arg, ArgTy, ...}`).
macro_rules! args {
    ( $( $name:ident : $variant:ident $(($arg:literal))? ),* $(,)? ) => {
        &[ $( Arg { name: stringify!($name), ty: ArgTy::$variant $(($arg))? } ),* ]
    };
}

/// `&[Field]` from `name: Variant = "doc";` rows; a `("Name")` suffix supplies a tuple variant's
/// payload. The [`SharedStruct`] / POD-mirror twin of [`args!`].
macro_rules! fields {
    ( $( $name:ident : $variant:ident $(($arg:literal))? = $doc:literal );* $(;)? ) => {
        &[ $( Field { name: stringify!($name), ty: FieldTy::$variant $(($arg))?, doc: $doc } ),* ]
    };
}

/// One [`RetKind`] from a bare [`RetShape`] variant name (`ret!(U32)`) or its `Result` twin
/// (`ret!(ResultU32)`), the return-position primitive [`fns!`]/[`methods!`] compose. Keeps the
/// flat `-> U32` / `-> ResultU32` authoring spelling while building the shape-plus-fallibility
/// pair underneath.
macro_rules! ret {
    (Unit) => {
        RetKind::Value(RetShape::Unit)
    };
    (Bool) => {
        RetKind::Value(RetShape::Bool)
    };
    (I32) => {
        RetKind::Value(RetShape::I32)
    };
    (U32) => {
        RetKind::Value(RetShape::U32)
    };
    (U64) => {
        RetKind::Value(RetShape::U64)
    };
    (Usize) => {
        RetKind::Value(RetShape::Usize)
    };
    (String) => {
        RetKind::Value(RetShape::String)
    };
    (Extern($n:literal)) => {
        RetKind::Value(RetShape::Extern($n))
    };
    (Shared($n:literal)) => {
        RetKind::Value(RetShape::Shared($n))
    };
    (UniquePtr($n:literal)) => {
        RetKind::Value(RetShape::UniquePtr($n))
    };
    (Vec($n:literal)) => {
        RetKind::Value(RetShape::Vec($n))
    };
    (VecU32) => {
        RetKind::Value(RetShape::VecU32)
    };
    (VecI32) => {
        RetKind::Value(RetShape::VecI32)
    };
    (VecU8) => {
        RetKind::Value(RetShape::VecU8)
    };
    (ResultUsize) => {
        RetKind::Fallible(RetShape::Usize)
    };
    (ResultU8) => {
        RetKind::Fallible(RetShape::U8)
    };
    (ResultU16) => {
        RetKind::Fallible(RetShape::U16)
    };
    (ResultU32) => {
        RetKind::Fallible(RetShape::U32)
    };
    (ResultU64) => {
        RetKind::Fallible(RetShape::U64)
    };
    (ResultString) => {
        RetKind::Fallible(RetShape::String)
    };
    (ResultExtern($n:literal)) => {
        RetKind::Fallible(RetShape::Extern($n))
    };
    (ResultShared($n:literal)) => {
        RetKind::Fallible(RetShape::Shared($n))
    };
    (ResultUniquePtr($n:literal)) => {
        RetKind::Fallible(RetShape::UniquePtr($n))
    };
    (ResultVec($n:literal)) => {
        RetKind::Fallible(RetShape::Vec($n))
    };
    (ResultVecU32) => {
        RetKind::Fallible(RetShape::VecU32)
    };
    (ResultVecU8) => {
        RetKind::Fallible(RetShape::VecU8)
    };
}

/// `&[VisitorMethod]` from `"doc" name(args) [-> Ret];` rows, composing [`args!`] for each row's
/// argument list. The return defaults to `U32`; write `-> Unit` (or any [`ret!`] spelling, with a
/// `("Name")` suffix for a tuple payload) to override.
macro_rules! methods {
    ( $(
        $doc:literal $name:ident ( $( $an:ident : $av:ident $(($aarg:literal))? ),* $(,)? )
        $( -> $rk:ident $(($rarg:literal))? )? ;
    )* ) => {
        &[ $( VisitorMethod {
            name: stringify!($name),
            doc: $doc,
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: methods!(@ret $( $rk $(($rarg))? )?),
        } ),* ]
    };
    (@ret) => { RetKind::Value(RetShape::U32) };
    (@ret $rk:ident) => { ret!($rk) };
    (@ret $rk:ident($rarg:literal)) => { ret!($rk($rarg)) };
}

/// `&[FnSpec]` from `"doc" name(args) [-> Ret] [= body];` rows, the domain twin of [`methods!`].
///
/// A row is `"doc" name(args) -> Ret;`, composing [`args!`] for the argument list. Omitting `->`
/// defaults the return to `Unit` (as in Rust); a leading `self: Type` in the args names a `self: &T`
/// receiver (`FnSpec::receiver`). The body suffix selects [`FnSpec::body`]'s kind:
///
/// | suffix                 | [`BodyKind`] variant | behavior                                      |
/// |------------------------|-----------------------|-----------------------------------------------|
/// | *(none)*               | `Custom`              | hand-written in one of the domain's `custom_tus` |
/// | `= scalar(call)`       | `ScalarCall`          | `return (ret)CALL;`                            |
/// | `= seg_scalar(a, s)`   | `SegScalar`           | `getnseg(n)`, read scalar field, `s` when null |
/// | `= seg_string(g)`      | `SegString`           | `getnseg(n)`, fill a `qstring` via `g`         |
/// | `= seg_string_pos(g)`  | `SegString`           | as above, and throw when `g` returns `<= 0`    |
macro_rules! fns {
    // All rows consumed: emit the accumulated slice.
    (@munch [ $($acc:expr,)* ]) => { &[ $($acc),* ] };

    // A `self: Type` receiver row (member call); tried first, so a plain row never sees `self`.
    (@munch [ $($acc:expr,)* ]
        $doc:literal
        $name:ident ( self : $recv:ident $(, $an:ident : $av:ident $(($aarg:literal))? )* $(,)? )
        $( -> $rk:ident $(($rarg:literal))? )?
        $( = $bk:ident ( $($bargs:literal),* ) )? ;
        $($rest:tt)*
    ) => {
        fns!(@munch [ $($acc,)* FnSpec {
            name: stringify!($name),
            receiver: Some(stringify!($recv)),
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: fns!(@ret $( $rk $(($rarg))? )?),
            body: fns!(@body $( $bk ( $($bargs),* ) )?),
            doc: $doc,
            sdk_alias: None,
        }, ] $($rest)*)
    };

    // A free-function row.
    (@munch [ $($acc:expr,)* ]
        $doc:literal
        $name:ident ( $( $an:ident : $av:ident $(($aarg:literal))? ),* $(,)? )
        $( -> $rk:ident $(($rarg:literal))? )?
        $( = $bk:ident ( $($bargs:literal),* ) )? ;
        $($rest:tt)*
    ) => {
        fns!(@munch [ $($acc,)* FnSpec {
            name: stringify!($name),
            receiver: None,
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: fns!(@ret $( $rk $(($rarg))? )?),
            body: fns!(@body $( $bk ( $($bargs),* ) )?),
            doc: $doc,
            sdk_alias: None,
        }, ] $($rest)*)
    };

    (@ret) => { RetKind::Value(RetShape::Unit) };
    (@ret $rk:ident) => { ret!($rk) };
    (@ret $rk:ident($rarg:literal)) => { ret!($rk($rarg)) };
    (@body) => { BodyKind::Custom };
    (@body scalar($call:literal)) => { BodyKind::ScalarCall { call: $call } };
    (@body seg_scalar($accessor:literal, $sentinel:literal)) => {
        BodyKind::SegScalar { accessor: $accessor, null_sentinel: $sentinel }
    };
    (@body seg_string($getter:literal)) => {
        BodyKind::SegString { getter: $getter, require_positive: false }
    };
    (@body seg_string_pos($getter:literal)) => {
        BodyKind::SegString { getter: $getter, require_positive: true }
    };

    // Entry: seed the muncher. Placed last so the `@munch`/`@ret`/`@body` arms match first.
    ( $($rows:tt)* ) => { fns!(@munch [] $($rows)*) };
}
