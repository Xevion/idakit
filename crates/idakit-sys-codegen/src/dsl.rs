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

/// One [`RetShape`] from its authoring spelling: a scalar name (`U32`), `Unit`, `String`, a named
/// shape (`Shared("Name")`), or a `Vec` of a scalar (`Vec(U8)`) or of a named type (`Vec("Name")`).
macro_rules! shape {
    (Unit) => {
        RetShape::Unit
    };
    (String) => {
        RetShape::String
    };
    (Extern($n:literal)) => {
        RetShape::Extern($n)
    };
    (Shared($n:literal)) => {
        RetShape::Shared($n)
    };
    (UniquePtr($n:literal)) => {
        RetShape::UniquePtr($n)
    };
    (Vec($n:literal)) => {
        RetShape::Vec($n)
    };
    (Vec($s:ident)) => {
        RetShape::VecScalar(Scalar::$s)
    };
    ($s:ident) => {
        RetShape::Scalar(Scalar::$s)
    };
}

/// One [`RetKind`] from a [`shape!`] spelling, or `Result(<shape>)` for a call that may throw
/// (`ret!(U32)`, `ret!(Result(Vec(U8)))`), the return-position primitive [`fns!`]/[`methods!`]
/// compose.
macro_rules! ret {
    (Result($($shape:tt)+)) => {
        RetKind::Fallible(shape!($($shape)+))
    };
    ($($shape:tt)+) => {
        RetKind::Value(shape!($($shape)+))
    };
}

/// `&[VisitorMethod]` from `"doc" name(args) [-> Ret];` rows, composing [`args!`] for each row's
/// argument list. The return defaults to `U32`; write `-> Unit` (or any [`ret!`] spelling, with a
/// `("Name")` suffix for a tuple payload) to override.
macro_rules! methods {
    ( $(
        $doc:literal $name:ident ( $( $an:ident : $av:ident $(($aarg:literal))? ),* $(,)? )
        $( -> $rk:ident $(( $($rarg:tt)+ ))? )? ;
    )* ) => {
        &[ $( VisitorMethod {
            name: stringify!($name),
            doc: $doc,
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: methods!(@ret $( $rk $(( $($rarg)+ ))? )?),
        } ),* ]
    };
    (@ret) => { RetKind::Value(RetShape::Scalar(Scalar::U32)) };
    (@ret $rk:ident) => { ret!($rk) };
    (@ret $rk:ident( $($rarg:tt)+ )) => { ret!($rk( $($rarg)+ )) };
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
/// | `= seg_scalar(a, s)`   | `SegScalar`           | fill a `segment_info_t` for `n`, read `a`, `s` when absent |
/// | `= seg_string(c)`      | `SegString`           | resolve `n` to an `ea`, fill a `qstring` by emitting `c` |
/// | `= seg_string_pos(c)`  | `SegString`           | as above, and throw when `c` returns `<= 0`    |
macro_rules! fns {
    // All rows consumed: emit the accumulated slice.
    (@munch [ $($acc:expr,)* ]) => { &[ $($acc),* ] };

    // A `self: Type` receiver row (member call); tried first, so a plain row never sees `self`.
    (@munch [ $($acc:expr,)* ]
        $doc:literal
        $name:ident ( self : $recv:ident $(, $an:ident : $av:ident $(($aarg:literal))? )* $(,)? )
        $( -> $rk:ident $(( $($rarg:tt)+ ))? )?
        $( = $bk:ident ( $($bargs:literal),* ) )? ;
        $($rest:tt)*
    ) => {
        fns!(@munch [ $($acc,)* FnSpec {
            name: stringify!($name),
            receiver: Some(stringify!($recv)),
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: fns!(@ret $( $rk $(( $($rarg)+ ))? )?),
            body: fns!(@body $( $bk ( $($bargs),* ) )?),
            doc: $doc,
            sdk_alias: None,
        }, ] $($rest)*)
    };

    // A free-function row.
    (@munch [ $($acc:expr,)* ]
        $doc:literal
        $name:ident ( $( $an:ident : $av:ident $(($aarg:literal))? ),* $(,)? )
        $( -> $rk:ident $(( $($rarg:tt)+ ))? )?
        $( = $bk:ident ( $($bargs:literal),* ) )? ;
        $($rest:tt)*
    ) => {
        fns!(@munch [ $($acc,)* FnSpec {
            name: stringify!($name),
            receiver: None,
            args: args!( $( $an : $av $(($aarg))? ),* ),
            ret: fns!(@ret $( $rk $(( $($rarg)+ ))? )?),
            body: fns!(@body $( $bk ( $($bargs),* ) )?),
            doc: $doc,
            sdk_alias: None,
        }, ] $($rest)*)
    };

    (@ret) => { RetKind::Value(RetShape::Unit) };
    (@ret $rk:ident) => { ret!($rk) };
    (@ret $rk:ident( $($rarg:tt)+ )) => { ret!($rk( $($rarg)+ )) };
    (@body) => { BodyKind::Custom };
    (@body scalar($call:literal)) => { BodyKind::ScalarCall { call: $call } };
    (@body seg_scalar($accessor:literal, $sentinel:literal)) => {
        BodyKind::SegScalar { accessor: $accessor, null_sentinel: $sentinel }
    };
    (@body seg_string($call:literal)) => {
        BodyKind::SegString { call: $call, require_positive: false }
    };
    (@body seg_string_pos($call:literal)) => {
        BodyKind::SegString { call: $call, require_positive: true }
    };

    // Entry: seed the muncher. Placed last so the `@munch`/`@ret`/`@body` arms match first.
    ( $($rows:tt)* ) => { fns!(@munch [] $($rows)*) };
}
