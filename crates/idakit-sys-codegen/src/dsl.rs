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

/// `&[VisitorMethod]` from `"doc" name(args) [-> Ret];` rows, composing [`args!`] for each row's
/// argument list. The return defaults to `U32`; write `-> Unit` (or any [`RetKind`] variant, with
/// a `("Name")` suffix for a tuple payload) to override.
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
    (@ret) => { RetKind::U32 };
    (@ret $rk:ident) => { RetKind::$rk };
    (@ret $rk:ident($rarg:literal)) => { RetKind::$rk($rarg) };
}

/// `&[FnSpec]` from `"doc" name(args) [-> Ret] [= body];` rows, the domain twin of [`methods!`].
///
/// A row is `"doc" name(args) -> Ret;`, composing [`args!`] for the argument list. Omitting `->`
/// defaults the return to `Unit` (as in Rust); a leading `self: Type` in the args names a `self: &T`
/// receiver (`FnSpec::receiver`). The body defaults to [`BodyKind::Custom`] (hand-written in the
/// domain's `custom_tu`); the `= scalar(...)` / `= seg_scalar(...)` / `= seg_string(...)` /
/// `= seg_string_pos(...)` suffixes select the templated body kinds instead.
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
        }, ] $($rest)*)
    };

    (@ret) => { RetKind::Unit };
    (@ret $rk:ident) => { RetKind::$rk };
    (@ret $rk:ident($rarg:literal)) => { RetKind::$rk($rarg) };
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
