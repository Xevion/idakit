//! The `macro_rules!` authoring DSL for [`super::spec`]/[`super::netnode`]/[`super::visitors`]:
//! terse row syntax that expands into the [`super::model`] spec types.

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
