//! Small declarative macros that collapse mechanical duplication crate-wide.
//!
//! [`forward!`] emits the thin [`Database`](crate::Database) FFI forwarders in `raw.rs`;
//! [`key_identity!`] emits the by-key `PartialEq`/`Eq`/`Hash`(/`Ord`) impls that a `Copy`
//! database-view carries. Both are textual conveniences: they expand to exactly the code they
//! replace, so the generated surface stays greppable and drift against `idakit_sys` or a view's
//! key field fails to compile.

/// Emit `pub(crate)` [`Database`](crate::Database) FFI forwarders from a `fn name(recv, args) ->
/// Ret = body;` list.
///
/// Each entry expands to one method whose body is the given expression verbatim, so the
/// per-argument transforms (`address.get()`, `.ok()`, casts, renamed `sys` symbols) stay visible
/// at the call site. Invoke it in associated-item position inside `impl Database`. Both `&self`
/// and `&mut self` receivers are accepted; a muncher walks the list so keep each block well under
/// the recursion limit.
macro_rules! forward {
    () => {};
    (
        $(#[$meta:meta])*
        fn $name:ident(&mut self $(, $arg:ident: $aty:ty)* $(,)?) $(-> $ret:ty)? = $body:expr;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub(crate) fn $name(&mut self $(, $arg: $aty)*) $(-> $ret)? { $body }
        forward! { $($rest)* }
    };
    (
        $(#[$meta:meta])*
        fn $name:ident(&self $(, $arg:ident: $aty:ty)* $(,)?) $(-> $ret:ty)? = $body:expr;
        $($rest:tt)*
    ) => {
        $(#[$meta])*
        pub(crate) fn $name(&self $(, $arg: $aty)*) $(-> $ret)? { $body }
        forward! { $($rest)* }
    };
}

/// Emit a `Copy` view's identity impls forwarded to its key field.
///
/// A database view keys a `&Database` borrow by one field (an address, an index, a [`NodeId`]).
/// Identity is that field alone; the borrow is incidental and must never participate, so deriving
/// (which would compare the `&Database`) is wrong. This forwards `PartialEq`/`Eq`/`Hash` to the
/// key explicitly, and the `, ord` form adds the matching `Ord`/`PartialOrd`. The view type takes
/// exactly one lifetime parameter.
///
/// [`NodeId`]: crate::netnode::NodeId
macro_rules! key_identity {
    ($ty:ident, $field:ident) => {
        impl PartialEq for $ty<'_> {
            fn eq(&self, o: &Self) -> bool {
                self.$field == o.$field
            }
        }
        impl Eq for $ty<'_> {}
        impl ::std::hash::Hash for $ty<'_> {
            fn hash<H: ::std::hash::Hasher>(&self, s: &mut H) {
                self.$field.hash(s);
            }
        }
    };
    ($ty:ident, $field:ident, ord) => {
        key_identity!($ty, $field);
        impl Ord for $ty<'_> {
            fn cmp(&self, o: &Self) -> ::std::cmp::Ordering {
                self.$field.cmp(&o.$field)
            }
        }
        impl PartialOrd for $ty<'_> {
            fn partial_cmp(&self, o: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(o))
            }
        }
    };
}
