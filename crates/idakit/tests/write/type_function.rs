//! Prototype surgery (return/arg/this/calling-convention edits), clearing a type, direct
//! function-cursor edits, and forward-declaring a struct.

use assert2::assert;
use idakit::prelude::*;

use crate::common::assert_type_write_err;

/// Prototype surgery edits one field at a time: seed a known prototype, swap the return type,
/// retype and rename a parameter, prepend an implicit `this`, and set a calling convention,
/// confirming each through a structural or textual read; the out-of-range and no-prototype paths
/// surface the typed `TypeWriteError`.
#[test]
fn type_surgery() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeShape, TypeWriteError, expr};

        let entry = idb.functions().next().expect("a function").address();

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type("int idakit_surgery_probe(int a, int b)")
            .expect("seed a prototype to edit");

        // Swap the return (int -> char *), retype arg 0 (-> unsigned int), rename arg 1.
        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_return_type(expr::char_().pointer())
            .expect("set the return type");
        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_arg_type(0, expr::decl("unsigned int"))
            .expect("retype arg 0");
        idb.function_mut(entry)
            .expect("a function at the entry")
            .rename_arg(1, "idakit_count")
            .expect("rename arg 1");

        let proto = idb
            .function(entry)
            .prototype_type()
            .expect("walk the edited prototype")
            .expect("a prototype is set");
        assert!(let TypeShape::Function { ret, params, .. } = proto.shape());
        assert!(let TypeShape::Ptr(_) = &proto.get(*ret).shape);
        assert!(params.len() == 2, "still two params, got {}", params.len());
        assert!(let TypeShape::Int { signed: false, .. } = &proto.get(params[0]).shape);
        // Param names are not in the structural walk; they render in the prototype text.
        let text = idb.function(entry).prototype().expect("prototype text");
        assert!(
            text.contains("idakit_count"),
            "the renamed arg should render: {text:?}"
        );

        // An out-of-range index is a typed TypeWriteError, without mutating.
        let r = idb
            .function_mut(entry)
            .expect("a function at the entry")
            .set_arg_type(9, expr::int32());
        assert_type_write_err!(
            r,
            TypeWriteError::ArgIndexOutOfRange {
                index: 9,
                arity: 2,
                ..
            }
        );

        // prepend_this inserts a leading implicit this-pointer, shifting the params.
        idb.function_mut(entry)
            .expect("a function at the entry")
            .prepend_this(expr::void().pointer())
            .expect("prepend a this-pointer");
        let proto = idb
            .function(entry)
            .prototype_type()
            .expect("walk after prepend_this")
            .expect("a prototype is set");
        assert!(let TypeShape::Function { params, .. } = proto.shape());
        assert!(
            params.len() == 3,
            "the this-pointer should be prepended, got {}",
            params.len()
        );
        let text = idb.function(entry).prototype().expect("prototype text");
        assert!(
            text.contains("this"),
            "the this arg should render: {text:?}"
        );

        // Setting a convention is accepted; its rendering is arch-dependent, so no string check.
        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_calling_convention(CallingConvention::Cdecl)
            .expect("set the calling convention");

        // A function whose type was cleared has no prototype to edit.
        idb.at_mut(entry).clear_type().expect("clear the prototype");
        let r = idb
            .function_mut(entry)
            .expect("a function at the entry")
            .set_return_type(expr::int32());
        assert_type_write_err!(r, TypeWriteError::NoPrototype { .. });
    });
}

/// Clearing a type is the inverse of applying one: set a prototype, confirm it, clear it, confirm
/// it is gone, and confirm a second clear is an idempotent success.
#[test]
fn type_clear() {
    crate::common::with_canonical_db(|idb| {
        let entry = idb.functions().next().expect("a function").address();

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type("int idakit_clear_probe(int a)")
            .expect("apply a prototype to clear");
        assert!(
            idb.function(entry).prototype().is_some(),
            "a prototype should be set before the clear"
        );

        idb.at_mut(entry).clear_type().expect("clear the type");
        assert!(
            idb.function(entry).prototype().is_none(),
            "the prototype should be gone after clear"
        );

        idb.at_mut(entry)
            .clear_type()
            .expect("a second clear is an idempotent success");
    });
}

/// `clear_type` and `rename` invoked directly on the function cursor from `function_mut`
/// (previously only exercised through the location cursor's `at_mut`).
#[test]
fn type_function_edit_direct() {
    crate::common::with_canonical_db(|idb| {
        let entry = idb.functions().next().expect("a function").address();

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type("int idakit_direct_probe(int a)")
            .expect("seed a prototype to clear");
        idb.function_mut(entry)
            .expect("a function at the entry")
            .clear_type()
            .expect("clear_type via FunctionEdit");
        assert!(
            idb.function(entry).prototype().is_none(),
            "the prototype should be gone after FunctionEdit::clear_type"
        );

        let original = idb.function(entry).name();
        idb.function_mut(entry)
            .expect("a function at the entry")
            .rename("idakit_direct_rename_probe")
            .expect("rename via FunctionEdit");
        assert!(idb.function(entry).name().as_str() == "idakit_direct_rename_probe");

        idb.function_mut(entry)
            .expect("a function at the entry")
            .rename(original.as_str())
            .expect("restore the original name");
        assert!(idb.function(entry).name().as_str() == original.as_str());
    });
}

/// `TypesMut::forward_declare` reserves a named struct with no body: it appears in `named_types`
/// and reads back as an opaque, bodyless type, and a later `define` over the same name completes
/// it into a full struct.
#[test]
fn type_forward_declare() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeShape;
        use idakit::types::diff::AggregateKind;

        idb.types_mut()
            .forward_declare("idakit_fwd_probe", AggregateKind::Struct)
            .expect("forward-declare a struct");
        assert!(
            idb.named_types().any(|t| t.name() == "idakit_fwd_probe"),
            "the forward-declared type should appear in named_types"
        );

        let opaque = idb
            .type_named("idakit_fwd_probe")
            .expect("resolve the forward-declared type");
        match opaque.shape() {
            TypeShape::Opaque(name) => assert!(name == "idakit_fwd_probe"),
            other => panic!("expected an opaque forward decl, got {other:?}"),
        }

        // define() over the same name completes the forward decl into a full struct.
        idb.types_mut()
            .define("struct idakit_fwd_probe { int x; };")
            .expect("complete the forward-declared struct");
        let completed = idb
            .type_named("idakit_fwd_probe")
            .expect("resolve the completed struct");
        assert!(
            let TypeShape::Struct { .. } = completed.shape(),
            "the forward decl should be completed into a full struct, got {:?}",
            completed.shape()
        );
    });
}
