//! Applying and defining prototypes and struct types: the direct-decl path (`type_apply`,
//! `type_define`), the built-recipe path (`type_build`, `type_function_build`), and their
//! typed-failure counterparts (`type_build_failed`, plus the failure paths inside `type_apply`).

use assert2::assert;
use idakit::prelude::*;

use crate::common::assert_type_write_err;

/// Applying a well-formed prototype sets it; a bad name or declaration surfaces the typed error.
#[test]
fn type_apply() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeWriteError;

        let address = idb.functions().next().expect("a function").address();

        // A well-formed prototype applies through the function cursor and shows up as a prototype.
        idb.function_mut(address)
            .expect("a function at the entry")
            .set_type("int idakit_probe(int a, int b)")
            .expect("apply function prototype");
        assert!(
            idb.function(address).prototype().is_some(),
            "a prototype should be set after apply"
        );

        // A bare, nonexistent name routes to the by-name path, a clean NoType.
        let r = idb.at_mut(address).set_type("idakit_no_such_type_zzz");
        assert_type_write_err!(r, TypeWriteError::NoType { .. });

        // A garbage declaration: ParseFailed carrying IDA's reason (captured off the msg channel,
        // or the fallback when IDA left none). Print it so a run shows whether the capture landed.
        match idb
            .at_mut(address)
            .set_type(expr::decl("%%% not a type %%%"))
        {
            Err(Error::TypeWrite {
                source: TypeWriteError::ParseFailed { reason, .. },
            }) => {
                println!("type-apply parse-error reason: {reason:?}");
            }
            other => panic!("garbage decl should be ParseFailed, got {other:?}"),
        }
    });
}

/// Defining a struct adds it to the type library so a later apply can reference it by name; a
/// malformed declaration surfaces the typed error.
#[test]
fn type_define() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::TypeWriteError;

        idb.types_mut()
            .define("struct idakit_pt { int x; int y; };")
            .expect("define struct");
        let names: Vec<String> = idb.named_types().map(|t| t.name()).collect();
        assert!(
            names.iter().any(|n| n == "idakit_pt"),
            "the defined struct should appear in named types"
        );

        // A defined function typedef applies cleanly by bare name (the by-name OK path), routed
        // through the scoped-closure cursor. A function type at a function entry sets its prototype.
        let entry = idb.functions().next().expect("a function").address();
        idb.types_mut()
            .define("typedef int idakit_fn_t(int arg);")
            .expect("define function typedef");
        idb.with_function_mut(entry, |f| f.set_type("idakit_fn_t"))
            .expect("a function at the entry")
            .expect("apply named function type");
        assert!(
            idb.function(entry).prototype().is_some(),
            "a prototype should be set after applying a named function type"
        );

        // A declaration referencing the freshly defined struct must parse, proving parse_decl
        // resolves against the local til, whether or not the kernel reshapes a code address to it.
        // Routed through the scoped-closure location cursor.
        let r = idb.with_location_mut(entry, |loc| loc.set_type(expr::decl("idakit_pt *")));
        assert!(
            !matches!(
                r,
                Err(Error::TypeWrite {
                    source: TypeWriteError::ParseFailed { .. }
                })
            ),
            "a decl referencing a defined local type must not fail parsing, got {r:?}"
        );

        // A malformed declaration: TypeDefineFailed.
        let r = idb
            .types_mut()
            .define("struct idakit_broken { this is not valid");
        assert!(let Err(Error::TypeDefineFailed { .. }) = r);
    });
}

/// A built recipe, a scalar leaf or a pointer/array composite, lowers through the
/// serialize-and-build path: the encoder emits postfix bytecode, the facade interpreter rebuilds
/// the `tinfo` bottom-up and applies it. A composite agrees with its text declaration, and one over
/// an unknown named type surfaces the typed error instead of panicking.
#[test]
fn type_build() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeWriteError, expr};

        let address = idb.functions().next().expect("a function").address();

        idb.types_mut()
            .define("struct idakit_built_pt { int x; int y; };")
            .expect("define struct for the build path");

        // The built composite reaches apply_tinfo with the type its text declaration parses to, so
        // the two agree at any address (a code entry may or may not accept a data type; both paths
        // match).
        let built = idb
            .at_mut(address)
            .set_type(expr::named("idakit_built_pt").pointer());
        let text = idb
            .at_mut(address)
            .set_type(expr::decl("idakit_built_pt *"));
        assert!(
            built.is_ok() == text.is_ok(),
            "a built composite should agree with its text declaration: built={built:?} text={text:?}"
        );
        println!("type-build composite applied: {}", built.is_ok());

        // A composite over an unknown named type BUILDS fine (an unresolved named leaf is accepted
        // into the tinfo), but the kernel refuses to APPLY it because the pointee is unresolved, a
        // deterministic ApplyRejected, regardless of the address.
        let r = idb
            .at_mut(address)
            .set_type(expr::named("idakit_no_such_built").pointer());
        assert_type_write_err!(r, TypeWriteError::ApplyRejected { .. });
    });
}

/// The from-scratch function-prototype builder lowers through the recipe path: build
/// `int f(int, unsigned int)` and a variadic twin, apply each as the entry's prototype, and read
/// the stored prototype back structurally (arch-independent) to confirm its return, arity, and
/// varargs flag.
#[test]
fn type_function_build() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeShape, expr};

        let entry = idb.functions().next().expect("a function").address();

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type(
                expr::function(expr::int32())
                    .arg(expr::int32())
                    .arg(expr::decl("unsigned int")),
            )
            .expect("apply a built prototype");
        let proto = idb
            .function(entry)
            .prototype_type()
            .expect("walk the built prototype")
            .expect("a prototype is set after the built apply");
        let TypeShape::Function {
            ret,
            params,
            varargs,
        } = proto.shape()
        else {
            panic!(
                "the built prototype should be a function, got {:?}",
                proto.shape()
            );
        };
        assert!(!*varargs, "the fixed prototype is not variadic");
        assert!(params.len() == 2, "two parameters, got {}", params.len());
        assert!(
            proto.get(*ret).shape
                == TypeShape::Int {
                    bytes: 4,
                    signed: true,
                },
            "the return type should be a signed 32-bit int"
        );

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type(expr::function(expr::void()).arg(expr::int32()).variadic())
            .expect("apply a variadic prototype");
        let proto = idb
            .function(entry)
            .prototype_type()
            .expect("walk the variadic prototype")
            .expect("a prototype is set after the variadic apply");
        assert!(let TypeShape::Function { varargs: true, .. } = proto.shape());

        // A builder-supplied calling convention applies. Its rendering is arch-dependent, so no
        // string check, matching type_surgery's cc note.
        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type(
                expr::function(expr::int32())
                    .arg(expr::int32())
                    .calling_convention(CallingConvention::Cdecl),
            )
            .expect("apply a prototype with a calling convention");
        assert!(
            idb.function(entry).prototype().is_some(),
            "a prototype should be set after applying a cc-carrying builder"
        );
    });
}

/// A composite recipe whose embedded declaration fails to parse fails at build time
/// (`BuildFailed`), distinct from a bare top-level `decl()`, which fails at parse time
/// (`ParseFailed`, see `type_apply`): wrapping the same garbage text in `.pointer()` routes it
/// through the recipe-build path instead of the direct-decl path.
#[test]
fn type_build_failed() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::{TypeWriteError, expr};

        let address = idb.functions().next().expect("a function").address();

        let r = idb
            .at_mut(address)
            .set_type(expr::decl("%%% not a type %%%").pointer());
        assert_type_write_err!(r, TypeWriteError::BuildFailed { .. });
    });
}

/// A builder-supplied parameter name renders in the applied prototype's text.
#[test]
fn type_named_arg_renders() {
    crate::common::with_canonical_db(|idb| {
        use idakit::types::expr;

        let entry = idb.functions().next().expect("a function").address();

        idb.function_mut(entry)
            .expect("a function at the entry")
            .set_type(expr::function(expr::int32()).named_arg("myparam", expr::int32()))
            .expect("apply a prototype with a named arg");
        let text = idb.function(entry).prototype().expect("prototype text");
        assert!(
            text.contains("myparam"),
            "the builder-supplied param name should render: {text:?}"
        );
    });
}
