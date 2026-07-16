//! Applying and defining prototypes and struct types: the direct-decl path (`type_apply`,
//! `type_define`), the built-recipe path (`type_build`, `type_function_build`), their
//! typed-failure counterparts (`type_build_failed`, plus the failure paths inside `type_apply`),
//! and the declaration edge cases (empty aggregates, anonymous members, recursion, redefinition,
//! rename collisions, and the identifier boundary).

use assert2::assert;
use idakit::prelude::*;
use rstest::rstest;

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
        assert!(
            let TypeShape::Function {
                ret,
                params,
                varargs,
            } = proto.shape()
        );
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

/// A representative sweep of declaration shapes through `define`, each read back structurally: an
/// array member and a plain typedef alias.
#[rstest]
#[case::array_member("struct idakit_pcase_arr { int items[4]; };", "idakit_pcase_arr")]
#[case::typedef_alias("typedef unsigned int idakit_pcase_alias;", "idakit_pcase_alias")]
fn type_define_decl_sweep(#[case] decl: &'static str, #[case] name: &'static str) {
    crate::common::with_canonical_db(move |idb| {
        idb.types_mut()
            .define(decl)
            .unwrap_or_else(|e| panic!("{decl:?} should define cleanly, got {e:?}"));
        assert!(
            idb.named_types().any(|t| t.name() == name),
            "{name} should appear in named_types after defining {decl:?}"
        );
    });
}

/// A struct member with no name (`union { ... };` spliced directly into the parent, the C11/MSVC
/// anonymous-member extension) reads back with an empty [`TypeMember::name`], as documented.
#[test]
fn type_define_anonymous_member() {
    crate::common::with_canonical_db(|idb| {
        idb.types_mut()
            .define("struct idakit_pcase_anon { union { int i; float f; }; int tag; };")
            .expect("define a struct with an anonymous union member");

        let ty = idb
            .type_named("idakit_pcase_anon")
            .expect("resolve the struct");
        assert!(let TypeShape::Struct { members, .. } = ty.shape());
        let anon = members
            .iter()
            .find(|m| m.name.is_empty())
            .expect("the anonymous union member should be present with an empty name");
        assert!(let TypeShape::Union { members: inner, .. } = &ty.get(anon.ty).shape);
        assert!(
            inner.len() == 2,
            "the anonymous union should keep its two fields, got {inner:?}"
        );
    });
}

/// An empty struct body (`{}`) may or may not be accepted by the declaration parser (C
/// historically forbids it; several parsers extend it): whichever way this IDA build rules, the
/// outcome is a clean success (zero members read back) or a clean `TypeDefineFailed`, never a
/// panic.
#[test]
fn type_define_empty_struct() {
    crate::common::with_canonical_db(|idb| {
        match idb.types_mut().define("struct idakit_pcase_empty { };") {
            Ok(()) => {
                let ty = idb
                    .type_named("idakit_pcase_empty")
                    .expect("resolve the empty struct");
                assert!(let TypeShape::Struct { members, .. } = ty.shape());
                assert!(members.is_empty(), "an empty struct should have no members");
                println!("type-define empty struct: accepted, size {:?}", ty.size());
            }
            Err(Error::TypeDefineFailed { reason, .. }) => {
                println!("type-define empty struct: rejected, reason {reason:?}");
            }
            other => {
                panic!("empty struct should define cleanly or TypeDefineFailed, got {other:?}");
            }
        }
    });
}

/// A self-referential struct (`struct Node { struct Node *next; int value; }`) resolves with the
/// recursive pointer closing back to the struct's own root [`TypeId`], the live-kernel
/// counterpart of `TypeTable`'s hand-built `recursive_struct_uses_a_placeholder_back_reference`
/// unit test.
#[test]
fn type_define_recursive_struct() {
    crate::common::with_canonical_db(|idb| {
        idb.types_mut()
            .define("struct idakit_pcase_node { struct idakit_pcase_node *next; int value; };")
            .expect("define a self-referential struct");

        let node = idb
            .type_named("idakit_pcase_node")
            .expect("resolve the recursive struct");
        assert!(let TypeShape::Struct { members, .. } = node.shape());
        assert!(members.len() == 2, "next and value, got {}", members.len());
        let next = members
            .iter()
            .find(|m| m.name == "next")
            .expect("member next");
        assert!(let TypeShape::Ptr(pointee) = &node.get(next.ty).shape);
        assert!(
            *pointee == node.root(),
            "next should point back at the struct's own root type, got a different handle"
        );
    });
}

/// Redefining a name with a different body is tolerated, per `define`'s doc: the type library
/// keeps the latest body, not the first.
#[test]
fn type_redefine_conflicting_body() {
    crate::common::with_canonical_db(|idb| {
        idb.types_mut()
            .define("struct idakit_pcase_redef { int a; };")
            .expect("define the first body");
        idb.types_mut()
            .define("struct idakit_pcase_redef { int a; int b; int c; };")
            .expect("redefining with a different body should be tolerated");

        let ty = idb
            .type_named("idakit_pcase_redef")
            .expect("resolve the redefined struct");
        assert!(let TypeShape::Struct { members, .. } = ty.shape());
        assert!(
            members.len() == 3,
            "the latest definition (3 members) should win, got {members:?}"
        );
    });
}

/// Renaming a type onto a name already taken by another type is a typed `DupName` rejection, the
/// til-level counterpart of the member/constant `DupName` cases in `type_member`/`type_enum`, and
/// leaves neither name moved.
#[test]
fn type_rename_collision() {
    crate::common::with_canonical_db(|idb| {
        idb.types_mut()
            .define("struct idakit_pcase_a { int x; };")
            .expect("define the first type");
        idb.types_mut()
            .define("struct idakit_pcase_b { int y; };")
            .expect("define the second type");

        let collided = idb.types_mut().rename("idakit_pcase_a", "idakit_pcase_b");
        assert_type_write_err!(
            collided,
            TypeWriteError::Rejected {
                code: TypeEditCode::DupName,
                ..
            }
        );
        assert!(idb.named_types().any(|t| t.name() == "idakit_pcase_a"));
        assert!(idb.named_types().any(|t| t.name() == "idakit_pcase_b"));
    });
}

/// A sweep of syntactically malformed declarations through `set_type`, each a clean `ParseFailed`
/// rather than a panic: an unterminated struct body and a dangling function-declarator paren.
#[rstest]
#[case::unterminated_struct("struct { int x;")]
#[case::dangling_paren("int (")]
fn type_apply_rejects_malformed_syntax(#[case] decl: &'static str) {
    crate::common::with_canonical_db(move |idb| {
        let address = idb.functions().next().expect("a function").address();
        let r = idb.at_mut(address).set_type(expr::decl(decl));
        assert_type_write_err!(r, TypeWriteError::ParseFailed { .. });
    });
}

/// The identifier boundary: a tag starting with a digit is not a valid C identifier and the
/// declaration parser rejects it (`TypeDefineFailed`), while a leading underscore or mixed-case
/// digits are ordinary valid identifiers that define cleanly.
#[rstest]
#[case::leading_digit("9bad", false)]
#[case::leading_underscore("_idakit_pcase_leading", true)]
#[case::mixed_case_digits("IdaKit_Pcase_42", true)]
fn type_define_name_boundary(#[case] name: &'static str, #[case] should_succeed: bool) {
    crate::common::with_canonical_db(move |idb| {
        let decl = format!("struct {name} {{ int x; }};");
        match (idb.types_mut().define(&decl), should_succeed) {
            (Ok(()), true) => {
                assert!(idb.named_types().any(|t| t.name() == name));
            }
            (Err(Error::TypeDefineFailed { .. }), false) => {}
            (result, expected) => panic!(
                "defining {decl:?} should {}, got {result:?}",
                if expected {
                    "succeed"
                } else {
                    "fail with TypeDefineFailed"
                }
            ),
        }
    });
}
