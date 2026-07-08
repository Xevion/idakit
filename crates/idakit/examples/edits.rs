//! Write-side cursors end to end: rename, comment, patch, type-apply, and signature surgery through
//! `at_mut`, `function_mut`, and `types_mut`.
//!
//! A tour of the write idioms: the read-capable cursor (read-modify-write with no re-borrow), the
//! `&str` classifier (name vs declaration), the `Option`/`Result` shapes of the acquirers, the
//! `TypeExpr` builder (scalar leaves, pointers, arrays, qualifiers composed off the kernel),
//! struct-member surgery (`edit(..).member(..)`), and the type errors (`TypeNotFound`,
//! `TypeParseFailed`, `TypeApplyFailed`, `TypeDefineFailed`, and the member-edit `TypeEditError`).
//! Nothing is persisted: the database closes with `save = false`, and the name and bytes it touches
//! are restored first.
//!
//! Run: cargo run -p idakit --example edits -- path/to/database.i64

use idakit::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = std::env::args()
        .nth(1)
        .expect("usage: edits <path/to/database.i64>");

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&db).call()?;

            let entry = idb
                .functions()
                .next()
                .expect("the database has a function")
                .address();

            name_and_comment(idb, entry)?;
            function_types(idb, entry)?;
            signature_surgery(idb, entry)?;
            defining_types(idb)?;
            editing_members(idb)?;
            building_types(idb, entry);
            classifier_and_errors(idb, entry);

            idb.close(false);
            println!("\nEDITS OK");
            Ok(())
        })?
    })??;

    Ok(())
}

/// The read-capable address cursor: rename, comment, and patch on one `at_mut`, each read back
/// without a re-borrow. The name and bytes are restored so nothing leaks past `save = false`.
fn name_and_comment(idb: &mut Database, ea: Address) -> Result<(), Error> {
    println!("== at_mut: rename + comment + patch (one read-capable cursor) ==");

    // `at` is the read view; `at_mut` the write cursor. Snapshot the name to put it back after.
    let original_name = idb.at(ea).name();
    println!("  {ea:#x} name before: {original_name:?}");

    let mut loc = idb.at_mut(ea);
    loc.rename("idakit_edit_demo")?;
    loc.set_comment("renamed by the edits example", false)?;
    loc.set_comment("shown at every xref", true)?;
    // Read back through the SAME cursor: no drop-and-reborrow between the write and the read.
    println!("  name after:      {:?}", loc.name());
    println!("  regular    cmt:  {:?}", loc.comment());
    println!("  repeatable cmt:  {:?}", loc.repeatable_comment());

    // Patch a few bytes, confirm the read-back, then restore the originals.
    let original_bytes = idb.at(ea).bytes(4);
    let flipped: Vec<u8> = original_bytes.iter().map(|b| !b).collect();
    let mut loc = idb.at_mut(ea);
    loc.patch(&flipped)?;
    println!(
        "  patched 4 bytes, read-back matches: {}",
        loc.bytes(4) == flipped
    );
    loc.patch(&original_bytes)?;

    if let Some(name) = original_name {
        idb.at_mut(ea).rename(name)?;
    }
    Ok(())
}

/// The noun cursor: apply a prototype through `function_mut` (an `Option`, keyed by the containing
/// function). Shows the `Option<Result>` shape of the scoped-closure form and the `None` for an
/// address inside no function.
fn function_types(idb: &mut Database, ea: Address) -> Result<(), Error> {
    println!("\n== function_mut: prototypes ==");
    println!("  prototype before: {:?}", idb.function(ea).prototype());

    // Acquire by key (a two-phase borrow keeps it a one-liner). `function_mut` is an `Option`: an
    // address in no function yields `None`, never a cursor over nothing.
    if let Some(mut f) = idb.function_mut(ea) {
        f.set_type("int edits_probe(int a, int b)")?;
    }
    println!("  prototype after:  {:?}", idb.function(ea).prototype());

    // The scoped-closure form returns `Option<Result<_>>` (None = no function, then the write's own
    // Result). `.transpose()?` collapses both layers at once, the idiom for that shape.
    idb.with_function_mut(ea, |f| f.set_type("void edits_probe(void)"))
        .transpose()?;
    println!("  prototype now:    {:?}", idb.function(ea).prototype());

    // An address inside no function: the cursor is simply absent.
    let nowhere = Address::new_const(0xffff_ffff_f000);
    println!(
        "  function_mut(unmapped) is_some: {}",
        idb.function_mut(nowhere).is_some()
    );

    // For the entry address, `function_mut(ea).set_type` and `at_mut(ea).set_type` are the same
    // apply today; `FunctionEdit` earns its own weight when signature surgery (return/arg edits)
    // arrives.

    // `clear_type` is the inverse of `set_type`; it removes the prototype and is idempotent.
    idb.at_mut(ea).clear_type()?;
    println!(
        "  prototype after clear: {:?}",
        idb.function(ea).prototype()
    );
    Ok(())
}

/// Signature surgery: read-modify-write one field at a time (return, an arg's type, an arg's name,
/// an implicit `this`, the calling convention), each a typed [`Error::Signature`] on failure.
fn signature_surgery(idb: &mut Database, ea: Address) -> Result<(), Error> {
    println!("\n== function_mut: signature surgery ==");

    if let Some(mut f) = idb.function_mut(ea) {
        f.set_type("int surgery_probe(int a, int b)")?;
    }
    println!("  seeded:        {:?}", idb.function(ea).prototype());

    // Each verb reads the current prototype, changes one field, and re-applies.
    if let Some(mut f) = idb.function_mut(ea) {
        f.set_return_type(expr::char_().pointer())?; // int -> char *
        f.set_arg_type(0, expr::decl("unsigned int"))?; // arg 0 -> unsigned int
        f.rename_arg(1, "count")?; // arg 1 -> count
        f.prepend_this(expr::void().pointer())?; // insert void *this
        f.set_calling_convention(CallingConvention::Cdecl)?;
    }
    println!("  after surgery: {:?}", idb.function(ea).prototype());

    // An out-of-range argument index is a typed error, not a panic.
    if let Some(mut f) = idb.function_mut(ea)
        && let Err(Error::Signature { source }) = f.set_arg_type(99, expr::int32())
    {
        println!("  set_arg_type(99, ..) -> Signature: {source}");
    }
    Ok(())
}

/// The capability cursor: `define` new named types, then reference one from a later declaration.
fn defining_types(idb: &mut Database) -> Result<(), Error> {
    println!("\n== types_mut: define ==");

    idb.types_mut()
        .define("struct edit_demo_t { int id; char *name; };")?;
    let present = idb.named_types().any(|t| t.name() == "edit_demo_t");
    println!("  defined edit_demo_t, present in named types: {present}");

    // A declaration referencing the just-defined type resolves against the local til.
    match idb
        .types_mut()
        .define("typedef struct edit_demo_t edit_demo_alias;")
    {
        Ok(()) => println!("  typedef alias to it: ok"),
        Err(e) => println!("  typedef alias: {e}"),
    }

    // A malformed declaration is a typed error carrying IDA's own reason.
    match idb.types_mut().define("struct broken { not valid") {
        Err(Error::TypeDefineFailed { reason, .. }) => {
            println!("  malformed define -> TypeDefineFailed: {reason}");
        }
        other => println!("  malformed define -> unexpected {other:?}"),
    }
    Ok(())
}

/// Member surgery on defined types: append/retype/rename struct fields through the `member(..)`
/// sub-cursor (with the structured rejection when a rename collides), then add and revalue enum
/// constants through `constant(..)`. Each edit auto-saves to the local til; nothing persists past
/// `save = false`.
fn editing_members(idb: &mut Database) -> Result<(), Error> {
    use idakit::types::expr;

    println!("\n== types_mut: edit members ==");

    idb.types_mut()
        .define("struct edit_member_demo { int a; int b; };")?;

    idb.types_mut()
        .edit("edit_member_demo")
        .add_member("c", expr::int32())?;
    idb.types_mut()
        .edit("edit_member_demo")
        .member("a")
        .set_type(expr::char_())?;
    idb.types_mut()
        .edit("edit_member_demo")
        .member("b")
        .rename("beta")?;

    let names: Vec<String> = idb
        .type_named("edit_member_demo")?
        .members()
        .unwrap_or_default()
        .iter()
        .map(|m| m.name.clone())
        .collect();
    println!("  after add + retype + rename, members: {names:?}");

    // Renaming onto an existing name surfaces the structured tinfo_code.
    match idb
        .types_mut()
        .edit("edit_member_demo")
        .member("c")
        .rename("a")
    {
        Err(Error::TypeEdit {
            source: TypeEditError::Rejected { code, .. },
        }) => println!("  duplicate rename -> Rejected({code})"),
        other => println!("  duplicate rename -> unexpected {other:?}"),
    }

    // Enum constants use the same cursor: add, revalue, rename.
    idb.types_mut()
        .define("enum edit_enum_demo { DEMO_A = 1, DEMO_B = 2 };")?;
    idb.types_mut()
        .edit("edit_enum_demo")
        .add_constant("DEMO_C", 3)?;
    idb.types_mut()
        .edit("edit_enum_demo")
        .constant("DEMO_A")
        .set_value(10)?;
    let constants: Vec<(String, u64)> = match idb.type_named("edit_enum_demo")?.shape() {
        idakit::types::TypeShape::Enum { members, .. } => {
            members.iter().map(|m| (m.name.clone(), m.value)).collect()
        }
        _ => Vec::new(),
    };
    println!("  after add + revalue, constants: {constants:?}");
    Ok(())
}

/// The `TypeExpr` builder: compose a recipe off the kernel (scalar-leaf roots, then the
/// pointer/array/qualifier transforms), inspect it, and apply it through the same `set_type`. A
/// composite lowers through the serialize-and-build facade, so the built form and its text twin
/// reach one `tinfo`; `named(..).pointer()` over an unknown type fails at build time.
fn building_types(idb: &mut Database, ea: Address) {
    println!("\n== TypeExpr builder: compose + apply ==");

    // Roots are free functions, transforms are methods, so a recipe reads left-to-right.
    let uint_array = expr::uint32().array(4); // uint32[4]
    let ptr_to_named = expr::named("edit_demo_t").pointer(); // edit_demo_t *
    let const_ptr = expr::int32().const_().pointer(); // const int32 *
    println!("  uint32().array(4)              -> {uint_array:<14} ({uint_array:?})");
    println!("  named(\"edit_demo_t\").pointer() -> {ptr_to_named}");
    println!("  int32().const_().pointer()     -> {const_ptr}");

    // `deref` peels one layer, the inverse of `pointer`; qualifiers are idempotent.
    println!(
        "  (edit_demo_t *).deref() == named: {}",
        ptr_to_named.clone().deref() == expr::named("edit_demo_t")
    );

    // Built recipes apply through the ordinary cursor. Whether a code entry accepts a data type is
    // the kernel's call; the point is that the built form lowers and applies like its text twin.
    report(
        "set_type(uint32().array(4))",
        idb.at_mut(ea).set_type(uint_array),
    );
    report(
        "set_type(named(..).pointer())",
        idb.at_mut(ea).set_type(ptr_to_named),
    );

    // A composite over an unknown named type fails while building the tinfo, a TypeApplyFailed.
    report(
        "set_type(named(\"no_such\").pointer())",
        idb.at_mut(ea)
            .set_type(expr::named("no_such_zzz").pointer()),
    );

    // A whole function prototype composes off the kernel too: a return root, then params.
    let proto = expr::function(expr::int32())
        .arg(expr::int32())
        .named_arg("flags", expr::uint32())
        .variadic()
        .build();
    println!("  function(int32).arg(int32).named_arg(\"flags\", uint32).variadic -> {proto}");
    report(
        "function_mut(entry).set_type(built prototype)",
        idb.function_mut(ea)
            .map_or(Ok(()), |mut f| f.set_type(proto)),
    );
}

/// The `&str` classifier and the type-error taxonomy. The not-found and parse-failure paths fail
/// before the kernel applies, so they never mutate; the closing `int` apply does reshape the item,
/// which is harmless here since the database closes without saving.
fn classifier_and_errors(idb: &mut Database, ea: Address) {
    println!("\n== the &str classifier + type errors ==");

    // `From<&str>`: a name that could exist routes by-name; a keyword or a declarator is parsed.
    println!("  \"edit_demo_t\"   -> {:?}", TypeExpr::from("edit_demo_t"));
    println!(
        "  \"edit_demo_t *\" -> {:?}",
        TypeExpr::from("edit_demo_t *")
    );
    println!(
        "  \"int\"           -> {:?}  (a keyword: parsed, not looked up)",
        TypeExpr::from("int")
    );

    // A bare unknown name takes the by-name path and reports a clean not-found, without mutating.
    report(
        "set_type(\"no_such_type_xyz\")",
        idb.at_mut(ea).set_type("no_such_type_xyz"),
    );

    // An explicit `named` root forces by-name even for a keyword, so `int` is not-found here (no
    // named type "int" exists), in contrast to the classifier, which parses a bare "int".
    report(
        "set_type(named(\"int\"))",
        idb.at_mut(ea).set_type(expr::named("int")),
    );

    // A garbage declaration fails in the parser, before any apply; the reason is IDA's own.
    report(
        "set_type(decl(\"%%% junk %%%\"))",
        idb.at_mut(ea).set_type(expr::decl("%%% junk %%%")),
    );

    // A builtin keyword like "int" parses and applies, rather than reporting a spurious not-found
    // from a by-name lookup that no til would ever satisfy.
    report("set_type(\"int\")", idb.at_mut(ea).set_type("int"));
}

/// Prints how one `set_type` call resolved, naming the error variant on failure.
fn report(call: &str, r: Result<(), Error>) {
    match r {
        Ok(()) => println!("  {call} -> Ok"),
        Err(Error::TypeNotFound { name }) => {
            println!("  {call} -> TypeNotFound {{ name: {name:?} }}");
        }
        Err(Error::TypeParseFailed { reason, .. }) => {
            println!("  {call} -> TypeParseFailed: {reason}")
        }
        Err(Error::TypeApplyFailed { reason, .. }) => {
            println!("  {call} -> TypeApplyFailed: {reason}")
        }
        Err(e) => println!("  {call} -> {e}"),
    }
}
