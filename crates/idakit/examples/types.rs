//! Structured type introspection over prototypes, named types, and a stack frame in one interned table.
//!
//! Every function prototype, named type, and stack frame walks out of the kernel as an owned
//! snapshot whose every parameter, member, and slot is a real `TypeId` you resolve by handle,
//! the idiomatic counterpart to a rendered declaration string. A prototype names a class only
//! opaquely (`fb::JsObject *`), and resolving that name tells you whether the database carries
//! its field layout or merely a forward declaration.
//!
//! Run: `cargo run -p idakit --example types -- path/to/database.i64 [TypeName]`

use std::collections::HashSet;

use idakit::prelude::*;

const SHOW_PROTOS: usize = 12;
const FRAME_BUDGET: usize = 3000;
const MAX_NAMES: usize = 64;

/// A one-line rendering of the type at `id`.
///
/// Aggregates render as their tag only (so a recursive type stays finite). `Ptr`/`Array`/
/// `Function` recurse into element types, bottoming out at a named tag or scalar.
fn one_line(table: &TypeTable, id: TypeId) -> String {
    match &table.get(id).shape {
        TypeShape::Void => "void".to_owned(),
        TypeShape::Bool => "bool".to_owned(),
        TypeShape::Int { bytes, signed } => {
            format!(
                "{}int{}",
                if *signed { "" } else { "u" },
                u32::from(*bytes) * 8
            )
        }
        TypeShape::Float { bytes } => format!("float{}", u32::from(*bytes) * 8),
        TypeShape::Ptr(inner) => format!("{} *", one_line(table, *inner)),
        TypeShape::Array { elem, len } => format!("{}[{len}]", one_line(table, *elem)),
        TypeShape::Struct { name, .. } => {
            format!("struct {}", name.as_deref().unwrap_or("<anon>"))
        }
        TypeShape::Union { name, .. } => format!("union {}", name.as_deref().unwrap_or("<anon>")),
        TypeShape::Enum { name, .. } => format!("enum {}", name.as_deref().unwrap_or("<anon>")),
        TypeShape::Function {
            ret,
            params,
            varargs,
        } => {
            let ps: Vec<String> = params.iter().map(|p| one_line(table, *p)).collect();
            let tail = if *varargs { ", ..." } else { "" };
            format!("{} ({}{})", one_line(table, *ret), ps.join(", "), tail)
        }
        TypeShape::Typedef { name, .. } => name.clone(),
        TypeShape::Opaque(name) => name.clone(),
        TypeShape::Unknown => "<unknown>".to_owned(),
    }
}

/// A type name worth resolving via [`Database::type_named`]: a definition's tag
/// ([`TypeShape::tag_name`]) or an [`Opaque`](TypeShape::Opaque) reference.
///
/// The latter is a name a prototype mentions without carrying a body here, which resolving
/// may or may not expand.
fn referenced_name(shape: &TypeShape) -> Option<&str> {
    match shape {
        TypeShape::Opaque(name) => Some(name),
        _ => shape.tag_name(),
    }
}

/// Parameter count of a prototype image, or 0 for a non-function root.
fn param_count(image: &Type) -> usize {
    match image.shape() {
        TypeShape::Function { params, .. } => params.len(),
        _ => 0,
    }
}

/// Prints an aggregate's fields, one per line, recursing into embedded (non-pointer)
/// aggregates so nesting is visible.
///
/// `seen` breaks cycles; `indent` bounds depth.
fn layout(table: &TypeTable, id: TypeId, indent: usize, seen: &mut HashSet<TypeId>) {
    const MAX_DEPTH: usize = 3;
    let (TypeShape::Struct { members, .. } | TypeShape::Union { members, .. }) =
        &table.get(id).shape
    else {
        return;
    };
    let pad = "  ".repeat(indent);
    for m in members {
        println!(
            "{pad}+{:#06x}  {:<28} {}",
            m.bit_offset / 8,
            m.name,
            one_line(table, m.ty)
        );
        if indent < MAX_DEPTH && seen.insert(m.ty) {
            layout(table, m.ty, indent + 1, seen);
        }
    }
}

/// Prints a resolved named type: its root shape, size, and (if the database carries a body)
/// its full field layout.
///
/// A forward-declared name resolves but has no layout to show, so say so.
fn print_layout(image: &Type, name: &str) {
    let (table, root) = (image.types(), image.root());
    println!("\n-- layout: {name} --");
    match image.size() {
        Some(s) => println!("  {}  ({s:#x} bytes)", one_line(table, root)),
        None => println!("  {}  (no stored size)", one_line(table, root)),
    }
    if image.members().is_none_or(|m| m.is_empty()) {
        println!("  forward-declared -- the database stores the name but no field layout");
        return;
    }
    let mut seen = HashSet::from([root]);
    layout(table, root, 1, &mut seen);
}

/// Signed fp-relative offset the way IDA shows it: `-0x18`, `0x8`.
fn soff(offset: i64) -> String {
    if offset < 0 {
        format!("-{:#x}", offset.unsigned_abs())
    } else {
        format!("{offset:#x}")
    }
}

/// Prints a function's stack frame: total size and every slot's offset, label, and resolved type.
fn print_frame(frame: &StackFrame, ea: Address) {
    println!(
        "\n== stack frame: {ea:#x}  ({} bytes, {} slots) ==",
        frame.size(),
        frame.len()
    );
    for v in frame.slots() {
        let ty = v
            .ty()
            .map_or_else(|| "-".to_owned(), |id| one_line(frame.types(), id));
        let label = match v.kind() {
            StackSlotKind::Variable { name, .. } if !name.is_empty() => name.clone(),
            StackSlotKind::Variable { .. } => "<unnamed>".to_owned(),
            StackSlotKind::ReturnAddress => "<return address>".to_owned(),
            StackSlotKind::SavedRegisters => "<saved registers>".to_owned(),
        };
        println!("  {:>8}  {label}", soff(v.offset()));
        if ty != "-" {
            println!("            {ty}");
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv = std::env::args().skip(1);
    let db = argv.next().expect("usage: types <db.i64> [TypeName]");
    let arg_type = argv.next();

    Ida::run(move |ida| -> Result<(), Error> {
        ida.call(move |idb| -> Result<(), Error> {
            idb.open(&db).call()?;

            // Prototypes are sparse in a stripped release binary -- scan every function, not a
            // prefix, so the reported ratio is honest and the sample isn't just entry-point stubs.
            let mut total = 0usize;
            let mut typed = 0usize;
            let mut shown: Vec<(Address, String, Type)> = Vec::new();
            let mut names: Vec<String> = Vec::new();
            let mut best_frame: Option<(Address, StackFrame)> = None;
            let mut best_vars = 0usize;
            let mut frames_tried = 0usize;

            for f in idb.functions() {
                total += 1;

                if let Some(image) = f.prototype_type()? {
                    typed += 1;
                    for (_, t) in image.types().iter() {
                        if let Some(n) = referenced_name(&t.shape)
                            && names.len() < MAX_NAMES
                            && !names.iter().any(|x| x == n)
                        {
                            names.push(n.to_owned());
                        }
                    }
                    if shown.len() < SHOW_PROTOS {
                        shown.push((f.address(), f.name().as_str().to_owned(), image));
                    }
                }

                if frames_tried < FRAME_BUDGET
                    && let Some(frame) = idb.frame(f.address())?
                {
                    frames_tried += 1;
                    // A local lives within its frame; an offset in the millions is IDA's own
                    // misanalysis of a garbage function. Skip such frames so we showcase a real one.
                    let locals = frame.slots().iter().filter(|v| !v.is_special());
                    let sane = locals.clone().all(|v| v.offset().unsigned_abs() < 0x1_0000);
                    let n = locals.count();
                    if sane && (best_frame.is_none() || n > best_vars) {
                        best_vars = n;
                        best_frame = Some((f.address(), frame));
                    }
                }
            }

            println!("== function prototypes ==");
            println!("{typed} of {total} functions carry a stored prototype.\n");
            for (ea, sym, image) in &shown {
                println!("  {ea:#x}  {}", one_line(image.types(), image.root()));
                let short: String = sym.chars().take(64).collect();
                if !short.is_empty() {
                    println!("               {short}");
                }
            }
            if let Some((ea, _, image)) = shown.iter().max_by_key(|(_, _, im)| param_count(im))
                && let TypeShape::Function {
                    ret,
                    params,
                    varargs,
                } = image.shape()
                && !params.is_empty()
            {
                println!("\n  every parameter is a resolved TypeId -- {ea:#x}:");
                println!("    ret    {}", one_line(image.types(), *ret));
                for (i, p) in params.iter().enumerate() {
                    println!("    arg{i}   {}", one_line(image.types(), *p));
                }
                if *varargs {
                    println!("    ...");
                }
            }

            // The named-type pass: resolve every name the prototypes reference and classify what
            // the database actually holds -- a full body to expand, or just a forward declaration.
            println!("\n== referenced named types ==");
            if let Some(name) = &arg_type {
                match idb.type_named(name) {
                    Ok(image) => print_layout(&image, name),
                    Err(e) => println!("  type_named({name:?}): {e}"),
                }
            } else {
                let mut bodies: Vec<(String, Type)> = Vec::new();
                let mut forward: Vec<String> = Vec::new();
                let mut not_local = 0usize;
                for name in &names {
                    match idb.type_named(name) {
                        Ok(image) if image.members().is_some_and(|m| !m.is_empty()) => {
                            bodies.push((name.clone(), image));
                        }
                        Ok(_) => forward.push(name.clone()),
                        Err(Error::TypeNotFound { .. }) => not_local += 1,
                        Err(e) => println!("  type_named({name:?}): {e}"),
                    }
                }
                println!(
                    "{} referenced: {} with a full body, {} forward-declared, {} not a local type.",
                    names.len(),
                    bodies.len(),
                    forward.len(),
                    not_local
                );
                if let Some((name, image)) = bodies
                    .iter()
                    .max_by_key(|(_, im)| im.members().map_or(0, <[_]>::len))
                {
                    print_layout(image, name);
                } else {
                    for n in forward.iter().take(6) {
                        println!("  forward-decl: {n}");
                    }
                }
            }

            match &best_frame {
                Some((ea, frame)) => print_frame(frame, *ea),
                None => println!("\n(no function has a stack frame)"),
            }

            idb.close(false);
            println!("\nTYPES OK");
            Ok(())
        })?
    })??;

    Ok(())
}
