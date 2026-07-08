//! Constructs [`TypeExpr`], the owned recipe a type write applies.
//!
//! A `TypeExpr` is the *constructor intent* for a type: what to apply, built off the kernel
//! thread and infallibly, with every parse or resolution deferred to the one apply call. Two
//! forms exist today: a raw C declaration ([`decl`]) and a reference to an existing named type
//! ([`named`]), and a type write (`set_type`) routes between them. A bare identifier that could
//! name a type classifies as a name; a builtin keyword (`int`) or anything with a declarator
//! classifies as a declaration.
//!
//! ```
//! use idakit::types::expr;
//!
//! // A reference to an existing type, resolved by name at apply time.
//! let by_name = expr::named("Widget");
//! // A declaration, parsed against the database's type library at apply time.
//! let by_decl = expr::decl("Widget *");
//!
//! // `&str` classifies itself: a name that could exist is by-name, a keyword or declarator is a
//! // declaration.
//! use idakit::types::TypeExpr;
//! assert!(TypeExpr::from("Widget") == by_name);
//! assert!(TypeExpr::from("Widget *") == by_decl);
//! assert!(TypeExpr::from("int").is_decl()); // a builtin keyword parses; it is not a named type
//! ```

use std::fmt;

/// An owned, `Send` recipe for a type to apply, from [`named`] or [`decl`].
///
/// The write-side analog of a resolved [`Type`](crate::types::Type): un-lifetimed and
/// table-free, it names *what to apply* without touching the kernel, so it is built anywhere and
/// applied at one fallible call. `Ord` lets a batch of recipes sort, group, and dedup.
///
/// Today it carries either a declaration string or a named-type reference; the combinator forms
/// (`pointer`, `array`, `const_`, and so on) that make it a full recursive builder land with the
/// facade that lowers a `TypeExpr` into a `tinfo_t`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum TypeExpr {
    /// A C declaration, parsed against the database's type library at apply time.
    Decl(String),
    /// A reference to an existing named type, resolved at apply time.
    Named(String),
}

/// A reference to the existing named type `name`, resolved at apply time.
///
/// The explicit by-name root: unlike `TypeExpr::from("Foo")`, it forces the name path even for a
/// spelling a declaration parser would also accept, so an absent type reports
/// [`TypeNotFound`](crate::error::Error::TypeNotFound) rather than a parse error.
#[must_use]
pub fn named(name: impl Into<String>) -> TypeExpr {
    TypeExpr::Named(name.into())
}

/// A C declaration recipe, parsed against the database's type library at apply time.
///
/// The explicit declaration root. Use it for anything with a declarator (`"Widget *"`,
/// `"int[8]"`), a keyword group (`"struct pt"`), or a builtin (`"unsigned int"`), and to force
/// the declaration parser over the by-name path for a bare identifier.
#[must_use]
pub fn decl(text: impl Into<String>) -> TypeExpr {
    TypeExpr::Decl(text.into())
}

impl TypeExpr {
    /// The recipe's source text, whichever form it takes.
    #[inline]
    #[must_use]
    pub fn source(&self) -> &str {
        match self {
            Self::Decl(s) | Self::Named(s) => s,
        }
    }

    /// Whether this is a [`named`] reference.
    #[inline]
    #[must_use]
    pub fn is_named(&self) -> bool {
        matches!(self, Self::Named(_))
    }

    /// The referenced type name, or `None` for a [`decl`].
    #[inline]
    #[must_use]
    pub fn as_named(&self) -> Option<&str> {
        match self {
            Self::Named(s) => Some(s),
            Self::Decl(_) => None,
        }
    }

    /// Whether this is a [`decl`] recipe.
    #[inline]
    #[must_use]
    pub fn is_decl(&self) -> bool {
        matches!(self, Self::Decl(_))
    }

    /// The declaration text, or `None` for a [`named`] reference.
    #[inline]
    #[must_use]
    pub fn as_decl(&self) -> Option<&str> {
        match self {
            Self::Decl(s) => Some(s),
            Self::Named(_) => None,
        }
    }
}

/// Classifies a `&str` by shape, routing a name that could exist to [`named`] and everything else
/// (a keyword or a declarator) to [`decl`].
impl From<&str> for TypeExpr {
    fn from(s: &str) -> Self {
        if is_bare_type_name(s) {
            Self::Named(s.to_owned())
        } else {
            Self::Decl(s.to_owned())
        }
    }
}

/// Classifies an owned `String` like [`From<&str>`](TypeExpr::from), reusing its allocation.
impl From<String> for TypeExpr {
    fn from(s: String) -> Self {
        if is_bare_type_name(&s) {
            Self::Named(s)
        } else {
            Self::Decl(s)
        }
    }
}

impl fmt::Display for TypeExpr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.source())
    }
}

/// Whether `s` could name an existing type: a single, optionally `::`-qualified, C identifier that
/// is not a builtin type keyword.
///
/// This is the test that routes a `&str` to the by-name apply path: `"Widget"` and `"ns::Inner"`
/// name an existing type, while `"Widget *"` (declarator), `"struct pt"` (keyword group), `"int"`
/// (a builtin keyword, which no til stores as a named type), and `""` are declarations. It is
/// deliberately strict: any surrounding or interior whitespace disqualifies the fast path and falls
/// through to the declaration parser, which still applies the type, just without the clean
/// not-found error.
fn is_bare_type_name(s: &str) -> bool {
    !s.is_empty() && !is_builtin_type_keyword(s) && s.split("::").all(is_c_identifier)
}

/// Whether `s` is a single C builtin type keyword (`int`, `char`, `__int64`, and so on).
///
/// These are lexical identifiers but never named types, so they route to the declaration parser
/// instead of the by-name path, where `set_type("int")` would otherwise miss and report a spurious
/// not-found. Multi-word builtins (`unsigned int`) already carry whitespace and take the
/// declaration path anyway.
fn is_builtin_type_keyword(s: &str) -> bool {
    matches!(
        s,
        "void"
            | "bool"
            | "_Bool"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "signed"
            | "unsigned"
            | "wchar_t"
            | "__int8"
            | "__int16"
            | "__int32"
            | "__int64"
            | "__int128"
    )
}

/// Whether `s` is a non-empty C identifier: a leading letter or `_`, then letters/digits/`_`.
fn is_c_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use assert2::assert;
    use rstest::rstest;

    use super::*;

    const fn assert_send<T: Send>() {}
    // A recipe owns its strings, so it travels off the kernel thread to be built anywhere.
    const _: () = assert_send::<TypeExpr>();

    #[rstest]
    // bare names -> by-name path
    #[case("Widget", true)]
    #[case("_hidden", true)]
    #[case("my_struct_t", true)]
    #[case("Foo123", true)]
    #[case("ns::Inner", true)]
    #[case("a::b::c", true)]
    #[case("int_t", true)]
    // merely starting like a keyword is still a name
    // builtin keywords -> declaration path (no til stores them as named types)
    #[case("int", false)]
    #[case("char", false)]
    #[case("void", false)]
    #[case("unsigned", false)]
    #[case("__int64", false)]
    #[case("bool", false)]
    // declarators / groups / junk -> declaration path
    #[case("Widget *", false)]
    #[case("int[8]", false)]
    #[case("struct pt", false)]
    #[case("unsigned int", false)]
    #[case("123Foo", false)]
    #[case("", false)]
    #[case("Widget ", false)]
    #[case(" Widget", false)]
    #[case("::Foo", false)]
    #[case("a::", false)]
    #[case("a:::b", false)]
    fn classifies_bare_names_against_declarations(#[case] input: &str, #[case] bare: bool) {
        assert!(is_bare_type_name(input) == bare);
    }

    #[test]
    fn from_str_routes_by_classification() {
        assert!(TypeExpr::from("Widget") == TypeExpr::Named("Widget".into()));
        assert!(TypeExpr::from("ns::Inner") == TypeExpr::Named("ns::Inner".into()));
        assert!(TypeExpr::from("Widget *") == TypeExpr::Decl("Widget *".into()));
        assert!(TypeExpr::from("struct pt") == TypeExpr::Decl("struct pt".into()));
        assert!(TypeExpr::from("int") == TypeExpr::Decl("int".into()));
    }

    #[test]
    fn from_owned_string_matches_str_classification() {
        assert!(TypeExpr::from("Widget".to_owned()) == TypeExpr::from("Widget"));
        assert!(TypeExpr::from("Widget *".to_owned()) == TypeExpr::from("Widget *"));
    }

    #[test]
    fn explicit_roots_bypass_classification() {
        // `decl` forces the declaration path even for a bare identifier; `named` forces by-name
        // even for a spelling the parser would accept.
        assert!(decl("Widget") == TypeExpr::Decl("Widget".into()));
        assert!(named("Widget") == TypeExpr::Named("Widget".into()));
    }

    #[test]
    fn projections_and_display() {
        let n = named("Widget");
        assert!(n.is_named() && !n.is_decl());
        assert!(n.as_named() == Some("Widget"));
        assert!(n.as_decl().is_none());
        assert!(n.source() == "Widget");
        assert!(format!("{n}") == "Widget");

        let d = decl("Widget *");
        assert!(d.is_decl() && !d.is_named());
        assert!(d.as_decl() == Some("Widget *"));
        assert!(d.as_named().is_none());
        assert!(format!("{d}") == "Widget *");
    }
}
