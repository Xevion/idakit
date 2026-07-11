//! `cxx` snapshot bridge for the import table (`idakit_cxx::imports_build`).
//!
//! Imports have no random-access index (they reach the caller only through
//! `enum_import_names`' per-name callback), so the raw facade builds an owned `qvector` behind
//! an opaque handle, then the Rust side indexes it field by field and frees it: a
//! build-handle, index-N-times, free dance across six `extern "C"` functions
//! (`idakit_imports_build`/`_qty`/`_item`/`_name`/`_module`/`_free`).
//!
//! `cxx` collapses that to one call. [`imports_build`] returns `Vec<ImportRec>` by value, an
//! owned, `Send` snapshot the C++ side materializes in one walk. [`ImportRec`] is a `cxx`
//! **shared struct** carrying two [`String`] fields, proving a shared struct may hold owned
//! strings (the field type is `rust::String` on the C++ side). No handle, no per-field
//! accessor, no free.

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    /// One import-table row, returned inside the [`imports_build`] snapshot.
    struct ImportRec {
        /// Address the import is bound to.
        ea: u64,
        /// Ordinal, or `0` when imported by name.
        ord: u64,
        /// Symbol name, empty when imported by ordinal.
        name: String,
        /// Owning module (library) name.
        module: String,
    }

    unsafe extern "C++" {
        include!("import_cxx.h");

        /// The whole import table as an owned, `Send` snapshot, built in one walk of every
        /// module's `enum_import_names`. Retires the raw handle/index/free dance.
        fn imports_build() -> Vec<ImportRec>;
    }
}

pub use ffi::{ImportRec, imports_build};
