//! The decompiler ctree as an owned, `Send`, interned ADT.
//!
//! A decompiled function is materialized on the kernel thread into owned arenas of
//! nodes and types, then handed back as a `Send` value any worker thread can analyze.

mod arena;
mod extract;
mod node;
mod ops;
mod render;
mod tree;
mod types;

pub use arena::{Arena, Idx};
pub use extract::ExtractError;
pub(crate) use extract::walk;
pub use node::{
    Case, Cexpr, Cinsn, ExprId, ExprNode, Lvar, LvarId, LvarLocation, NodeRef, StmtId, StmtNode,
};
pub use ops::{AssignOp, BinOp, UnOp};
pub use tree::{Ctree, CtreeBuilder, Descendants};
pub use types::{EnumMember, TypeData, TypeId, TypeKind, TypeMember, TypeTable};
