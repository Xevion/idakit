//! The decompiler ctree as an owned, `Send`, interned ADT. See design §4.5.
//!
//! A decompiled function is materialized on the kernel thread into owned arenas of
//! nodes and types, then handed back as a `Send` value any worker thread can analyze.

mod arena;
mod node;
mod ops;
mod tree;
mod types;

pub use arena::{Arena, Idx};
pub use node::{Case, Cexpr, Cinsn, ExprId, ExprNode, LvarId, NodeRef, StmtId, StmtNode};
pub use ops::{AssignOp, BinOp, UnOp};
pub use tree::{Ctree, CtreeBuilder, Descendants};
pub use types::{EnumMember, TypeData, TypeId, TypeKind, TypeMember, TypeTable};
