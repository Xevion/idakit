//! The decompiler ctree as an owned, `Send`, interned ADT.
//!
//! A decompiled function is materialized on the kernel thread into owned arenas of
//! nodes and types, then handed back as a `Send` value any worker thread can analyze.
// TODO: document the ctree ADT (node/types/query) and drop this allow; the rest of
// the public API is `deny(missing_docs)`.
#![allow(missing_docs)]

mod extract;
mod node;
mod ops;
pub mod query;
mod render;
mod tree;

pub use crate::arena::{Arena, Idx};
pub use crate::types::{EnumMember, TypeData, TypeId, TypeKind, TypeMember, TypeTable};
pub use extract::ExtractError;
pub(crate) use extract::walk;
pub use node::{
    Case, ExpressionId, ExpressionKind, ExpressionNode, Local, LocalId, LocalLocation, NodeRef,
    StatementId, StatementKind, StatementNode,
};
pub use ops::{AssignOp, BinOp, UnOp};
pub use tree::{Ctree, CtreeBuilder, Descendants};
