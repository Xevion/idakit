//! Walks a decompiled function's syntax tree ([`Ctree`]) off the kernel thread.
//!
//! A decompiled function is materialized on the kernel thread into owned, interned arenas of
//! nodes and types, then handed back as a `Send` [`Ctree`] any worker thread can analyze.

mod extract;
mod node;
mod ops;
pub mod query;
mod render;
mod tree;

pub use extract::ExtractError;
pub(crate) use extract::walk;
pub use node::{
    Case, ExpressionId, ExpressionKind, ExpressionNode, Local, LocalId, LocalLocation,
    LocationPiece, NodeRef, StatementId, StatementKind, StatementNode,
};
pub use ops::{AssignmentOp, BinaryOp, UnaryOp};
pub use tree::{Ctree, CtreeBuilder, Descendants};
