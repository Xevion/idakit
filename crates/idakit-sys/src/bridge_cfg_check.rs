//! A validation bridge proving a hand-written `cxx` bridge can share the generated
//! [`FlowChart`]/`qflow_chart_t` `ExternType`; consumed only by `roundtrip.rs`, not the `idakit`
//! library.
//!
//! It declares no `qflow_chart_t` of its own; instead it aliases the *same* Rust type
//! [`bridge_gen`](crate::bridge_gen) bound to the SDK's `qflow_chart_t`. A `&FlowChart` produced
//! by [`cfg_build`](crate::bridge_gen::cfg_build) is therefore accepted here without conversion,
//! which a `using`-alias-per-bridge form could not express (each bridge would mint its own
//! distinct opaque `FlowChart`).

#[cxx::bridge(namespace = "idakit_cxx")]
mod ffi {
    unsafe extern "C++" {
        include!("cfg_check_cxx.h");

        /// The same `qflow_chart_t` the [`bridge_gen`](crate::bridge_gen) bridge bound; this is
        /// a type alias, not a fresh opaque type, so the two bridges share one Rust `FlowChart`.
        ///
        /// The C++ name override is repeated per bridge (`cxx` derives the emitted name from
        /// each declaration), so this bridge also emits the real global `::qflow_chart_t`.
        #[namespace = ""]
        #[cxx_name = "qflow_chart_t"]
        type FlowChart = crate::bridge_gen::FlowChart;

        /// Total number of successor edges across the whole graph (the sum of every block's
        /// successor count). A free function over a `&FlowChart` built by the generated bridge.
        fn cfg_total_edges_check(fc: &FlowChart) -> usize;
    }
}

pub use ffi::cfg_total_edges_check;
