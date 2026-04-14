//! pangea-sim — Typed infrastructure simulation and proof engine.
//!
//! Synthesize infrastructure as Ruby from Rust types, execute it,
//! capture Terraform JSON, and verify invariants — all without
//! touching any cloud API.
//!
//! # Architecture
//!
//! ```text
//! Rust types (IacType, IacResource)
//!   → ruby-synthesizer (RubyNode AST)
//!     → Ruby source (emit_file)
//!       → SimulationEngine (execute Ruby)
//!         → Terraform JSON (serde_json::Value)
//!           → Invariant checks (proven properties)
//!             → Certification (tameshi attestation)
//! ```

pub mod engine;
pub mod error;
pub mod invariants;
pub mod analysis;
pub mod sandbox;
pub mod simulations;
pub mod transitions;
pub mod certification;
pub mod compliance;
pub mod remediation;
pub mod schemas;
pub mod network;
pub mod state_machines;
pub mod security_policies;
pub mod business;
