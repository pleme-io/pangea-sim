//! Error types for the simulation engine.

/// Errors that can occur during simulation.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    /// Ruby execution failed.
    #[error("ruby execution failed (exit {exit_code}): {stderr}")]
    RubyExecution {
        exit_code: i32,
        stderr: String,
    },

    /// Ruby output was not valid JSON.
    #[error("ruby output is not valid JSON: {source}")]
    InvalidJson {
        #[from]
        source: serde_json::Error,
    },

    /// IO error (e.g., ruby binary not found).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invariant violation detected.
    #[error("invariant violation: {0}")]
    InvariantViolation(String),
}
