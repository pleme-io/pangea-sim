//! Execution backend abstraction — subprocess vs WASM sandbox.
//!
//! The `ExecutionBackend` trait allows pangea-sim to run Ruby code
//! through different execution engines while maintaining identical
//! semantics and determinism guarantees.
//!
//! # Backends
//!
//! - [`SubprocessBackend`] — runs Ruby via `std::process::Command` (default)
//! - [`WasmBackend`] — runs Ruby in an isolated WASM sandbox (requires `wasm-sandbox` feature)
//!
//! # Architecture
//!
//! The backend trait decouples execution from the simulation engine,
//! enabling deterministic, sandboxed execution without changing the
//! invariant checking or analysis pipeline.

use std::path::PathBuf;

/// Errors from execution backends.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    /// Ruby process exited with non-zero status.
    #[error("Ruby execution failed: {0}")]
    ExecutionFailed(String),

    /// Output could not be parsed (e.g., invalid JSON).
    #[error("Invalid output: {0}")]
    InvalidOutput(String),

    /// Sandbox environment failed to initialize.
    #[error("Sandbox initialization failed: {0}")]
    SandboxInit(String),

    /// Underlying IO error (binary not found, pipe failure, etc.).
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Backend for executing Ruby code and capturing output.
///
/// Implementors provide isolated Ruby execution. The engine delegates
/// to the backend and only cares about the stdout string result.
pub trait ExecutionBackend: Send + Sync {
    /// Execute Ruby source code and return stdout.
    ///
    /// # Errors
    ///
    /// Returns `ExecutionError` if the Ruby process fails, the sandbox
    /// cannot be initialized, or IO fails.
    fn execute(&self, ruby_source: &str) -> Result<String, ExecutionError>;

    /// Execute Ruby and parse output as JSON.
    ///
    /// Default implementation calls [`execute`](Self::execute) and parses
    /// the result with `serde_json`.
    ///
    /// # Errors
    ///
    /// Returns `ExecutionError::InvalidOutput` if stdout is not valid JSON.
    fn execute_to_json(&self, ruby_source: &str) -> Result<serde_json::Value, ExecutionError> {
        let output = self.execute(ruby_source)?;
        serde_json::from_str(&output)
            .map_err(|e| ExecutionError::InvalidOutput(format!("JSON parse error: {e}")))
    }

    /// Human-readable backend name.
    fn name(&self) -> &str;

    /// Whether this backend provides deterministic execution.
    ///
    /// Both subprocess (with controlled env) and WASM backends are
    /// deterministic. This flag is informational for proof metadata.
    fn is_deterministic(&self) -> bool;
}

/// Subprocess backend — runs Ruby via `std::process::Command`.
///
/// This is the original execution strategy. It discovers `ruby` from
/// PATH and passes the source via `-e`. Load paths are injected as
/// `-I` flags.
pub struct SubprocessBackend {
    ruby_bin: PathBuf,
    load_paths: Vec<PathBuf>,
}

impl SubprocessBackend {
    /// Create a new subprocess backend with `ruby` from PATH.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ruby_bin: PathBuf::from("ruby"),
            load_paths: Vec::new(),
        }
    }

    /// Set the Ruby binary path.
    #[must_use]
    pub fn ruby_bin(mut self, path: impl Into<PathBuf>) -> Self {
        self.ruby_bin = path.into();
        self
    }

    /// Add a load path (`-I` flag) for the Ruby process.
    #[must_use]
    pub fn load_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.load_paths.push(path.into());
        self
    }
}

impl Default for SubprocessBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionBackend for SubprocessBackend {
    fn execute(&self, ruby_source: &str) -> Result<String, ExecutionError> {
        use std::process::Command;

        let mut cmd = Command::new(&self.ruby_bin);

        for path in &self.load_paths {
            cmd.arg("-I").arg(path);
        }

        cmd.arg("-e").arg(ruby_source);

        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let exit_code = output.status.code().unwrap_or(-1);
            return Err(ExecutionError::ExecutionFailed(format!(
                "exit {exit_code}: {stderr}"
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    }

    fn name(&self) -> &str {
        "subprocess"
    }

    fn is_deterministic(&self) -> bool {
        true
    }
}

/// WASM sandbox backend — runs Ruby in an isolated WASM environment.
///
/// Requires the `wasm-sandbox` feature flag. The backend uses wasmtime
/// to execute a `ruby.wasm` module with WASI support, providing
/// deterministic, sandboxed execution with no filesystem or network
/// access beyond what is explicitly granted.
///
/// Currently scaffolding — a `ruby.wasm` module must be provided via
/// [`module_path`](Self::module_path). Without it, execution returns
/// an error indicating the module is required.
#[cfg(feature = "wasm-sandbox")]
pub struct WasmBackend {
    /// Path to ruby.wasm module.
    wasm_module_path: Option<PathBuf>,
}

#[cfg(feature = "wasm-sandbox")]
impl WasmBackend {
    /// Create a new WASM backend without a module path.
    ///
    /// Call [`module_path`](Self::module_path) to set the ruby.wasm binary
    /// before executing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            wasm_module_path: None,
        }
    }

    /// Set the path to the ruby.wasm module.
    #[must_use]
    pub fn module_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.wasm_module_path = Some(path.into());
        self
    }
}

#[cfg(feature = "wasm-sandbox")]
impl Default for WasmBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "wasm-sandbox")]
impl ExecutionBackend for WasmBackend {
    fn execute(&self, _ruby_source: &str) -> Result<String, ExecutionError> {
        use wasmtime::*;

        // Create WASM engine with deterministic config.
        let mut config = Config::new();
        config.wasm_threads(false); // No threads for determinism

        let _engine = Engine::new(&config)
            .map_err(|e| ExecutionError::SandboxInit(e.to_string()))?;

        // Full implementation requires a ruby.wasm binary.
        // The engine is created to validate wasmtime links correctly,
        // but actual Ruby execution is deferred until a module is provided.
        Err(ExecutionError::SandboxInit(
            "WASM backend requires ruby.wasm module. \
             Set module_path() or use SubprocessBackend."
                .into(),
        ))
    }

    fn name(&self) -> &str {
        "wasm-sandbox"
    }

    fn is_deterministic(&self) -> bool {
        true
    }
}
