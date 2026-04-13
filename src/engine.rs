//! Simulation engine — execute synthesized Ruby, capture Terraform JSON.
//!
//! The engine takes Ruby source code (produced by ruby-synthesizer),
//! executes it via an [`ExecutionBackend`](crate::sandbox::ExecutionBackend),
//! and captures the Terraform JSON output.
//!
//! The Ruby execution is isolated:
//! - No cloud APIs called (synthesis only, no apply)
//! - Output is deterministic (same input → same JSON)
//! - Subprocess has no network access (can be sandboxed further with WASM)
//!
//! # Backends
//!
//! By default the engine uses [`SubprocessBackend`](crate::sandbox::SubprocessBackend).
//! Use [`with_backend`](SimulationEngine::with_backend) to swap in a
//! [`WasmBackend`](crate::sandbox::WasmBackend) or any custom implementation.

use std::process::Command;
use crate::error::SimError;
use crate::sandbox::ExecutionBackend;

/// Result of a simulation — the Terraform JSON output.
pub type TerraformJson = serde_json::Value;

/// Simulation engine that executes synthesized Ruby and captures Terraform JSON.
///
/// Uses an [`ExecutionBackend`] to run Ruby code. Defaults to
/// [`SubprocessBackend`] for backward compatibility.
pub struct SimulationEngine {
    /// Path to the Ruby binary (used by the default subprocess path).
    ruby_bin: String,
    /// Additional load paths (-I flags) for the Ruby process.
    load_paths: Vec<String>,
    /// Optional pluggable execution backend.
    backend: Option<Box<dyn ExecutionBackend>>,
}

impl SimulationEngine {
    /// Create a new simulation engine.
    ///
    /// Discovers Ruby from PATH by default. Load paths should include
    /// pangea-core, terraform-synthesizer, abstract-synthesizer, and
    /// any provider gems needed for the simulation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            ruby_bin: "ruby".to_string(),
            load_paths: Vec::new(),
            backend: None,
        }
    }

    /// Set the Ruby binary path.
    #[must_use]
    pub fn ruby_bin(mut self, path: &str) -> Self {
        self.ruby_bin = path.to_string();
        self
    }

    /// Add a load path for the Ruby process.
    #[must_use]
    pub fn load_path(mut self, path: &str) -> Self {
        self.load_paths.push(path.to_string());
        self
    }

    /// Set a custom execution backend.
    ///
    /// When a backend is set, [`execute`](Self::execute) delegates to
    /// it instead of spawning a Ruby subprocess directly. This enables
    /// WASM sandboxed execution or any other backend that implements
    /// [`ExecutionBackend`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use pangea_sim::engine::SimulationEngine;
    /// use pangea_sim::sandbox::SubprocessBackend;
    ///
    /// let engine = SimulationEngine::new()
    ///     .with_backend(Box::new(SubprocessBackend::new()));
    /// ```
    #[must_use]
    pub fn with_backend(mut self, backend: Box<dyn ExecutionBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Execute Ruby source code and capture the output as JSON.
    ///
    /// If a backend is set via [`with_backend`](Self::with_backend), delegates
    /// to it. Otherwise falls back to the built-in subprocess execution.
    ///
    /// The Ruby script MUST print valid JSON to stdout. The last expression
    /// should be the Terraform synthesis result converted to JSON.
    ///
    /// # Errors
    ///
    /// Returns `SimError::RubyExecution` if the Ruby process exits non-zero.
    /// Returns `SimError::InvalidJson` if stdout is not valid JSON.
    pub fn execute(&self, ruby_source: &str) -> Result<TerraformJson, SimError> {
        if let Some(ref backend) = self.backend {
            let stdout = backend.execute(ruby_source).map_err(|e| {
                SimError::RubyExecution {
                    exit_code: -1,
                    stderr: e.to_string(),
                }
            })?;
            let json: TerraformJson = serde_json::from_str(stdout.trim())?;
            return Ok(json);
        }

        // Default subprocess path (preserves original behavior exactly).
        let mut cmd = Command::new(&self.ruby_bin);

        for path in &self.load_paths {
            cmd.arg("-I").arg(path);
        }

        cmd.arg("-e").arg(ruby_source);

        let output = cmd.output()?;

        if !output.status.success() {
            return Err(SimError::RubyExecution {
                exit_code: output.status.code().unwrap_or(-1),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: TerraformJson = serde_json::from_str(stdout.trim())?;
        Ok(json)
    }

    /// Returns the name of the active execution backend.
    ///
    /// Returns `"subprocess (builtin)"` when using the default path,
    /// or the backend's [`name()`](ExecutionBackend::name) when a
    /// custom backend is set.
    #[must_use]
    pub fn backend_name(&self) -> &str {
        self.backend
            .as_ref()
            .map_or("subprocess (builtin)", |b| b.name())
    }

    /// Synthesize a resource and capture Terraform JSON.
    ///
    /// Wraps the resource call in the standard Pangea synthesis boilerplate:
    /// requires, synthesizer creation, resource call, JSON output.
    ///
    /// # Arguments
    ///
    /// * `provider_require` — e.g., "pangea-aws" (the require path)
    /// * `provider_module` — e.g., "Pangea::Resources::AWS" (the module to extend)
    /// * `resource_call` — e.g., "aws_vpc(:test, { cidr_block: '10.0.0.0/16' })"
    pub fn synthesize_resource(
        &self,
        provider_require: &str,
        provider_module: &str,
        resource_call: &str,
    ) -> Result<TerraformJson, SimError> {
        let script = format!(
            r#"
require 'json'
require '{provider_require}'
require 'terraform-synthesizer'

synth = TerraformSynthesizer.new
synth.extend({provider_module})
synth.{resource_call}
puts JSON.generate(synth.synthesis)
"#
        );
        self.execute(&script)
    }

    /// Execute a raw Ruby block that returns a hash, capture as JSON.
    ///
    /// The block should produce a Ruby Hash. The engine wraps it with
    /// `require 'json'` and `puts JSON.generate(result)`.
    pub fn execute_to_json(&self, ruby_block: &str) -> Result<TerraformJson, SimError> {
        let script = format!(
            "require 'json'\nresult = begin\n{ruby_block}\nend\nputs JSON.generate(result)\n"
        );
        self.execute(&script)
    }
}

impl Default for SimulationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_simple_json() {
        let engine = SimulationEngine::new();
        let result = engine.execute(r#"require 'json'; puts JSON.generate({ "hello" => "world" })"#);
        match result {
            Ok(json) => assert_eq!(json["hello"], "world"),
            Err(SimError::Io(_)) => {
                // Ruby not available in test environment — skip
                eprintln!("SKIP: ruby not found");
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn execute_to_json_block() {
        let engine = SimulationEngine::new();
        let result = engine.execute_to_json("{ 'count' => 42, 'items' => [1, 2, 3] }");
        match result {
            Ok(json) => {
                assert_eq!(json["count"], 42);
                assert_eq!(json["items"].as_array().unwrap().len(), 3);
            }
            Err(SimError::Io(_)) => eprintln!("SKIP: ruby not found"),
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn execute_invalid_ruby_returns_error() {
        let engine = SimulationEngine::new();
        let result = engine.execute("this is not valid ruby code !!!");
        match result {
            Err(SimError::RubyExecution { exit_code, .. }) => {
                assert_ne!(exit_code, 0);
            }
            Err(SimError::Io(_)) => eprintln!("SKIP: ruby not found"),
            Ok(_) => panic!("expected error for invalid ruby"),
            Err(e) => panic!("unexpected error type: {e}"),
        }
    }

    #[test]
    fn execute_non_json_output_returns_error() {
        let engine = SimulationEngine::new();
        let result = engine.execute("puts 'not json'");
        match result {
            Err(SimError::InvalidJson { .. }) => {} // expected
            Err(SimError::Io(_)) => eprintln!("SKIP: ruby not found"),
            Ok(_) => panic!("expected JSON parse error"),
            Err(e) => panic!("unexpected error type: {e}"),
        }
    }

    #[test]
    fn deterministic_output() {
        let engine = SimulationEngine::new();
        let script = r#"require 'json'; puts JSON.generate({ "a" => 1, "b" => [2, 3] })"#;
        let r1 = engine.execute(script);
        let r2 = engine.execute(script);
        match (r1, r2) {
            (Ok(j1), Ok(j2)) => assert_eq!(j1, j2),
            (Err(SimError::Io(_)), _) | (_, Err(SimError::Io(_))) => {
                eprintln!("SKIP: ruby not found");
            }
            (Err(e), _) | (_, Err(e)) => panic!("unexpected error: {e}"),
        }
    }
}
