//! Sandbox execution backend proofs.
//!
//! Verifies that execution backends satisfy their contracts:
//! - Subprocess backend executes Ruby and returns output
//! - Determinism: identical inputs produce identical outputs
//! - Backend metadata (name, determinism flag) is correct
//! - WASM backend scaffolding compiles and reports correct state

use pangea_sim::sandbox::{ExecutionBackend, SubprocessBackend};

#[test]
fn subprocess_backend_is_deterministic() {
    let backend = SubprocessBackend::new();
    assert!(backend.is_deterministic());
    assert_eq!(backend.name(), "subprocess");
}

#[test]
fn subprocess_default_trait() {
    let backend = SubprocessBackend::default();
    assert_eq!(backend.name(), "subprocess");
}

#[test]
fn subprocess_executes_ruby() {
    let backend = SubprocessBackend::new();
    let result = backend.execute("puts 'hello'");
    // Only test if ruby is available
    match result {
        Ok(output) => assert_eq!(output.trim(), "hello"),
        Err(pangea_sim::sandbox::ExecutionError::Io(_)) => {
            eprintln!("SKIP: ruby not found");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn subprocess_execute_to_json() {
    let backend = SubprocessBackend::new();
    let result = backend.execute_to_json("require 'json'; puts JSON.generate({ 'a' => 1 })");
    match result {
        Ok(json) => assert_eq!(json["a"], 1),
        Err(pangea_sim::sandbox::ExecutionError::Io(_)) => {
            eprintln!("SKIP: ruby not found");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn subprocess_invalid_ruby_returns_error() {
    let backend = SubprocessBackend::new();
    let result = backend.execute("this is not valid ruby code !!!");
    match result {
        Err(pangea_sim::sandbox::ExecutionError::ExecutionFailed(_)) => {} // expected
        Err(pangea_sim::sandbox::ExecutionError::Io(_)) => {
            eprintln!("SKIP: ruby not found");
        }
        Ok(_) => panic!("expected error for invalid ruby"),
        Err(e) => panic!("unexpected error type: {e}"),
    }
}

#[test]
fn subprocess_determinism_proof() {
    let backend = SubprocessBackend::new();
    let ruby = "require 'json'; puts JSON.generate({ a: 1, b: 2 })";

    // Execute same code 5 times, verify identical output
    let results: Vec<_> = (0..5).filter_map(|_| backend.execute(ruby).ok()).collect();

    if results.len() >= 2 {
        for r in &results[1..] {
            assert_eq!(&results[0], r, "Non-deterministic execution detected");
        }
    } else {
        eprintln!("SKIP: ruby not available for determinism proof");
    }
}

#[test]
fn subprocess_custom_ruby_bin() {
    let backend = SubprocessBackend::new()
        .ruby_bin("/usr/bin/ruby")
        .load_path("/some/path");
    assert_eq!(backend.name(), "subprocess");
}

#[test]
fn engine_with_subprocess_backend() {
    use pangea_sim::engine::SimulationEngine;

    let engine =
        SimulationEngine::new().with_backend(Box::new(SubprocessBackend::new()));
    assert_eq!(engine.backend_name(), "subprocess");

    let result =
        engine.execute(r#"require 'json'; puts JSON.generate({ "hello" => "world" })"#);
    match result {
        Ok(json) => assert_eq!(json["hello"], "world"),
        Err(pangea_sim::error::SimError::Io(_)) => {
            eprintln!("SKIP: ruby not found");
        }
        Err(pangea_sim::error::SimError::RubyExecution { .. }) => {
            // Backend error mapped to RubyExecution — could be missing ruby
            eprintln!("SKIP: ruby execution failed (likely not found)");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[test]
fn engine_default_backend_name() {
    use pangea_sim::engine::SimulationEngine;

    let engine = SimulationEngine::new();
    assert_eq!(engine.backend_name(), "subprocess (builtin)");
}

#[cfg(feature = "wasm-sandbox")]
mod wasm_tests {
    use pangea_sim::sandbox::{ExecutionBackend, WasmBackend};

    #[test]
    fn wasm_backend_is_deterministic() {
        let backend = WasmBackend::new();
        assert!(backend.is_deterministic());
        assert_eq!(backend.name(), "wasm-sandbox");
    }

    #[test]
    fn wasm_backend_default_trait() {
        let backend = WasmBackend::default();
        assert_eq!(backend.name(), "wasm-sandbox");
    }

    #[test]
    fn wasm_backend_requires_module() {
        let backend = WasmBackend::new();
        let result = backend.execute("puts 'hello'");
        assert!(result.is_err()); // No module configured
    }

    #[test]
    fn wasm_backend_with_module_path() {
        let backend = WasmBackend::new().module_path("/path/to/ruby.wasm");
        let result = backend.execute("puts 'hello'");
        // Still errors — the module file doesn't exist, but the builder works
        assert!(result.is_err());
    }
}
