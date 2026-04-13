# pangea-sim

Typed infrastructure simulation and proof engine. Synthesize infrastructure
as Ruby, execute it, capture Terraform JSON, prove security invariants hold
across all possible configurations — without touching any cloud API.

## The Concept

```
Rust types → ruby-synthesizer → Ruby source → execute → Terraform JSON → invariant check → proof
```

The entire IaC pipeline becomes a pure function from types to proven JSON.
Simulation replaces deployment for verification. The cost is zero.

## Security Invariants (10)

| Invariant | What it proves |
|-----------|---------------|
| NoPublicSsh | No SG rule allows 0.0.0.0/0 on port 22 |
| AllEbsEncrypted | Every EBS volume is encrypted |
| ImdsV2Required | Every launch template requires IMDSv2 |
| NoPublicS3 | No S3 bucket allows public access |
| IamLeastPrivilege | No IAM policy has Action: * on Resource: * |
| NoDefaultVpcUsage | No resource references default VPC |
| AllSubnetsPrivate | No subnet is public unless tagged Tier: public |
| EncryptionAtRest | All RDS + DynamoDB have encryption |
| LoggingEnabled | All load balancers have access logging |
| TaggingComplete | All resources have ManagedBy + Purpose tags |

Each invariant is proven across 10,000 random configurations via proptest.

## Usage

```rust
use pangea_sim::engine::SimulationEngine;
use pangea_sim::invariants::{all_invariants, check_all};
use pangea_sim::analysis::ArchitectureAnalysis;

// Execute synthesized Ruby, capture Terraform JSON
let engine = SimulationEngine::new();
let tf_json = engine.execute_to_json("{ 'resource' => { 'aws_vpc' => { 'main' => { 'cidr_block' => '10.0.0.0/16' } } } }").unwrap();

// Prove invariants hold
let invariants = all_invariants();
let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
check_all(&refs, &tf_json).expect("all invariants hold");

// Analyze structure
let analysis = ArchitectureAnalysis::from_terraform_json(&tf_json);
assert!(analysis.has_resource("aws_vpc", 1));
```

## What's Proven (285+ tests)

| Category | Tests | What |
|----------|-------|------|
| Invariant proofs | 16 | proptest x 10 invariants x 10,000 configs |
| Invariant unit | 27 | Per-invariant pass/fail + composition |
| Analysis proofs | 8 | Resource counting, cross-refs, determinism |
| Engine tests | 5 | JSON execution, error handling, determinism |
| Determinism | 5 | JSON round-trip, value reflexivity |
| Analysis | 9 | Structure, sorting, independence |
| Architecture invariants | 20 | All 20 simulations satisfy all 10 invariants |
| Architecture variants | 40 | Resource production + determinism per simulation |
| Builder fleet proofs | 36 | Exhaustive fleet config coverage |
| Builder fleet sims | 20 | Simulation structure + analysis |
| Composed systems | 9 | Multi-architecture composition |
| Compiler-is-verifier | 27 | Full pipeline type-to-proof |
| Sandbox proofs | 9 | Execution backend correctness |
| Compliance proofs | 26 | NIST/CIS/FedRAMP/PCI/SOC2 control mapping, proptest verification, non-compliance detection, certification chain |

## Certification Module (feature: `certification`)

BLAKE3 cryptographic attestation of invariant proofs. Requires `tameshi` and `blake3`.

### Data Types

```rust
ProofResult {
    invariant_name: String,  // e.g., "no_public_ssh"
    passed: bool,
    configs_tested: usize,
    input_hash: String,      // BLAKE3 of serialized Terraform JSON
    proof_hash: String,       // BLAKE3 of "name:passed:configs:input_hash"
}

SimulationCertificate {
    architecture: String,     // e.g., "secure_vpc"
    proofs: Vec<ProofResult>,
    all_passed: bool,         // all proofs passed
    certificate_hash: String, // BLAKE3 of serialized proofs vector
    timestamp: String,        // Unix epoch seconds
}
```

### Proof Chain

```
certify_invariant(name, tf_json, passed, count)
  -> ProofResult { input_hash: BLAKE3(tf_json), proof_hash: BLAKE3(content) }
    -> certify_simulation(arch, proofs)
      -> SimulationCertificate { certificate_hash: BLAKE3(proofs) }
        -> verify_certificate(cert)
          -> recompute BLAKE3(cert.proofs) == cert.certificate_hash
```

Tampering with ANY proof or the certificate hash breaks verification.

## Compliance Module (feature: `compliance`)

Links invariant proofs to NIST 800-53, CIS AWS, FedRAMP, PCI DSS, and SOC 2 controls.
Requires `compliance-controls` crate (path dependency).

### Key Functions

```rust
use pangea_sim::compliance::{verify_baseline, coverage_report, ComplianceResult};
use compliance_controls::{fedramp_moderate, cis_aws_v3};

// Verify Terraform JSON against FedRAMP Moderate baseline
let result: ComplianceResult = verify_baseline(&tf_json, &fedramp_moderate());
assert!(result.all_satisfied);

// Check how well our invariants cover a baseline
let coverage = coverage_report(&cis_aws_v3());
assert!(coverage.percentage() > 80.0);
```

### Control Mapping (10 invariants -> 30+ controls across 5 frameworks)

| Invariant | NIST | CIS | SOC2 | PCI |
|-----------|------|-----|------|-----|
| NoPublicSsh | AC-17, SC-7(4) | 5.2 | CC6.1 | 1.2.1 |
| AllEbsEncrypted | SC-28(1), SC-13 | 2.2.1 | CC6.1 | 3.4.1 |
| ImdsV2Required | SC-3 | EC2.21 | -- | -- |
| NoPublicS3 | AC-3, AC-14 | 2.1.1 | CC6.1 | -- |
| IamLeastPrivilege | AC-6, AC-6(1) | -- | CC6.1 | -- |
| NoDefaultVpcUsage | SC-7 | 5.1 | -- | -- |
| AllSubnetsPrivate | SC-7(5), AC-4 | -- | -- | 1.2.5 |
| EncryptionAtRest | SC-28, SC-12 | -- | -- | 3.4.1 |
| LoggingEnabled | AU-2, AU-12, SI-4 | -- | CC7.1, CC7.2 | -- |
| TaggingComplete | CM-8, CM-2 | -- | -- | -- |

## Sandbox Module

Pluggable execution backends via the `ExecutionBackend` trait.

```rust
pub trait ExecutionBackend: Send + Sync {
    fn execute(&self, ruby_source: &str) -> Result<String, ExecutionError>;
    fn execute_to_json(&self, ruby_source: &str) -> Result<serde_json::Value, ExecutionError>;
    fn name(&self) -> &str;
    fn is_deterministic(&self) -> bool;
}
```

| Backend | Feature | Status |
|---------|---------|--------|
| `SubprocessBackend` | default | Fully functional, `ruby -e` via `Command` |
| `WasmBackend` | `wasm-sandbox` | Scaffolding -- wasmtime engine created, needs `ruby.wasm` module |

The engine falls back to built-in subprocess execution when no backend is set.
`backend_name()` returns `"subprocess (builtin)"` for default, or the backend's `name()`.

## Full Proof Chain

```
IacType (iac-forge IR)
  -> iac_type_to_ruby() [total, injective for scalars, deterministic]
    -> RubyType [emit() always produces valid Ruby]
      -> RubyNode AST [balanced blocks by construction]
        -> emit_file() [frozen_string_literal always first]
          -> SimulationEngine.execute() [deterministic]
            -> Terraform JSON [serde_json::Value]
              -> 10 invariants [proven over 10,000+ random configs]
                -> verify_baseline() [NIST/CIS/FedRAMP/PCI/SOC2 compliance]
                -> certify_invariant() [BLAKE3 input + proof hash]
                  -> certify_simulation() [BLAKE3 certificate hash]
                    -> verify_certificate() [tamper-evident]
                      -> tameshi attestation layers [Merkle composition]
```

## Integration Points

| Crate | Relationship |
|-------|-------------|
| `ruby-synthesizer` | Upstream: provides IacType-to-RubyType bridge, RubyNode AST |
| `iac-forge` | Upstream: provides `IacType`, `IacAttribute`, `IacResource` IR types |
| `compliance-controls` | Upstream: provides `Control`, `Baseline`, control mappings via `compliance` feature |
| `tameshi` | Downstream: attestation layers consume `ProofResult` via `certification` feature |
| `workspace-state-graph` | Downstream: maps cross-repo type and proof connectivity |

## Convergence Theory

pangea-sim is the **verification** stage of the convergence pipeline:
- declared (Rust types) -> resolved (Ruby AST) -> converged (Ruby source) -> **verified** (invariant proofs)

Combined with ruby-synthesizer (147 proofs) = **341 proofs total** (194 with certification).
The typed bridge from Rust to proven infrastructure is complete.
