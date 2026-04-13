# pangea-sim

Zero-cost infrastructure simulation and proof engine. Synthesize infrastructure
as Ruby from Rust types, execute it, capture Terraform JSON, and prove security
invariants hold across all possible configurations -- without touching any
cloud API.

## The Thesis

The Rust compiler is the infrastructure verifier. Compile-time type checking
combined with property-based testing provides deployment-equivalent guarantees
at zero cost, before any cloud API is ever called.

```
Rust types (IacType, IacResource)
  -> ruby-synthesizer (RubyNode AST)
    -> Ruby source (emit_file)
      -> SimulationEngine (execute Ruby)
        -> Terraform JSON (serde_json::Value)
          -> Invariant checks (10 security properties)
            -> BLAKE3 attestation (tamper-evident certificates)
              -> Composition (multi-architecture proofs)
```

## Security Invariants (10)

Every invariant is a pure function from Terraform JSON to pass/fail, proven
across thousands of random configurations via proptest.

| # | Invariant | Struct | What it prevents |
|---|-----------|--------|------------------|
| 1 | NoPublicSsh | `NoPublicSsh` | SG rules allowing `0.0.0.0/0` on port 22 |
| 2 | AllEbsEncrypted | `AllEbsEncrypted` | Unencrypted EBS volumes in launch templates |
| 3 | ImdsV2Required | `ImdsV2Required` | Launch templates without `http_tokens: "required"` |
| 4 | NoPublicS3 | `NoPublicS3` | S3 buckets missing `block_public_acls` or `block_public_policy` |
| 5 | IamLeastPrivilege | `IamLeastPrivilege` | IAM policies with `Action: "*"` AND `Resource: "*"` |
| 6 | NoDefaultVpcUsage | `NoDefaultVpcUsage` | Any resource referencing `vpc_id: "default"` |
| 7 | AllSubnetsPrivate | `AllSubnetsPrivate` | Subnets with `map_public_ip_on_launch: true` without `Tier: public` tag |
| 8 | EncryptionAtRest | `EncryptionAtRest` | RDS without `storage_encrypted`, DynamoDB without SSE |
| 9 | LoggingEnabled | `LoggingEnabled` | Load balancers without `access_logs.enabled: true` |
| 10 | TaggingComplete | `TaggingComplete` | Resources missing `ManagedBy` or `Purpose` tags |

All invariants implement the `Invariant` trait:

```rust
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>>;
}
```

## Simulation Engine

The `SimulationEngine` executes synthesized Ruby code and captures the
Terraform JSON output. It supports pluggable execution backends via the
`ExecutionBackend` trait.

```rust
use pangea_sim::engine::SimulationEngine;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::analysis::ArchitectureAnalysis;

let engine = SimulationEngine::new();
let tf_json = engine.execute_to_json(
    "{ 'resource' => { 'aws_vpc' => { 'main' => { 'cidr_block' => '10.0.0.0/16' } } } }"
).unwrap();

let invariants = all_invariants();
let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
check_all(&refs, &tf_json).expect("all invariants hold");

let analysis = ArchitectureAnalysis::from_terraform_json(&tf_json);
assert!(analysis.has_resource("aws_vpc", 1));
```

Key engine methods:

| Method | Purpose |
|--------|---------|
| `execute(ruby_source)` | Execute raw Ruby, return Terraform JSON |
| `execute_to_json(ruby_block)` | Wrap a Ruby hash expression, return JSON |
| `synthesize_resource(require, module, call)` | Full Pangea synthesis boilerplate |
| `with_backend(backend)` | Set a custom `ExecutionBackend` |
| `backend_name()` | Return the active backend's name |

## Sandbox Module

The `sandbox` module decouples execution from the simulation engine via the
`ExecutionBackend` trait.

```rust
pub trait ExecutionBackend: Send + Sync {
    fn execute(&self, ruby_source: &str) -> Result<String, ExecutionError>;
    fn execute_to_json(&self, ruby_source: &str) -> Result<serde_json::Value, ExecutionError>;
    fn name(&self) -> &str;
    fn is_deterministic(&self) -> bool;
}
```

### Backends

| Backend | Feature | Description |
|---------|---------|-------------|
| `SubprocessBackend` | (default) | Runs Ruby via `std::process::Command` |
| `WasmBackend` | `wasm-sandbox` | Runs Ruby in an isolated WASM sandbox via wasmtime |

The `WasmBackend` requires a `ruby.wasm` module provided via `module_path()`.
It is currently scaffolding -- the wasmtime engine is created and configured
for determinism (no threads), but full Ruby execution requires the module binary.

## Certification Module

Feature-gated behind `certification` (requires `tameshi` and `blake3`).

When invariant proofs pass, this module creates cryptographic attestation
certificates. Each invariant check becomes a BLAKE3-hashed entry in a
tamper-evident certificate.

```rust
// Feature: certification
use pangea_sim::certification::{certify_invariant, certify_simulation, verify_certificate};

let tf_json = serde_json::json!({"resource": {}});
let proof = certify_invariant("NoPublicSsh", &tf_json, true, 10_000);
// proof.input_hash  -- BLAKE3 of the Terraform JSON
// proof.proof_hash  -- BLAKE3 of invariant_name:passed:configs:input_hash

let cert = certify_simulation("secure_vpc", vec![proof]);
assert!(verify_certificate(&cert));  // recomputes BLAKE3, compares
```

### Data Types

| Type | Purpose |
|------|---------|
| `ProofResult` | Single invariant proof: name, passed, configs_tested, input_hash, proof_hash |
| `SimulationCertificate` | Collection of proofs for an architecture: all_passed, certificate_hash, timestamp |

### Functions

| Function | Purpose |
|----------|---------|
| `blake3_hash(bytes)` | BLAKE3 hash to 64-char hex string |
| `certify_invariant(name, tf_json, passed, count)` | Create a `ProofResult` with deterministic hashes |
| `certify_simulation(arch, proofs)` | Create a tamper-evident `SimulationCertificate` |
| `verify_certificate(cert)` | Recompute BLAKE3 over proofs, compare to stored hash |

## Architecture Simulations (20)

Each simulation module defines a config struct, a proptest strategy
(`arb_config()`), and a `simulate()` function that produces compliant
Terraform JSON. Every simulation guarantees all 10 invariants hold.

| Module | What it simulates | Min resources |
|--------|-------------------|---------------|
| `secure_vpc` | VPC + IGW + SG + default SG lockdown | 3 |
| `tiered_subnets` | Public/private subnet tiers | 1 |
| `nat_gateway` | NAT gateway with routing | 1 |
| `dns_zone` | Route53 hosted zone + records | 1 |
| `bastion_host` | Bastion with encrypted EBS + IMDSv2 | 2 |
| `k3s_dev_cluster` | VPC + launch template + ASG + IAM | 5 |
| `k3s_cluster_iam` | K3s IAM roles and policies | 2 |
| `nix_builder_fleet` | Fleet behind NLB with encrypted EBS | 4 |
| `ingress_alb` | ALB with access logging | 2 |
| `encrypted_storage` | KMS key + encrypted S3/EBS | 1 |
| `monitoring_stack` | CloudWatch + SNS + alarms | 1 |
| `waf_shield` | WAF web ACL + rules | 1 |
| `backup_vault` | AWS Backup vault + plan | 1 |
| `vpc_endpoints` | Interface/gateway VPC endpoints | 1 |
| `secrets_manager` | Secrets Manager with KMS | 1 |
| `cloudtrail` | CloudTrail + S3 bucket + KMS | 2 |
| `rds_cluster` | RDS instance with encryption + subnet group | 3 |
| `wireguard_vpn` | WireGuard server with SG + launch template | 3 |
| `ecr_registry` | ECR repository with lifecycle policy | 1 |
| `config_recorder` | AWS Config recorder + S3 delivery | 3 |

### Composed System Proofs (3)

Multi-architecture compositions that prove invariants are preserved under
composition -- the whole is as secure as its parts.

| System | Components | Purpose |
|--------|------------|---------|
| `ProductionK8sPlatform` | VPC + K3s + ALB + monitoring + backups + encryption + DNS | Full production stack |
| `BuilderInfra` | VPC + Nix builders + WireGuard VPN + DNS + encryption | Cloud builder fleet |
| `DataPlatform` | VPC + RDS + encryption + monitoring + backups + VPN | Database platform |

## Test Suite

Default features (176 tests):

```
cargo test
```

With certification feature (194 tests):

```
cargo test --features certification
```

With all features (adds WASM sandbox tests):

```
cargo test --all-features
```

### Test Breakdown

| Test file | Tests | What |
|-----------|-------|------|
| `src/` (unit) | 41-45 | Invariant pass/fail, engine execution, analysis, certification |
| `invariant_proofs` | 16 | proptest proofs: compliant pass, noncompliant fail, purity, monotonicity |
| `architecture_invariants` | 20 | All 10 invariants x 20 simulations (500 configs each) |
| `architecture_variants` | 40 | All 20 simulations produce resources + are deterministic |
| `composed_systems` | 9 | 3 composed systems x (invariants + resources + determinism) |
| `compiler_is_verifier` | 27-30 | Type homomorphism, structural correctness, composition |
| `sandbox_proofs` | 9 | Backend contracts, determinism, engine integration |
| `certification_proofs` | 0-11 | BLAKE3 determinism, certificate integrity, tampering detection |
| `analysis_proofs` | 8 | Resource counting, cross-refs, BTreeMap ordering |
| `determinism` | 5 | JSON round-trip, value reflexivity, analysis determinism |

### Key Proptest Proofs

- **10,000 configs each**: NoPublicSsh, AllEbsEncrypted, ImdsV2Required, check_all
- **5,000 configs**: invariant purity, union consistency, type homomorphism
- **500 configs**: each simulation x 10 invariants (20 simulations = 10,000 total)
- **200 configs**: each composed system x invariants + determinism

## Features

| Feature | Dependencies | What it enables |
|---------|-------------|-----------------|
| `wasm-sandbox` | `wasmtime`, `wasmtime-wasi` | `WasmBackend` for isolated WASM execution |
| `certification` | `tameshi`, `blake3` | `certify_invariant`, `certify_simulation`, `verify_certificate` |

## Dependencies

| Crate | Purpose |
|-------|---------|
| `ruby-synthesizer` (path, `iac-bridge` feature) | IacType-to-RubyType bridge, RubyNode AST, emit |
| `iac-forge` (git) | `IacType`, `IacAttribute`, `IacResource` IR types |
| `serde` + `serde_json` | Terraform JSON representation |
| `proptest` | Property-based testing framework |
| `thiserror` | Error type derivation |

## Integration with Other Crates

```
iac-forge (IacType, IacResource)
    |
    v
ruby-synthesizer (iac_bridge::iac_type_to_ruby -> RubyNode -> emit)
    |
    v
pangea-sim (SimulationEngine -> invariant checks -> certification)
    |
    v
tameshi (attestation layers, BLAKE3 Merkle trees)
    |
    v
workspace-state-graph (cross-repo type and proof connectivity)
```

## License

MIT
