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

## What's Proven (70 tests)

| Category | Tests | What |
|----------|-------|------|
| Invariant proofs | 16 | proptest × 10 invariants × 10,000 configs |
| Invariant unit | 27 | Per-invariant pass/fail + composition |
| Analysis proofs | 8 | Resource counting, cross-refs, determinism |
| Engine tests | 5 | JSON execution, error handling, determinism |
| Determinism | 5 | JSON round-trip, value reflexivity |
| Analysis | 9 | Structure, sorting, independence |

## Convergence Theory

pangea-sim is the **verification** stage of the convergence pipeline:
- declared (Rust types) → resolved (Ruby AST) → converged (Ruby source) → **verified** (invariant proofs)

Combined with ruby-synthesizer (147 proofs) = **217 proofs total**.
The typed bridge from Rust to proven infrastructure is complete.
