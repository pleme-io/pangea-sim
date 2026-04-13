# Compliance Verification

## Overview

The compliance module bridges pangea-sim's invariant proofs to formal compliance
frameworks. When the `compliance` feature is enabled (requires `compliance-controls`
crate), `verify_baseline()` takes synthesized Terraform JSON and a compliance
baseline, runs the mapped invariants, and produces per-control pass/fail results.

## How verify_baseline() Works

```rust
pub fn verify_baseline(
    tf_json: &serde_json::Value,
    baseline: &Baseline,
) -> ComplianceResult
```

For each control in the baseline:

1. **Find covering invariants**: Iterate `ALL_INVARIANTS`, call
   `controls_for_invariant(inv)`, check if the result contains this control.
   Multiple invariants may cover the same control.

2. **Run invariants**: For each covering invariant, look up the matching
   `Invariant` struct (via snake_case to PascalCase name mapping) and call
   `inv.check(tf_json)`.

3. **Record result**: If ANY covering invariant passes, the control is satisfied.
   If ALL fail, the control is violated. Each result includes the control ID,
   invariant name, satisfaction status, and error message.

4. **Aggregate**: The `ComplianceResult` contains total controls, satisfied count,
   violated count, per-control results, and `all_satisfied: bool`.

### Name Mapping

pangea-sim invariants use snake_case (`no_public_ssh`). compliance-controls uses
PascalCase (`NoPublicSsh`). The `invariant_name_to_pascal()` function bridges:

| snake_case | PascalCase |
|------------|------------|
| `no_public_ssh` | `NoPublicSsh` |
| `all_ebs_encrypted` | `AllEbsEncrypted` |
| `imdsv2_required` | `ImdsV2Required` |
| `no_public_s3` | `NoPublicS3` |
| `iam_least_privilege` | `IamLeastPrivilege` |
| `no_default_vpc_usage` | `NoDefaultVpcUsage` |
| `all_subnets_private` | `AllSubnetsPrivate` |
| `encryption_at_rest` | `EncryptionAtRest` |
| `logging_enabled` | `LoggingEnabled` |
| `tagging_complete` | `TaggingComplete` |

## How Invariants Map to Controls

Each invariant checks a specific property of Terraform JSON. When an invariant
passes, it satisfies the compliance controls mapped to it in
`compliance-controls/src/invariant_mapping.rs`:

| Invariant | What It Checks | Controls Satisfied |
|-----------|---------------|-------------------|
| `NoPublicSsh` | No SG rule allows 0.0.0.0/0 on port 22 | AC-17, SC-7(4), CIS 5.2, SOC2 CC6.1, PCI 1.2.1 |
| `AllEbsEncrypted` | Every EBS volume/launch template has encryption | SC-28(1), SC-13, CIS 2.2.1, SOC2 CC6.1, PCI 3.4.1 |
| `ImdsV2Required` | Every launch template has http_tokens: required | SC-3, CIS EC2.21 |
| `NoPublicS3` | All S3 buckets block public ACLs and policies | AC-3, AC-14, CIS 2.1.1, SOC2 CC6.1 |
| `IamLeastPrivilege` | No IAM policy has Action:* + Resource:* | AC-6, AC-6(1), SOC2 CC6.1 |
| `NoDefaultVpcUsage` | No resource references default VPC | SC-7, CIS 5.1 |
| `AllSubnetsPrivate` | No public IP mapping without Tier:public tag | SC-7(5), AC-4, PCI 1.2.5 |
| `EncryptionAtRest` | RDS + DynamoDB have encryption enabled | SC-28, SC-12, PCI 3.4.1 |
| `LoggingEnabled` | All ALBs have access_logs enabled | AU-2, AU-12, SI-4, SOC2 CC7.1, SOC2 CC7.2 |
| `TaggingComplete` | All resources have ManagedBy + Purpose tags | CM-8, CM-2 |

## How Simulations Generate Compliant JSON

pangea-sim's 20+ simulation modules each produce Terraform JSON that satisfies
all 10 invariants by construction. The simulation pipeline:

```
SimulationConfig (typed Rust struct)
  -> simulation function (e.g., secure_vpc::simulate())
    -> Terraform JSON (serde_json::Value)
      -> check_all(invariants, tf_json) -> Ok(()) (all pass)
        -> verify_baseline(tf_json, fedramp_moderate()) -> ComplianceResult
```

Each simulation module (secure_vpc, tiered_subnets, k3s_cluster, etc.) produces
JSON where:
- Security groups never allow SSH from 0.0.0.0/0
- All EBS volumes are encrypted
- Launch templates require IMDSv2
- S3 buckets block public access
- IAM policies follow least privilege
- No default VPC references exist
- Subnets are private unless tagged
- Databases have encryption at rest
- Load balancers have access logging
- All resources have required tags

This is not checked after generation -- it is structural. The simulation code
constructs compliant resources. The invariant proofs verify what the code
guarantees.

## How to Verify a New Architecture Against FedRAMP Moderate

```rust
use pangea_sim::compliance::{verify_baseline, coverage_report};
use compliance_controls::fedramp_moderate;

// 1. Get your Terraform JSON (from simulation, synthesis, or file)
let tf_json: serde_json::Value = /* your Terraform JSON */;

// 2. Get the baseline
let baseline = fedramp_moderate();

// 3. Check coverage (which controls can our invariants verify?)
let coverage = coverage_report(&baseline);
println!("Coverage: {:.1}% ({}/{})",
    coverage.percentage(), coverage.covered_count, coverage.total);
for control in &coverage.uncovered {
    println!("  NOT COVERED by invariants: {:?}", control);
}

// 4. Verify the actual Terraform JSON
let result = verify_baseline(&tf_json, &baseline);
println!("Baseline: {} -- {}", result.baseline_name,
    if result.all_satisfied { "PASS" } else { "FAIL" });

for r in &result.results {
    if !r.satisfied {
        println!("  VIOLATED: {} (invariant: {}) -- {}",
            r.control_id, r.invariant,
            r.message.as_deref().unwrap_or(""));
    }
}
```

## The Certification Chain

When compliance verification passes, the certification module creates
tamper-evident proof:

```
verify_baseline(tf_json, baseline) -> ComplianceResult { all_satisfied: true }
  |
  v
certify_invariant(name, tf_json, true, configs_tested)
  -> ProofResult {
       input_hash: BLAKE3(tf_json),        // content-addresses the input
       proof_hash: BLAKE3(proof_content),   // content-addresses the result
     }
  |
  v
certify_simulation(architecture, proofs)
  -> SimulationCertificate {
       certificate_hash: BLAKE3(all_proofs), // tamper-evident
       all_passed: true,
     }
  |
  v
verify_certificate(cert) -> true  // recompute hash, compare
  |
  v
tameshi attestation layers -> sekiban K8s admission webhook
  -> deploy gate (reject if invalid)
```

Every hash in the chain is BLAKE3. Changing any input, any proof result,
or any certificate field invalidates the chain. The deployment webhook
(sekiban) rejects invalid signatures.

## Data Types

### ComplianceResult

```rust
struct ComplianceResult {
    baseline_name: String,     // e.g., "FedRAMP Moderate"
    total_controls: usize,
    satisfied_count: usize,
    violated_count: usize,
    results: Vec<ControlResult>,
    all_satisfied: bool,
}
```

### ControlResult

```rust
struct ControlResult {
    control_id: String,        // e.g., "AC-17", "CIS 5.2", "SOC2 CC6.1"
    invariant: String,         // e.g., "NoPublicSsh"
    satisfied: bool,
    message: Option<String>,   // error details if not satisfied
}
```

### Coverage Report

```rust
fn coverage_report(baseline: &Baseline) -> BaselineCoverage
```

Returns which controls in the baseline are covered by our 10 invariants
and which are not. Controls not covered by any invariant will always
show as violated in `verify_baseline()`.
