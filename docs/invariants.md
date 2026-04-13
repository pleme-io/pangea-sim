# Security Invariants

pangea-sim enforces 10 security invariants over synthesized Terraform JSON.
Each invariant is a pure function: given a `serde_json::Value` representing
Terraform configuration, it returns `Ok(())` if the property holds, or
`Err(Vec<Violation>)` listing every violation found.

All invariants implement the `Invariant` trait:

```rust
pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>>;
}
```

Violations carry full context:

```rust
pub struct Violation {
    pub invariant: String,       // which invariant
    pub resource_type: String,   // e.g., "aws_security_group_rule"
    pub resource_name: String,   // e.g., "bad_ssh"
    pub message: String,         // human-readable description
}
```

## Invariant 1: NoPublicSsh

**What it prevents:** SSH access from the public internet.

**How it checks:** Scans every `aws_security_group_rule` resource. If the rule
is `type: "ingress"`, the port range includes 22 (`from_port <= 22 && to_port >= 22`),
and `cidr_blocks` contains `"0.0.0.0/0"`, the invariant fails.

**Why it matters:** Public SSH is the most common misconfiguration in cloud
infrastructure. A single open SG rule exposes every instance to brute-force
attacks.

**Egress is ignored:** Only ingress rules are checked. Egress `0.0.0.0/0` is
normal and allowed.

## Invariant 2: AllEbsEncrypted

**What it prevents:** Unencrypted EBS volumes attached via launch templates.

**How it checks:** Scans every `aws_launch_template` resource. For each
`block_device_mappings` entry, checks that `ebs.encrypted` is `true`.
Missing or `false` values trigger a violation.

**Why it matters:** Unencrypted EBS volumes expose data at rest. If an instance
is terminated or a snapshot is shared, the data is readable without decryption.

## Invariant 3: ImdsV2Required

**What it prevents:** Instance metadata service v1 (SSRF vulnerability vector).

**How it checks:** Scans every `aws_launch_template` resource. Checks that
`metadata_options.http_tokens` is `"required"`. If the field is missing or set
to `"optional"`, the invariant fails.

**Why it matters:** IMDSv1 allows any process on the instance to query
credentials via a simple HTTP GET. IMDSv2 requires a session token, preventing
SSRF-based credential theft.

## Invariant 4: NoPublicS3

**What it prevents:** S3 buckets with public access.

**How it checks:** Scans every `aws_s3_bucket_public_access_block` resource.
Both `block_public_acls` and `block_public_policy` must be `true`. Each
missing or `false` value is a separate violation.

**Why it matters:** Public S3 buckets are the source of the largest data
breaches in cloud computing history. Blocking public access at the bucket
level prevents accidental exposure regardless of ACL or policy settings.

## Invariant 5: IamLeastPrivilege

**What it prevents:** Overly permissive IAM policies with `Action: "*"` and
`Resource: "*"`.

**How it checks:** Scans `aws_iam_policy` and `aws_iam_role_policy` resources.
Parses the `policy` field as JSON, iterates over `Statement` entries, and
checks whether both `Action` and `Resource` contain `"*"` (as string or in an
array).

**Why it matters:** `Action: "*", Resource: "*"` grants full administrative
access. Any compromised workload with this policy can do anything in the
account.

## Invariant 6: NoDefaultVpcUsage

**What it prevents:** Resources deployed to the AWS default VPC.

**How it checks:** Scans ALL resource types. If any resource has
`vpc_id: "default"`, the invariant fails.

**Why it matters:** The default VPC has permissive networking defaults (public
subnets, open NACL rules). Infrastructure should always use purpose-built VPCs
with explicit security controls.

## Invariant 7: AllSubnetsPrivate

**What it prevents:** Subnets that assign public IPs without explicit intent.

**How it checks:** Scans every `aws_subnet` resource. If
`map_public_ip_on_launch` is `true`, the subnet must have a tag
`Tier: "public"`. Without that tag, the invariant fails.

**Why it matters:** Public subnets should be explicitly declared as such.
Accidentally making a subnet public exposes all instances in it to the
internet.

## Invariant 8: EncryptionAtRest

**What it prevents:** Unencrypted databases and DynamoDB tables.

**How it checks:** Two resource types:
- `aws_db_instance`: `storage_encrypted` must be `true`
- `aws_dynamodb_table`: `server_side_encryption.enabled` must be `true`

**Why it matters:** Encryption at rest protects data if physical media is
compromised or if snapshots are shared. It is a baseline requirement for
virtually every compliance framework.

## Invariant 9: LoggingEnabled

**What it prevents:** Load balancers without access logging.

**How it checks:** Scans every `aws_lb` resource. The `access_logs.enabled`
field must be `true`. Missing `access_logs` block or `enabled: false` both
trigger violations.

**Why it matters:** Access logs are essential for incident investigation,
compliance auditing, and anomaly detection. Without them, there is no record
of which clients accessed which endpoints.

## Invariant 10: TaggingComplete

**What it prevents:** Resources missing required organizational tags.

**How it checks:** Scans EVERY resource across ALL types. Each resource must
have a `tags` object containing both `ManagedBy` and `Purpose` keys. Missing
either key produces a violation listing which tags are absent.

**Why it matters:** Tags are the foundation of cost allocation, access control
policies, and operational runbooks. Untagged resources are invisible to
governance tooling.

## How Proptest Proves Them

Each invariant is proven in multiple ways:

### 1. Architecture Invariants (`tests/architecture_invariants.rs`)

A macro generates a proptest for each of the 20 simulation modules:

```rust
prove_invariants!(secure_vpc, pangea_sim::simulations::secure_vpc);
```

Each proof generates 500 random configurations via `arb_config()` and verifies
all 10 invariants hold. 20 simulations x 500 configs = 10,000 verified stacks.

### 2. Invariant Proofs (`tests/invariant_proofs.rs`)

16 proptest proofs at up to 10,000 cases each:

| Proof | Cases | What it proves |
|-------|-------|----------------|
| 1-3 | 10,000 | NoPublicSsh, AllEbsEncrypted, ImdsV2Required pass compliant configs |
| 4 | 10,000 | `check_all` passes compliant configs |
| 5-7 | 10,000 | Each invariant correctly detects its violation |
| 8 | 10,000 | Noncompliant configs fail at least one invariant |
| 9 | 10,000 | Adding non-security resources does not break compliance |
| 10 | 10,000 | Each invariant passes independently (no masking) |
| 11 | 5 cases | Empty/null JSON passes all invariants (vacuous truth) |
| 12 | 5,000 | Same input always gives same result (purity) |
| 13 | 5,000 | `check_all` violations == union of individual checks |
| 14 | 2,000 | Adding a bad resource never decreases violation count (monotonicity) |
| 15 | 1 | All invariant names are unique |
| 16 | 10,000 | No invariant panics on arbitrary JSON (robustness) |

### 3. Composed System Proofs (`tests/composed_systems.rs`)

3 multi-architecture compositions at 200 configs each, proving that composing
individually-compliant architectures preserves all invariants.

### 4. Compiler-Is-Verifier Proofs (`tests/compiler_is_verifier.rs`)

5,000 random compliant architecture configs verified against all 10 invariants,
plus proofs that each invariant passes individually with no interaction effects.

## Using check_all

```rust
use pangea_sim::invariants::{all_invariants, check_all, Invariant};

let tf_json = serde_json::json!({...});
let invs = all_invariants();
let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();

match check_all(&refs, &tf_json) {
    Ok(()) => println!("All invariants hold"),
    Err(violations) => {
        for v in &violations {
            eprintln!("{}: {} ({}.{})",
                v.invariant, v.message, v.resource_type, v.resource_name);
        }
    }
}
```

## Adding a New Invariant

1. Define a struct in `src/invariants/mod.rs` implementing `Invariant`
2. Add it to the `all_invariants()` vector
3. Add unit tests (pass and fail cases)
4. Ensure all 20 simulation modules produce compliant output for the new invariant
5. The architecture_invariants and architecture_variants tests will automatically
   cover it via the macro
