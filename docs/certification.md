# Certification Module

The certification module creates BLAKE3 cryptographic attestation of invariant
proof results. It is feature-gated behind `certification` and requires the
`tameshi` and `blake3` crates.

```toml
# Cargo.toml
[features]
certification = ["dep:tameshi", "dep:blake3"]
```

## Overview

When security invariants pass, the certification module produces tamper-evident
certificates. Each proof result contains BLAKE3 hashes of both the input
(Terraform JSON) and the proof content. Certificates aggregate multiple proof
results and produce a top-level hash over the entire collection.

```
Invariant check passes
  -> certify_invariant()
    -> ProofResult { input_hash, proof_hash }
      -> certify_simulation()
        -> SimulationCertificate { certificate_hash }
          -> verify_certificate()
            -> BLAKE3(cert.proofs) == cert.certificate_hash
```

## Data Types

### ProofResult

Represents a single invariant proof with cryptographic binding to the input.

```rust
pub struct ProofResult {
    pub invariant_name: String,   // e.g., "no_public_ssh"
    pub passed: bool,             // whether the invariant held
    pub configs_tested: usize,    // number of configurations tested
    pub input_hash: String,       // BLAKE3 hex of serialized Terraform JSON
    pub proof_hash: String,       // BLAKE3 hex of proof content string
}
```

The `proof_hash` is computed from the concatenation
`"{invariant_name}:{passed}:{configs_tested}:{input_hash}"`, making it
dependent on every field. Changing any value produces a different hash.

### SimulationCertificate

Aggregates proof results for an architecture simulation.

```rust
pub struct SimulationCertificate {
    pub architecture: String,      // e.g., "secure_vpc", "k3s_cluster"
    pub proofs: Vec<ProofResult>,  // all invariant proofs
    pub all_passed: bool,          // true iff every proof passed
    pub certificate_hash: String,  // BLAKE3 hex of serialized proofs vector
    pub timestamp: String,         // Unix epoch seconds (e.g., "1712345678s")
}
```

Both types derive `Serialize` and `Deserialize` for JSON serialization.

## Functions

### blake3_hash

```rust
pub fn blake3_hash(content: &[u8]) -> String
```

Computes a BLAKE3 hash and returns the 64-character hex string representation.
BLAKE3 produces 256-bit (32-byte) hashes.

### certify_invariant

```rust
pub fn certify_invariant(
    invariant_name: &str,
    tf_json: &serde_json::Value,
    passed: bool,
    configs_tested: usize,
) -> ProofResult
```

Creates a `ProofResult` with deterministic hashes:
1. Serializes `tf_json` to bytes via `serde_json::to_vec`
2. Computes `input_hash = BLAKE3(serialized_json)`
3. Forms the proof content string: `"{name}:{passed}:{count}:{input_hash}"`
4. Computes `proof_hash = BLAKE3(proof_content)`

This function is deterministic: same inputs always produce the same hashes.

### certify_simulation

```rust
pub fn certify_simulation(
    architecture: &str,
    proofs: Vec<ProofResult>,
) -> SimulationCertificate
```

Creates a `SimulationCertificate`:
1. Sets `all_passed` to true only if every proof has `passed: true`
2. Serializes the proofs vector to bytes
3. Computes `certificate_hash = BLAKE3(serialized_proofs)`
4. Records the current Unix timestamp

Empty proof vectors produce `all_passed: true` (vacuously true) and a valid
certificate hash.

### verify_certificate

```rust
pub fn verify_certificate(cert: &SimulationCertificate) -> bool
```

Recomputes the BLAKE3 hash of `cert.proofs` and compares it to
`cert.certificate_hash`. Returns `true` if they match.

This detects:
- Tampered `certificate_hash` values
- Modified proof results (changed `proof_hash`, `passed`, etc.)
- Added or removed proofs

## Tamper Detection

The certification chain provides three layers of integrity:

1. **Input binding:** `input_hash` ties the proof to the exact Terraform JSON
   that was tested. A different infrastructure configuration produces a
   different hash.

2. **Proof binding:** `proof_hash` ties the proof to its invariant name,
   pass/fail result, and config count. Changing any field changes the hash.

3. **Certificate binding:** `certificate_hash` ties the certificate to the
   exact set of proofs. Adding, removing, or modifying any proof changes the
   certificate hash, causing `verify_certificate()` to return `false`.

## Integration with tameshi

The `certification` feature depends on the `tameshi` crate (path dependency).
tameshi provides multi-layer cryptographic attestation with BLAKE3 Merkle trees.
pangea-sim's `ProofResult` and `SimulationCertificate` can feed into tameshi's
attestation layers for composed infrastructure signatures.

The chain:

```
pangea-sim certification
  -> ProofResult per invariant
    -> SimulationCertificate per architecture
      -> tameshi AttestationLayer (Merkle composition)
        -> sekiban K8s admission webhook (deployment gating)
        -> kensa compliance engine (NIST/OSCAL binding)
```

## Test Coverage (11 tests with `--features certification`)

| Test | What it proves |
|------|----------------|
| `hash_determinism` | Same bytes always produce same BLAKE3 hash |
| `hash_sensitivity` | Different bytes produce different hashes |
| `certify_invariant_deterministic` | Same inputs produce same ProofResult hashes |
| `verify_roundtrip` | certify_simulation -> verify_certificate succeeds |
| `proof_result_has_deterministic_hash` | ProofResult hashing is reproducible |
| `different_inputs_produce_different_hashes` | Different Terraform JSON -> different input_hash |
| `failed_proof_has_different_hash` | passed=true vs passed=false -> different proof_hash |
| `simulation_certificate_integrity` | Multi-proof certificate verifies |
| `tampered_certificate_fails_verification` | Modified certificate_hash -> verify returns false |
| `all_passed_reflects_individual_proofs` | One failed proof -> all_passed is false |
| `empty_proofs_certificate` | Empty proofs -> all_passed true, certificate verifies |
| `certificate_serialization_roundtrip` | JSON serialize -> deserialize preserves certificate_hash |
| `blake3_hash_is_64_hex_chars` | Hash output is exactly 64 hex characters |
| `proof_result_captures_config_count` | configs_tested field is preserved |
| `tampered_proof_breaks_certificate` | Modified proof within certificate -> verify fails |
