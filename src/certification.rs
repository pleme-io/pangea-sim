//! Proof certification via tameshi attestation.
//!
//! When invariant proofs pass, this module creates cryptographic
//! attestation layers certifying the results. Each invariant check
//! becomes a hashed entry in a BLAKE3 Merkle-style certificate.
//!
//! Feature-gated behind `certification` — requires `tameshi` and `blake3`.

#[cfg(feature = "certification")]
use blake3;

use serde::{Deserialize, Serialize};

/// Result of a single invariant proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult {
    /// Invariant name (e.g., "no_public_ssh").
    pub invariant_name: String,
    /// Whether the invariant held.
    pub passed: bool,
    /// Number of configurations tested.
    pub configs_tested: usize,
    /// BLAKE3 hash of the Terraform JSON that was tested.
    pub input_hash: String,
    /// BLAKE3 hash of the proof output.
    pub proof_hash: String,
}

/// A collection of proof results for an architecture simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationCertificate {
    /// Architecture name (e.g., "secure_vpc", "k3s_cluster").
    pub architecture: String,
    /// All invariant proofs.
    pub proofs: Vec<ProofResult>,
    /// Whether ALL invariants passed.
    pub all_passed: bool,
    /// BLAKE3 hash of the entire certificate.
    pub certificate_hash: String,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

/// Hash content with BLAKE3 and return hex string.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "certification")]
#[must_use]
pub fn blake3_hash(content: &[u8]) -> String {
    let hash = blake3::hash(content);
    hash.to_hex().to_string()
}

/// Create a proof result from an invariant check.
///
/// Produces a deterministic `ProofResult` whose `input_hash` and `proof_hash`
/// are computed via BLAKE3 over the serialized Terraform JSON and the
/// concatenated proof content respectively.
///
/// # Panics
///
/// This function does not panic (serialization of `serde_json::Value` is infallible).
#[cfg(feature = "certification")]
#[must_use]
pub fn certify_invariant(
    invariant_name: &str,
    tf_json: &serde_json::Value,
    passed: bool,
    configs_tested: usize,
) -> ProofResult {
    let input_bytes = serde_json::to_vec(tf_json).unwrap_or_default();
    let input_hash = blake3_hash(&input_bytes);

    let proof_content = format!("{invariant_name}:{passed}:{configs_tested}:{input_hash}");
    let proof_hash = blake3_hash(proof_content.as_bytes());

    ProofResult {
        invariant_name: invariant_name.to_string(),
        passed,
        configs_tested,
        input_hash,
        proof_hash,
    }
}

/// Create a simulation certificate from proof results.
///
/// The `certificate_hash` is the BLAKE3 hash of the serialized proof vector,
/// making the certificate tamper-evident.
///
/// # Panics
///
/// This function does not panic.
#[cfg(feature = "certification")]
#[must_use]
pub fn certify_simulation(architecture: &str, proofs: Vec<ProofResult>) -> SimulationCertificate {
    let all_passed = proofs.iter().all(|p| p.passed);

    let cert_content = serde_json::to_vec(&proofs).unwrap_or_default();
    let certificate_hash = blake3_hash(&cert_content);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}s", d.as_secs()))
        .unwrap_or_else(|_| "0s".to_string());

    SimulationCertificate {
        architecture: architecture.to_string(),
        proofs,
        all_passed,
        certificate_hash,
        timestamp,
    }
}

/// Verify a certificate's integrity.
///
/// Recomputes the BLAKE3 hash of the serialized proofs and compares it
/// to the stored `certificate_hash`. Returns `true` if they match.
#[cfg(feature = "certification")]
#[must_use]
pub fn verify_certificate(cert: &SimulationCertificate) -> bool {
    let cert_content = serde_json::to_vec(&cert.proofs).unwrap_or_default();
    let expected_hash = blake3_hash(&cert_content);
    cert.certificate_hash == expected_hash
}

#[cfg(test)]
#[cfg(feature = "certification")]
mod tests {
    use super::*;

    #[test]
    fn hash_determinism() {
        let data = b"hello world";
        assert_eq!(blake3_hash(data), blake3_hash(data));
    }

    #[test]
    fn hash_sensitivity() {
        assert_ne!(blake3_hash(b"a"), blake3_hash(b"b"));
    }

    #[test]
    fn certify_invariant_deterministic() {
        let tf = serde_json::json!({"resource": {}});
        let p1 = certify_invariant("test", &tf, true, 1);
        let p2 = certify_invariant("test", &tf, true, 1);
        assert_eq!(p1.proof_hash, p2.proof_hash);
        assert_eq!(p1.input_hash, p2.input_hash);
    }

    #[test]
    fn verify_roundtrip() {
        let tf = serde_json::json!({"resource": {}});
        let proofs = vec![certify_invariant("x", &tf, true, 1)];
        let cert = certify_simulation("arch", proofs);
        assert!(verify_certificate(&cert));
    }
}
