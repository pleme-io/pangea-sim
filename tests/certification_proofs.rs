//! Certification proofs -- prove that attestation preserves integrity.

#![cfg(feature = "certification")]

use pangea_sim::certification::{
    blake3_hash, certify_invariant, certify_simulation, verify_certificate, SimulationCertificate,
};

#[test]
fn proof_result_has_deterministic_hash() {
    let tf_json = serde_json::json!({
        "resource": { "aws_vpc": { "test": { "cidr_block": "10.0.0.0/16" }}}
    });

    let proof1 = certify_invariant("NoPublicSsh", &tf_json, true, 1000);
    let proof2 = certify_invariant("NoPublicSsh", &tf_json, true, 1000);

    assert_eq!(
        proof1.proof_hash, proof2.proof_hash,
        "Proof hashing must be deterministic"
    );
    assert_eq!(proof1.input_hash, proof2.input_hash);
}

#[test]
fn different_inputs_produce_different_hashes() {
    let json1 = serde_json::json!({"resource": {"aws_vpc": {}}});
    let json2 = serde_json::json!({"resource": {"aws_s3_bucket": {}}});

    let proof1 = certify_invariant("NoPublicSsh", &json1, true, 100);
    let proof2 = certify_invariant("NoPublicSsh", &json2, true, 100);

    assert_ne!(proof1.input_hash, proof2.input_hash);
}

#[test]
fn failed_proof_has_different_hash() {
    let tf_json = serde_json::json!({"resource": {}});

    let passed = certify_invariant("NoPublicSsh", &tf_json, true, 100);
    let failed = certify_invariant("NoPublicSsh", &tf_json, false, 100);

    assert_ne!(passed.proof_hash, failed.proof_hash);
}

#[test]
fn simulation_certificate_integrity() {
    let tf_json = serde_json::json!({"resource": {}});

    let proofs = vec![
        certify_invariant("NoPublicSsh", &tf_json, true, 1000),
        certify_invariant("AllEbsEncrypted", &tf_json, true, 1000),
        certify_invariant("ImdsV2Required", &tf_json, true, 1000),
    ];

    let cert = certify_simulation("secure_vpc", proofs);
    assert!(cert.all_passed);
    assert!(verify_certificate(&cert));
    assert_eq!(cert.proofs.len(), 3);
}

#[test]
fn tampered_certificate_fails_verification() {
    let tf_json = serde_json::json!({"resource": {}});

    let proofs = vec![certify_invariant("NoPublicSsh", &tf_json, true, 100)];

    let mut cert = certify_simulation("test", proofs);
    cert.certificate_hash = "tampered".to_string();

    assert!(!verify_certificate(&cert));
}

#[test]
fn all_passed_reflects_individual_proofs() {
    let tf_json = serde_json::json!({"resource": {}});

    let proofs = vec![
        certify_invariant("NoPublicSsh", &tf_json, true, 100),
        certify_invariant("AllEbsEncrypted", &tf_json, false, 100), // FAILED
    ];

    let cert = certify_simulation("mixed", proofs);
    assert!(
        !cert.all_passed,
        "Certificate should reflect failed proof"
    );
}

#[test]
fn empty_proofs_certificate() {
    let cert = certify_simulation("empty", vec![]);
    assert!(cert.all_passed); // vacuously true
    assert!(verify_certificate(&cert));
}

#[test]
fn certificate_serialization_roundtrip() {
    let tf_json = serde_json::json!({"resource": {}});
    let proofs = vec![certify_invariant("test", &tf_json, true, 1)];
    let cert = certify_simulation("roundtrip", proofs);

    let json = serde_json::to_string(&cert).unwrap();
    let deserialized: SimulationCertificate = serde_json::from_str(&json).unwrap();

    assert_eq!(cert.certificate_hash, deserialized.certificate_hash);
    assert!(verify_certificate(&deserialized));
}

#[test]
fn blake3_hash_is_64_hex_chars() {
    let hash = blake3_hash(b"test data");
    assert_eq!(hash.len(), 64, "BLAKE3 hex string should be 64 characters");
    assert!(
        hash.chars().all(|c| c.is_ascii_hexdigit()),
        "Hash should be valid hex"
    );
}

#[test]
fn proof_result_captures_config_count() {
    let tf_json = serde_json::json!({"resource": {}});
    let proof = certify_invariant("test", &tf_json, true, 10_000);
    assert_eq!(proof.configs_tested, 10_000);
}

#[test]
fn tampered_proof_breaks_certificate() {
    let tf_json = serde_json::json!({"resource": {}});

    let proofs = vec![
        certify_invariant("NoPublicSsh", &tf_json, true, 100),
        certify_invariant("AllEbsEncrypted", &tf_json, true, 100),
    ];

    let mut cert = certify_simulation("tamper_test", proofs);
    // Tamper with a proof hash inside the certificate
    cert.proofs[0].proof_hash = "aaaa".to_string();

    // Certificate hash was computed over the original proofs, so it
    // should no longer match the (now-tampered) proofs vector.
    assert!(
        !verify_certificate(&cert),
        "Tampered proof should invalidate certificate"
    );
}
