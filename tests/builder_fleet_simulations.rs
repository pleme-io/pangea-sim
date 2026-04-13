//! Builder fleet simulation pipeline proofs.
//!
//! Exercises the FULL simulation engine pipeline:
//! simulate -> Terraform JSON -> ArchitectureAnalysis -> Certification
//!
//! Proves structural correctness, analysis accuracy, and cryptographic
//! certification chain integrity for the nix builder fleet.

use proptest::prelude::*;
use serde_json::Value;

use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::simulations::nix_builder_fleet::{self, NixBuilderFleetConfig, simulate};

// ── Helpers ──────────────────────────────────────────────────────

fn default_config() -> NixBuilderFleetConfig {
    NixBuilderFleetConfig {
        name: "sim-test".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string(), "us-east-1b".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: "t3.medium".to_string(),
        ami_id: "ami-12345678".to_string(),
        volume_size: 100,
        fleet_size_min: 1,
        fleet_size_max: 3,
        nix_port: 22,
    }
}

// ── Simulation produces valid JSON ───────────────────────────────

#[test]
fn simulate_returns_valid_json_with_resource_key() {
    let config = default_config();
    let tf = simulate(&config);
    assert!(
        tf.get("resource").is_some(),
        "simulation output must have 'resource' key"
    );
    assert!(
        tf.get("resource").unwrap().is_object(),
        "'resource' must be a JSON object"
    );
}

#[test]
fn simulate_resource_types_are_objects() {
    let config = default_config();
    let tf = simulate(&config);
    let resources = tf.get("resource").unwrap().as_object().unwrap();
    for (resource_type, instances) in resources {
        assert!(
            instances.is_object(),
            "resource type '{}' instances must be an object",
            resource_type
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Every random config produces valid JSON with resource key.
    #[test]
    fn random_config_produces_valid_json(config in nix_builder_fleet::arb_config()) {
        let tf = simulate(&config);
        prop_assert!(tf.get("resource").is_some());
        prop_assert!(tf["resource"].is_object());
    }
}

// ── JSON structure correctness ───────────────────────────────────

#[test]
fn simulate_vpc_has_correct_cidr() {
    let config = default_config();
    let tf = simulate(&config);
    let vpc = &tf["resource"]["aws_vpc"]["sim-test-vpc"];
    assert_eq!(
        vpc["cidr_block"].as_str().unwrap(),
        "10.0.0.0/16"
    );
}

#[test]
fn simulate_vpc_has_dns_support() {
    let config = default_config();
    let tf = simulate(&config);
    let vpc = &tf["resource"]["aws_vpc"]["sim-test-vpc"];
    assert_eq!(vpc["enable_dns_support"].as_bool(), Some(true));
    assert_eq!(vpc["enable_dns_hostnames"].as_bool(), Some(true));
}

#[test]
fn simulate_launch_template_has_encrypted_ebs() {
    let config = default_config();
    let tf = simulate(&config);
    let lt = &tf["resource"]["aws_launch_template"]["sim-test-lt"];
    let ebs = &lt["block_device_mappings"][0]["ebs"];
    assert_eq!(ebs["encrypted"].as_bool(), Some(true));
    assert_eq!(ebs["volume_size"].as_i64(), Some(100));
    assert_eq!(ebs["volume_type"].as_str(), Some("gp3"));
}

#[test]
fn simulate_launch_template_has_imdsv2() {
    let config = default_config();
    let tf = simulate(&config);
    let lt = &tf["resource"]["aws_launch_template"]["sim-test-lt"];
    assert_eq!(
        lt["metadata_options"]["http_tokens"].as_str(),
        Some("required")
    );
    assert_eq!(
        lt["metadata_options"]["http_endpoint"].as_str(),
        Some("enabled")
    );
}

#[test]
fn simulate_nlb_is_internal_with_access_logs() {
    let config = default_config();
    let tf = simulate(&config);
    let nlb = &tf["resource"]["aws_lb"]["sim-test-nlb"];
    assert_eq!(nlb["internal"].as_bool(), Some(true));
    assert_eq!(nlb["load_balancer_type"].as_str(), Some("network"));
    assert_eq!(nlb["access_logs"]["enabled"].as_bool(), Some(true));
}

#[test]
fn simulate_asg_respects_fleet_size() {
    let config = NixBuilderFleetConfig {
        fleet_size_min: 2,
        fleet_size_max: 5,
        ..default_config()
    };
    let tf = simulate(&config);
    let asg = &tf["resource"]["aws_autoscaling_group"]["sim-test-asg"];
    assert_eq!(asg["min_size"].as_i64(), Some(2));
    assert_eq!(asg["max_size"].as_i64(), Some(5));
    assert_eq!(asg["desired_capacity"].as_i64(), Some(2));
}

#[test]
fn simulate_sg_rules_use_vpc_cidr() {
    let config = NixBuilderFleetConfig {
        cidr: "10.99.0.0/16".to_string(),
        ..default_config()
    };
    let tf = simulate(&config);
    let nix_rule = &tf["resource"]["aws_security_group_rule"]["sim-test-nix-in"];
    let cidrs = nix_rule["cidr_blocks"].as_array().unwrap();
    assert!(
        cidrs.iter().any(|c| c.as_str() == Some("10.99.0.0/16")),
        "SG rule should use the VPC CIDR"
    );
}

#[test]
fn simulate_target_group_uses_nix_port() {
    for port in [22u16, 8080] {
        let config = NixBuilderFleetConfig {
            nix_port: port,
            ..default_config()
        };
        let tf = simulate(&config);
        let tg = &tf["resource"]["aws_lb_target_group"]["sim-test-tg"];
        assert_eq!(
            tg["port"].as_u64(),
            Some(u64::from(port)),
            "target group port should match nix_port"
        );
    }
}

#[test]
fn simulate_all_resources_have_required_tags() {
    let config = default_config();
    let tf = simulate(&config);
    let resources = tf["resource"].as_object().unwrap();
    for (rtype, instances) in resources {
        for (rname, rconfig) in instances.as_object().unwrap() {
            let tags = rconfig.get("tags").and_then(Value::as_object);
            assert!(
                tags.is_some(),
                "resource {rtype}.{rname} has no tags"
            );
            let tags = tags.unwrap();
            assert!(
                tags.contains_key("ManagedBy"),
                "resource {rtype}.{rname} missing ManagedBy tag"
            );
            assert!(
                tags.contains_key("Purpose"),
                "resource {rtype}.{rname} missing Purpose tag"
            );
        }
    }
}

// ── ArchitectureAnalysis correctness ─────────────────────────────

#[test]
fn analysis_extracts_correct_resource_count() {
    let config = default_config();
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
    // VPC(1) + SG(1) + SG rules(2) + LT(1) + ASG(1) + NLB(1) + TG(1) + Listener(1) = 9
    assert_eq!(analysis.resource_count, 9);
}

#[test]
fn analysis_extracts_correct_resource_types() {
    let config = default_config();
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);

    assert_eq!(analysis.resources_by_type["aws_vpc"], 1);
    assert_eq!(analysis.resources_by_type["aws_security_group"], 1);
    assert_eq!(analysis.resources_by_type["aws_security_group_rule"], 2);
    assert_eq!(analysis.resources_by_type["aws_launch_template"], 1);
    assert_eq!(analysis.resources_by_type["aws_autoscaling_group"], 1);
    assert_eq!(analysis.resources_by_type["aws_lb"], 1);
    assert_eq!(analysis.resources_by_type["aws_lb_target_group"], 1);
    assert_eq!(analysis.resources_by_type["aws_lb_listener"], 1);
}

#[test]
fn analysis_has_resource_queries() {
    let config = default_config();
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);

    assert!(analysis.has_resource("aws_vpc", 1));
    assert!(!analysis.has_resource("aws_vpc", 2));
    assert!(analysis.has_resource("aws_security_group_rule", 2));
    assert!(!analysis.has_resource("aws_rds_cluster", 1));
}

#[test]
fn analysis_finds_cross_references() {
    let config = default_config();
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);

    // The fleet uses many cross-references: vpc_id, sg_id, lt_id, tg_arn, nlb_arn
    assert!(
        analysis.cross_references.len() >= 5,
        "expected at least 5 cross-references, got {}",
        analysis.cross_references.len()
    );
}

#[test]
fn analysis_no_data_sources() {
    let config = default_config();
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
    assert_eq!(analysis.data_source_count, 0);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Analysis is deterministic across all random configs.
    #[test]
    fn analysis_deterministic_on_random_config(config in nix_builder_fleet::arb_config()) {
        let tf = simulate(&config);
        let a1 = ArchitectureAnalysis::from_terraform_json(&tf);
        let a2 = ArchitectureAnalysis::from_terraform_json(&tf);
        prop_assert_eq!(a1.resource_count, a2.resource_count);
        prop_assert_eq!(a1.resources_by_type, a2.resources_by_type);
        prop_assert_eq!(a1.data_source_count, a2.data_source_count);
        prop_assert_eq!(a1.cross_references.len(), a2.cross_references.len());
    }
}

// ── Serialization round-trip ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Simulation JSON survives serialization round-trip.
    #[test]
    fn json_serialization_round_trip(config in nix_builder_fleet::arb_config()) {
        let tf = simulate(&config);
        let serialized = serde_json::to_string(&tf).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();
        prop_assert_eq!(&tf, &deserialized);
    }
}

// ── Full pipeline: simulate -> analyze -> check invariants ───────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Full pipeline proof: simulate, analyze, check invariants, all pass.
    #[test]
    fn full_pipeline_proof(config in nix_builder_fleet::arb_config()) {
        // Step 1: Simulate
        let tf = simulate(&config);
        prop_assert!(tf.get("resource").is_some());

        // Step 2: Analyze
        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        prop_assert!(analysis.resource_count >= 9);
        prop_assert!(analysis.has_resource("aws_vpc", 1));
        prop_assert!(analysis.has_resource("aws_lb", 1));

        // Step 3: Check all invariants
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(check_all(&refs, &tf).is_ok());
    }
}

// ── Certification chain (feature-gated) ──────────────────────────

#[cfg(feature = "certification")]
mod certification_tests {
    use super::*;
    use pangea_sim::certification::{
        blake3_hash, certify_invariant, certify_simulation, verify_certificate,
    };

    #[test]
    fn certify_each_invariant_on_builder_fleet() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        for inv in &invs {
            let passed = inv.check(&tf).is_ok();
            assert!(passed, "invariant {} must pass", inv.name());

            let proof = certify_invariant(inv.name(), &tf, passed, 1);
            assert!(proof.passed);
            assert!(!proof.input_hash.is_empty());
            assert!(!proof.proof_hash.is_empty());
            assert_eq!(proof.configs_tested, 1);
        }
    }

    #[test]
    fn certify_full_simulation_certificate() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        let proofs: Vec<_> = invs
            .iter()
            .map(|inv| {
                let passed = inv.check(&tf).is_ok();
                certify_invariant(inv.name(), &tf, passed, 1000)
            })
            .collect();

        let cert = certify_simulation("nix_builder_fleet", proofs);
        assert!(cert.all_passed);
        assert_eq!(cert.proofs.len(), 10);
        assert_eq!(cert.architecture, "nix_builder_fleet");
        assert!(!cert.certificate_hash.is_empty());
    }

    #[test]
    fn verify_builder_fleet_certificate() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        let proofs: Vec<_> = invs
            .iter()
            .map(|inv| certify_invariant(inv.name(), &tf, inv.check(&tf).is_ok(), 500))
            .collect();

        let cert = certify_simulation("nix_builder_fleet", proofs);
        assert!(
            verify_certificate(&cert),
            "certificate verification failed"
        );
    }

    #[test]
    fn tamper_detection_on_builder_fleet_certificate() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        let proofs: Vec<_> = invs
            .iter()
            .map(|inv| certify_invariant(inv.name(), &tf, true, 100))
            .collect();

        // Tamper with certificate hash
        let mut cert = certify_simulation("nix_builder_fleet", proofs);
        cert.certificate_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(
            !verify_certificate(&cert),
            "tampered certificate should fail verification"
        );
    }

    #[test]
    fn tamper_detection_on_proof_within_certificate() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        let proofs: Vec<_> = invs
            .iter()
            .map(|inv| certify_invariant(inv.name(), &tf, true, 100))
            .collect();

        let mut cert = certify_simulation("nix_builder_fleet", proofs);
        // Tamper with a proof inside the certificate
        cert.proofs[0].passed = false;
        assert!(
            !verify_certificate(&cert),
            "tampering with individual proof should invalidate certificate"
        );
    }

    #[test]
    fn certificate_determinism() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();

        let make_proofs = || {
            invs.iter()
                .map(|inv| certify_invariant(inv.name(), &tf, true, 100))
                .collect::<Vec<_>>()
        };

        let cert1 = certify_simulation("nix_builder_fleet", make_proofs());
        let cert2 = certify_simulation("nix_builder_fleet", make_proofs());

        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
        assert_eq!(cert1.all_passed, cert2.all_passed);
        for (p1, p2) in cert1.proofs.iter().zip(cert2.proofs.iter()) {
            assert_eq!(p1.proof_hash, p2.proof_hash);
            assert_eq!(p1.input_hash, p2.input_hash);
        }
    }

    #[test]
    fn certificate_input_hash_changes_with_config() {
        let config1 = default_config();
        let config2 = NixBuilderFleetConfig {
            name: "other-fleet".to_string(),
            cidr: "10.99.0.0/16".to_string(),
            ..default_config()
        };

        let tf1 = simulate(&config1);
        let tf2 = simulate(&config2);

        let proof1 = certify_invariant("no_public_ssh", &tf1, true, 100);
        let proof2 = certify_invariant("no_public_ssh", &tf2, true, 100);

        assert_ne!(
            proof1.input_hash, proof2.input_hash,
            "different configs must produce different input hashes"
        );
    }

    #[test]
    fn blake3_hash_of_simulation_output_is_64_hex() {
        let config = default_config();
        let tf = simulate(&config);
        let bytes = serde_json::to_vec(&tf).unwrap();
        let hash = blake3_hash(&bytes);
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        /// Full certification pipeline over random configs.
        #[test]
        fn full_certification_pipeline(config in nix_builder_fleet::arb_config()) {
            let tf = simulate(&config);
            let invs = all_invariants();

            let proofs: Vec<_> = invs
                .iter()
                .map(|inv| {
                    let passed = inv.check(&tf).is_ok();
                    certify_invariant(inv.name(), &tf, passed, 1)
                })
                .collect();

            let cert = certify_simulation("nix_builder_fleet", proofs);
            prop_assert!(cert.all_passed);
            prop_assert!(verify_certificate(&cert));
            prop_assert_eq!(cert.proofs.len(), 10);
        }
    }
}
