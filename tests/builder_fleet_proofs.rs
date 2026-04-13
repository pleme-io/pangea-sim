//! Builder fleet variant/invariant proofs.
//!
//! Every configuration variant of the nix builder fleet satisfies
//! ALL 10 security invariants. Proven via proptest over 1000+ random
//! configurations per dimension.
//!
//! Unlike the generic `architecture_invariants.rs` which uses a macro
//! across all architectures with 500 cases, these tests are dedicated
//! to the builder fleet and exercise EVERY config dimension individually,
//! verify each invariant by name, and prove composition preserves invariants.

use proptest::prelude::*;
use serde_json::Value;

use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::simulations::composed;
use pangea_sim::simulations::nix_builder_fleet::{self, NixBuilderFleetConfig, simulate};

// ── Helpers ──────────────────────────────────────────────────────

/// Build a fleet config with explicit values for targeted testing.
fn fleet_config(
    name: &str,
    cidr: &str,
    instance_type: &str,
    ami_id: &str,
    volume_size: i64,
    min: i64,
    max: i64,
    nix_port: u16,
) -> NixBuilderFleetConfig {
    NixBuilderFleetConfig {
        name: name.to_string(),
        cidr: cidr.to_string(),
        azs: vec!["us-east-1a".to_string(), "us-east-1b".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: instance_type.to_string(),
        ami_id: ami_id.to_string(),
        volume_size,
        fleet_size_min: min,
        fleet_size_max: max,
        nix_port,
    }
}

fn assert_all_invariants(tf: &Value) {
    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
    assert!(
        check_all(&refs, tf).is_ok(),
        "invariant violation in builder fleet simulation"
    );
}

// ── Per-invariant proofs over random configs ─────────────────────

macro_rules! prove_single_invariant {
    ($test_name:ident, $invariant_idx:expr, $invariant_name:expr) => {
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(1000))]
            #[test]
            fn $test_name(config in nix_builder_fleet::arb_config()) {
                let tf = simulate(&config);
                let invs = all_invariants();
                let inv = &invs[$invariant_idx];
                assert_eq!(inv.name(), $invariant_name);
                prop_assert!(
                    inv.check(&tf).is_ok(),
                    "invariant {} violated on builder fleet config: {:?}",
                    $invariant_name,
                    config
                );
            }
        }
    };
}

prove_single_invariant!(no_public_ssh_holds, 0, "no_public_ssh");
prove_single_invariant!(all_ebs_encrypted_holds, 1, "all_ebs_encrypted");
prove_single_invariant!(imdsv2_required_holds, 2, "imdsv2_required");
prove_single_invariant!(no_public_s3_holds, 3, "no_public_s3");
prove_single_invariant!(iam_least_privilege_holds, 4, "iam_least_privilege");
prove_single_invariant!(no_default_vpc_usage_holds, 5, "no_default_vpc_usage");
prove_single_invariant!(all_subnets_private_holds, 6, "all_subnets_private");
prove_single_invariant!(encryption_at_rest_holds, 7, "encryption_at_rest");
prove_single_invariant!(logging_enabled_holds, 8, "logging_enabled");
prove_single_invariant!(tagging_complete_holds, 9, "tagging_complete");

// ── Architecture variant proofs: aarch64 instance types ──────────

#[test]
fn aarch64_c7g_medium_satisfies_all_invariants() {
    let config = fleet_config("arm-med", "10.0.0.0/16", "c7g.medium", "ami-arm64test", 100, 1, 3, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn aarch64_c7g_large_satisfies_all_invariants() {
    let config = fleet_config("arm-lg", "10.1.0.0/16", "c7g.large", "ami-arm64test", 200, 2, 5, 8080);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn aarch64_c7g_xlarge_satisfies_all_invariants() {
    let config = fleet_config("arm-xl", "10.2.0.0/16", "c7g.xlarge", "ami-arm64test", 500, 1, 8, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── Architecture variant proofs: x86_64 instance types ───────────

#[test]
fn x86_64_c6i_large_satisfies_all_invariants() {
    let config = fleet_config("x86-lg", "10.3.0.0/16", "c6i.large", "ami-x86test01", 100, 1, 4, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn x86_64_c6i_xlarge_satisfies_all_invariants() {
    let config = fleet_config("x86-xl", "10.4.0.0/16", "c6i.xlarge", "ami-x86test01", 300, 2, 8, 8080);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── Fleet size variant proofs ────────────────────────────────────

#[test]
fn fleet_size_min_1_max_1() {
    let config = fleet_config("fleet-1", "10.10.0.0/16", "t3.medium", "ami-12345678", 50, 1, 1, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn fleet_size_min_2_max_5() {
    let config = fleet_config("fleet-25", "10.11.0.0/16", "t3.large", "ami-12345678", 100, 2, 5, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn fleet_size_min_1_max_8() {
    let config = fleet_config("fleet-18", "10.12.0.0/16", "m5.xlarge", "ami-12345678", 200, 1, 8, 8080);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── Port variant proofs ──────────────────────────────────────────

#[test]
fn nix_port_22_satisfies_invariants() {
    let config = fleet_config("port-22", "10.20.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn nix_port_8080_satisfies_invariants() {
    let config = fleet_config("port-8080", "10.21.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 2, 8080);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── CIDR variant proofs ──────────────────────────────────────────

#[test]
fn cidr_10_0_satisfies_invariants() {
    let config = fleet_config("cidr-10", "10.0.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn cidr_10_100_satisfies_invariants() {
    let config = fleet_config("cidr-100", "10.100.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn cidr_10_255_satisfies_invariants() {
    let config = fleet_config("cidr-255", "10.255.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── Volume size variant proofs ───────────────────────────────────

#[test]
fn volume_size_20gb_satisfies_invariants() {
    let config = fleet_config("vol-20", "10.30.0.0/16", "t3.medium", "ami-abcdef12", 20, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn volume_size_500gb_satisfies_invariants() {
    let config = fleet_config("vol-500", "10.31.0.0/16", "t3.medium", "ami-abcdef12", 500, 1, 2, 22);
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── AMI ID variant proofs ────────────────────────────────────────

#[test]
fn different_ami_ids_satisfy_invariants() {
    for ami in &["ami-00000001", "ami-ffffffff", "ami-a1b2c3d4", "ami-nixos001"] {
        let config = fleet_config("ami-test", "10.40.0.0/16", "t3.medium", ami, 100, 1, 2, 22);
        let tf = simulate(&config);
        assert_all_invariants(&tf);
    }
}

// ── Profile variant proofs ───────────────────────────────────────

#[test]
fn dev_profile_satisfies_invariants() {
    let config = NixBuilderFleetConfig {
        name: "dev-fleet".to_string(),
        cidr: "10.50.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: pangea_sim::simulations::config::Profile::Dev,
        instance_type: "t3.medium".to_string(),
        ami_id: "ami-devtest01".to_string(),
        volume_size: 100,
        fleet_size_min: 1,
        fleet_size_max: 2,
        nix_port: 22,
    };
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

#[test]
fn production_profile_satisfies_invariants() {
    let config = NixBuilderFleetConfig {
        name: "prod-fleet".to_string(),
        cidr: "10.51.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string(), "us-east-1b".to_string(), "us-east-1c".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: "m5.xlarge".to_string(),
        ami_id: "ami-prodtest1".to_string(),
        volume_size: 300,
        fleet_size_min: 2,
        fleet_size_max: 8,
        nix_port: 8080,
    };
    let tf = simulate(&config);
    assert_all_invariants(&tf);
}

// ── Composition variant proofs ───────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Composed BuilderInfra (VPC + builders + VPN + DNS + encryption)
    /// preserves all invariants across random configs.
    #[test]
    fn builder_infra_composition_preserves_all_invariants(config in composed::arb_builder_infra()) {
        let tf = composed::simulate_builder_infra(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(
            check_all(&refs, &tf).is_ok(),
            "BuilderInfra composition violated invariants"
        );
    }

    /// Composed BuilderInfra has cross-references between components.
    #[test]
    fn builder_infra_composition_has_cross_references(config in composed::arb_builder_infra()) {
        let tf = composed::simulate_builder_infra(&config);
        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        // A composed system with VPC + builders + VPN + DNS + encryption
        // must have cross-references (e.g., vpc_id references).
        prop_assert!(
            !analysis.cross_references.is_empty(),
            "composed system should have cross-references"
        );
    }
}

// ── Determinism proofs ───────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Same builder fleet config produces identical JSON across 5 runs.
    #[test]
    fn builder_fleet_deterministic_5_runs(config in nix_builder_fleet::arb_config()) {
        let first = simulate(&config);
        for _ in 0..4 {
            let again = simulate(&config);
            prop_assert_eq!(
                &first, &again,
                "builder fleet simulation is not deterministic"
            );
        }
    }
}

#[test]
fn specific_config_deterministic_across_runs() {
    let config = fleet_config("det-test", "10.60.0.0/16", "c5.large", "ami-det12345", 150, 1, 4, 22);
    let results: Vec<Value> = (0..5).map(|_| simulate(&config)).collect();
    for i in 1..results.len() {
        assert_eq!(
            results[0], results[i],
            "run 0 differs from run {i}"
        );
    }
}

// ── Resource structure proofs ────────────────────────────────────

#[test]
fn builder_fleet_contains_expected_resource_types() {
    let config = fleet_config("res-test", "10.70.0.0/16", "t3.medium", "ami-abcdef12", 100, 1, 3, 22);
    let tf = simulate(&config);
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf);

    // Builder fleet must produce: VPC, SG, SG rules, launch template, ASG, NLB, target group, listener
    assert!(analysis.has_resource("aws_vpc", 1), "missing VPC");
    assert!(analysis.has_resource("aws_security_group", 1), "missing security group");
    assert!(analysis.has_resource("aws_security_group_rule", 1), "missing SG rules");
    assert!(analysis.has_resource("aws_launch_template", 1), "missing launch template");
    assert!(analysis.has_resource("aws_autoscaling_group", 1), "missing ASG");
    assert!(analysis.has_resource("aws_lb", 1), "missing NLB");
    assert!(analysis.has_resource("aws_lb_target_group", 1), "missing target group");
    assert!(analysis.has_resource("aws_lb_listener", 1), "missing listener");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Every random config produces at least 8 resources (the minimum set).
    #[test]
    fn builder_fleet_minimum_resource_count(config in nix_builder_fleet::arb_config()) {
        let tf = simulate(&config);
        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        // VPC + SG + 2 SG rules + LT + ASG + NLB + TG + listener = 9 resources
        prop_assert!(
            analysis.resource_count >= 9,
            "only {} resources (expected >= 9)",
            analysis.resource_count
        );
    }

    /// Builder fleet always has cross-references (VPC→SG→LT→ASG chain).
    #[test]
    fn builder_fleet_has_cross_references(config in nix_builder_fleet::arb_config()) {
        let tf = simulate(&config);
        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        prop_assert!(
            !analysis.cross_references.is_empty(),
            "builder fleet should have cross-references"
        );
    }
}

// ── Invariant exhaustiveness proof ───────────────────────────────

#[test]
fn all_ten_invariants_checked_on_builder_fleet() {
    let config = fleet_config("exhaust", "10.80.0.0/16", "t3.medium", "ami-12345678", 100, 1, 2, 22);
    let tf = simulate(&config);
    let invs = all_invariants();
    assert_eq!(invs.len(), 10, "expected exactly 10 invariants");

    let expected_names = [
        "no_public_ssh",
        "all_ebs_encrypted",
        "imdsv2_required",
        "no_public_s3",
        "iam_least_privilege",
        "no_default_vpc_usage",
        "all_subnets_private",
        "encryption_at_rest",
        "logging_enabled",
        "tagging_complete",
    ];

    for (i, inv) in invs.iter().enumerate() {
        assert_eq!(inv.name(), expected_names[i]);
        assert!(
            inv.check(&tf).is_ok(),
            "invariant {} failed on builder fleet",
            inv.name()
        );
    }
}
