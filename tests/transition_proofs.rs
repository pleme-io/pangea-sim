//! State transition proofs — prove migrations preserve invariants.
//!
//! 21 tests covering:
//! - State diff computation (5 tests)
//! - Transition proofs (5 tests)
//! - Rollback proofs (3 tests)
//! - Migration proofs (5 tests)
//! - Integration with simulations (3 tests)

use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::transitions::{
    compute_diff, prove_rollback, simulate_migration, simulate_transition,
};
use proptest::prelude::*;
use serde_json::{json, Value};

// ── Helpers ─────────────────────────────────────────────────────

/// A compliant Terraform state with required tags and no violations.
fn compliant_state(name: &str, cidr: &str) -> Value {
    json!({
        "resource": {
            "aws_vpc": {
                format!("{name}-vpc"): {
                    "cidr_block": cidr,
                    "enable_dns_support": true,
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_security_group": {
                format!("{name}-sg"): {
                    "name": format!("{name}-sg"),
                    "vpc_id": format!("${{aws_vpc.{name}-vpc.id}}"),
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            }
        }
    })
}

/// A compliant state with an additional subnet resource.
fn compliant_state_with_subnet(name: &str, cidr: &str) -> Value {
    json!({
        "resource": {
            "aws_vpc": {
                format!("{name}-vpc"): {
                    "cidr_block": cidr,
                    "enable_dns_support": true,
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_security_group": {
                format!("{name}-sg"): {
                    "name": format!("{name}-sg"),
                    "vpc_id": format!("${{aws_vpc.{name}-vpc.id}}"),
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_subnet": {
                format!("{name}-private"): {
                    "vpc_id": format!("${{aws_vpc.{name}-vpc.id}}"),
                    "cidr_block": "10.0.1.0/24",
                    "map_public_ip_on_launch": false,
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            }
        }
    })
}

/// A non-compliant state: SSH open to 0.0.0.0/0.
fn non_compliant_state(name: &str) -> Value {
    json!({
        "resource": {
            "aws_vpc": {
                format!("{name}-vpc"): {
                    "cidr_block": "10.0.0.0/16",
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_security_group_rule": {
                format!("{name}-bad-ssh"): {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            }
        }
    })
}

/// Verify a Terraform JSON value passes all invariants.
fn assert_compliant(tf: &Value) {
    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
    assert!(check_all(&refs, tf).is_ok(), "expected compliant state");
}

// ── State Diff Proofs (1-5) ─────────────────────────────────────

/// 1. Identical states produce an empty diff.
#[test]
fn diff_identical_states_is_empty() {
    let state = compliant_state("alpha", "10.0.0.0/16");
    let diff = compute_diff(&state, &state);

    assert!(diff.added_resources.is_empty());
    assert!(diff.removed_resources.is_empty());
    assert!(diff.modified_resources.is_empty());
    assert_eq!(diff.from_hash, diff.to_hash);
}

/// 2. Adding a resource appears in added_resources.
#[test]
fn diff_adding_resource_detected() {
    let from = compliant_state("beta", "10.0.0.0/16");
    let to = compliant_state_with_subnet("beta", "10.0.0.0/16");
    let diff = compute_diff(&from, &to);

    assert!(
        diff.added_resources.contains(&"aws_subnet.beta-private".to_string()),
        "expected aws_subnet.beta-private in added: {:?}",
        diff.added_resources
    );
    assert!(diff.removed_resources.is_empty());
}

/// 3. Removing a resource appears in removed_resources.
#[test]
fn diff_removing_resource_detected() {
    let from = compliant_state_with_subnet("gamma", "10.0.0.0/16");
    let to = compliant_state("gamma", "10.0.0.0/16");
    let diff = compute_diff(&from, &to);

    assert!(
        diff.removed_resources
            .contains(&"aws_subnet.gamma-private".to_string()),
        "expected aws_subnet.gamma-private in removed: {:?}",
        diff.removed_resources
    );
    assert!(diff.added_resources.is_empty());
}

/// 4. Modifying a resource appears in modified_resources.
#[test]
fn diff_modifying_resource_detected() {
    let from = compliant_state("delta", "10.0.0.0/16");
    let to = compliant_state("delta", "10.1.0.0/16"); // changed CIDR

    // The VPC key stays the same but its value differs.
    let diff = compute_diff(&from, &to);

    assert!(
        diff.modified_resources
            .contains(&"aws_vpc.delta-vpc".to_string()),
        "expected aws_vpc.delta-vpc in modified: {:?}",
        diff.modified_resources
    );
    // The SG also changes because the vpc_id ref format stays the same but cidr differs
    // in the VPC. The SG itself should NOT change since its fields are the same.
    assert!(
        !diff.modified_resources
            .contains(&"aws_security_group.delta-sg".to_string()),
        "SG should not be modified when only CIDR changes"
    );
}

/// 5. Diff is deterministic: same inputs always produce the same diff.
#[test]
fn diff_is_deterministic() {
    let from = compliant_state("eps", "10.0.0.0/16");
    let to = compliant_state_with_subnet("eps", "10.0.0.0/16");

    let diff1 = compute_diff(&from, &to);
    let diff2 = compute_diff(&from, &to);

    assert_eq!(diff1.from_hash, diff2.from_hash);
    assert_eq!(diff1.to_hash, diff2.to_hash);
    assert_eq!(diff1.added_resources, diff2.added_resources);
    assert_eq!(diff1.removed_resources, diff2.removed_resources);
    assert_eq!(diff1.modified_resources, diff2.modified_resources);
}

// ── Transition Proofs (6-10) ────────────────────────────────────

// 6. Compliant -> compliant transition preserves invariants (proptest, 500 configs).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn transition_compliant_to_compliant_preserves_invariants(
        name in "[a-z]{3,8}",
        second_octet_from in 0..=255_u8,
        second_octet_to in 0..=255_u8,
    ) {
        let from = compliant_state(&name, &format!("10.{second_octet_from}.0.0/16"));
        let to = compliant_state(&name, &format!("10.{second_octet_to}.0.0/16"));

        let proof = simulate_transition(&from, &to);
        prop_assert!(proof.from_valid, "from state should be valid");
        prop_assert!(proof.to_valid, "to state should be valid");
        prop_assert!(proof.invariants_preserved, "invariants should be preserved");
        prop_assert!(proof.violations.is_empty(), "no violations expected");
    }
}

/// 7. Compliant -> non-compliant transition detects violation.
#[test]
fn transition_compliant_to_non_compliant_detects_violation() {
    let from = compliant_state("zeta", "10.0.0.0/16");
    let to = non_compliant_state("zeta");

    let proof = simulate_transition(&from, &to);
    assert!(proof.from_valid);
    assert!(!proof.to_valid);
    assert!(!proof.invariants_preserved);
    assert!(!proof.violations.is_empty());
}

/// 8. Non-compliant -> compliant transition shows to_valid=true.
#[test]
fn transition_non_compliant_to_compliant_shows_to_valid() {
    let from = non_compliant_state("eta");
    let to = compliant_state("eta", "10.0.0.0/16");

    let proof = simulate_transition(&from, &to);
    assert!(!proof.from_valid);
    assert!(proof.to_valid);
    assert!(!proof.invariants_preserved, "from is invalid so overall not preserved");
}

/// 9. Adding encryption does not break invariants.
#[test]
fn transition_adding_encryption_preserves_invariants() {
    let from = compliant_state("theta", "10.0.0.0/16");

    // Add a launch template with encrypted EBS and IMDSv2
    let to = json!({
        "resource": {
            "aws_vpc": {
                "theta-vpc": {
                    "cidr_block": "10.0.0.0/16",
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_security_group": {
                "theta-sg": {
                    "name": "theta-sg",
                    "vpc_id": "${aws_vpc.theta-vpc.id}",
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            },
            "aws_launch_template": {
                "theta-lt": {
                    "name": "theta-lt",
                    "instance_type": "t3.medium",
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": {
                            "encrypted": true,
                            "volume_size": 50,
                            "volume_type": "gp3"
                        }
                    }],
                    "metadata_options": {
                        "http_tokens": "required",
                        "http_endpoint": "enabled"
                    },
                    "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                }
            }
        }
    });

    assert_compliant(&from);
    assert_compliant(&to);

    let proof = simulate_transition(&from, &to);
    assert!(proof.invariants_preserved);
    assert!(
        proof
            .diff
            .added_resources
            .contains(&"aws_launch_template.theta-lt".to_string())
    );
}

// 10. Adding a resource preserves existing invariants (proptest).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn adding_resource_preserves_invariants(
        name in "[a-z]{3,8}",
        octet in 0..=255_u8,
    ) {
        let from = compliant_state(&name, &format!("10.{octet}.0.0/16"));
        let to = compliant_state_with_subnet(&name, &format!("10.{octet}.0.0/16"));

        let proof = simulate_transition(&from, &to);
        prop_assert!(proof.from_valid);
        prop_assert!(proof.to_valid);
        prop_assert!(proof.invariants_preserved);
    }
}

// ── Rollback Proofs (11-13) ─────────────────────────────────────

// 11. Compliant -> compliant is rollback-safe (proptest, 500 configs).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn rollback_compliant_to_compliant_is_safe(
        name in "[a-z]{3,8}",
        octet in 0..=255_u8,
    ) {
        let from = compliant_state(&name, &format!("10.{octet}.0.0/16"));
        let to = compliant_state_with_subnet(&name, &format!("10.{octet}.0.0/16"));

        let proof = prove_rollback(&from, &to);
        prop_assert!(proof.rollback_safe, "rollback should be safe between compliant states");
        prop_assert!(proof.forward.invariants_preserved);
        prop_assert!(proof.backward.invariants_preserved);
    }
}

/// 12. Compliant -> non-compliant is NOT rollback-safe.
#[test]
fn rollback_compliant_to_non_compliant_is_not_safe() {
    let from = compliant_state("iota", "10.0.0.0/16");
    let to = non_compliant_state("iota");

    let proof = prove_rollback(&from, &to);
    assert!(!proof.rollback_safe);
    // Forward: from is valid, to is not
    assert!(proof.forward.from_valid);
    assert!(!proof.forward.to_valid);
    // Backward: from (the non-compliant) is invalid
    assert!(!proof.backward.from_valid);
    assert!(proof.backward.to_valid);
}

/// 13. Symmetric transitions are always rollback-safe.
#[test]
fn symmetric_transition_is_rollback_safe() {
    let state_a = compliant_state("kappa", "10.0.0.0/16");
    let state_b = compliant_state("kappa", "10.1.0.0/16");

    let proof = prove_rollback(&state_a, &state_b);
    assert!(proof.rollback_safe);

    // Forward and backward should both have the same validity
    assert_eq!(
        proof.forward.invariants_preserved,
        proof.backward.invariants_preserved
    );
}

// ── Migration Proofs (14-18) ────────────────────────────────────

/// 14. Single-step migration = one transition proof.
#[test]
fn migration_single_step() {
    let a = compliant_state("lam", "10.0.0.0/16");
    let b = compliant_state_with_subnet("lam", "10.0.0.0/16");

    let plan = simulate_migration(&[a, b]);
    assert_eq!(plan.steps.len(), 1);
    assert!(plan.all_steps_valid);
}

// 15. Multi-step migration: A -> B -> C, all steps valid (proptest).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]
    #[test]
    fn migration_multi_step_all_valid(
        name in "[a-z]{3,8}",
        octet in 0..=200_u8,
    ) {
        let a = compliant_state(&name, &format!("10.{octet}.0.0/16"));
        let b = compliant_state_with_subnet(&name, &format!("10.{octet}.0.0/16"));
        let c = compliant_state(&name, &format!("10.{}.0.0/16", octet.wrapping_add(1)));

        let plan = simulate_migration(&[a, b, c]);
        prop_assert_eq!(plan.steps.len(), 2);
        prop_assert!(plan.all_steps_valid, "all migration steps should be valid");
    }
}

/// 16. Migration with one bad step detects failure.
#[test]
fn migration_detects_bad_step() {
    let a = compliant_state("mu", "10.0.0.0/16");
    let b_bad = non_compliant_state("mu");
    let c = compliant_state("mu", "10.1.0.0/16");

    let plan = simulate_migration(&[a, b_bad, c]);
    assert_eq!(plan.steps.len(), 2);
    assert!(!plan.all_steps_valid);

    // Step 1 (A->B_bad): to_valid should be false
    assert!(!plan.steps[0].to_valid);
    // Step 2 (B_bad->C): from_valid should be false
    assert!(!plan.steps[1].from_valid);
}

/// 17. Empty migration (fewer than 2 steps) is trivially valid.
#[test]
fn migration_empty_is_trivially_valid() {
    let plan_empty = simulate_migration(&[]);
    assert!(plan_empty.all_steps_valid);
    assert!(plan_empty.steps.is_empty());
    assert_eq!(plan_empty.total_added, 0);

    let plan_single = simulate_migration(&[compliant_state("nu", "10.0.0.0/16")]);
    assert!(plan_single.all_steps_valid);
    assert!(plan_single.steps.is_empty());
}

/// 18. Migration stats aggregate correctly.
#[test]
fn migration_stats_aggregate() {
    let a = compliant_state("xi", "10.0.0.0/16");
    let b = compliant_state_with_subnet("xi", "10.0.0.0/16");
    let c = compliant_state("xi", "10.0.0.0/16"); // same as a, subnet removed

    let plan = simulate_migration(&[a, b, c]);
    assert_eq!(plan.steps.len(), 2);

    // Step 1: added subnet
    assert_eq!(plan.steps[0].diff.added_resources.len(), 1);
    // Step 2: removed subnet
    assert_eq!(plan.steps[1].diff.removed_resources.len(), 1);

    // Totals
    assert_eq!(plan.total_added, 1);
    assert_eq!(plan.total_removed, 1);
}

// ── Integration with Simulations (19-21) ────────────────────────

/// 19. Generate two VPC configs, simulate transition between them.
#[test]
fn integration_vpc_transition() {
    use pangea_sim::simulations::secure_vpc::{SecureVpcConfig, simulate};
    use pangea_sim::simulations::config::Profile;

    let config_a = SecureVpcConfig {
        name: "alpha".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Dev,
        flow_logs: false,
    };

    let config_b = SecureVpcConfig {
        name: "alpha".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string(), "us-east-1b".to_string()],
        profile: Profile::Production,
        flow_logs: true,
    };

    let from = simulate(&config_a);
    let to = simulate(&config_b);

    assert_compliant(&from);
    assert_compliant(&to);

    let proof = simulate_transition(&from, &to);
    assert!(proof.invariants_preserved);
    assert!(proof.from_valid);
    assert!(proof.to_valid);

    // Flow logs added in config_b
    assert!(
        !proof.diff.added_resources.is_empty(),
        "expected added resources for flow logs: {:?}",
        proof.diff
    );
}

/// 20. Generate builder fleet configs at different scales, prove transition safe.
#[test]
fn integration_builder_fleet_scaling_transition() {
    use pangea_sim::simulations::nix_builder_fleet::{NixBuilderFleetConfig, simulate};
    use pangea_sim::simulations::config::Profile;

    let small = NixBuilderFleetConfig {
        name: "builders".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Dev,
        instance_type: "t3.medium".to_string(),
        ami_id: "ami-abc12345".to_string(),
        volume_size: 50,
        fleet_size_min: 1,
        fleet_size_max: 2,
        nix_port: 8080,
    };

    let large = NixBuilderFleetConfig {
        name: "builders".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string(), "us-east-1b".to_string()],
        profile: Profile::Production,
        instance_type: "m5.xlarge".to_string(),
        ami_id: "ami-def67890".to_string(),
        volume_size: 200,
        fleet_size_min: 2,
        fleet_size_max: 8,
        nix_port: 8080,
    };

    let from = simulate(&small);
    let to = simulate(&large);

    assert_compliant(&from);
    assert_compliant(&to);

    let proof = simulate_transition(&from, &to);
    assert!(proof.invariants_preserved);

    // Resources are modified (same keys, different values like instance_type, volume_size)
    assert!(
        !proof.diff.modified_resources.is_empty(),
        "expected modified resources: {:?}",
        proof.diff
    );
}

/// 21. Compliance baseline verification across transitions.
#[test]
fn integration_compliance_across_transition() {
    use pangea_sim::simulations::secure_vpc::{SecureVpcConfig, simulate};
    use pangea_sim::simulations::config::Profile;

    let config_a = SecureVpcConfig {
        name: "compl".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Dev,
        flow_logs: false,
    };

    let config_b = SecureVpcConfig {
        name: "compl".to_string(),
        cidr: "10.1.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Production,
        flow_logs: true,
    };

    let from = simulate(&config_a);
    let to = simulate(&config_b);

    // Both states satisfy all invariants
    let proof = simulate_transition(&from, &to);
    assert!(proof.invariants_preserved);

    // Rollback is also safe
    let rollback = prove_rollback(&from, &to);
    assert!(rollback.rollback_safe);

    // Multi-step migration through both is safe
    let plan = simulate_migration(&[from, to]);
    assert!(plan.all_steps_valid);
    assert_eq!(plan.steps.len(), 1);
}
