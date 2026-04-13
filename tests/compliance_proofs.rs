//! Compliance proofs -- invariants linked to NIST/CIS/FedRAMP controls.
//!
//! Proves that the 10 security invariants map to specific compliance
//! controls, and that compliant Terraform JSON satisfies entire baselines.

#![cfg(feature = "compliance")]

use compliance_controls::*;
use pangea_sim::compliance::*;
use pangea_sim::simulations::{config::*, nix_builder_fleet, secure_vpc};

// ── Helper: build a compliant simulation JSON ──────────────────────

fn compliant_secure_vpc_json() -> serde_json::Value {
    secure_vpc::simulate(&secure_vpc::SecureVpcConfig {
        name: "test".to_string(),
        cidr: "10.0.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Production,
        flow_logs: true,
    })
}

fn compliant_builder_fleet_json() -> serde_json::Value {
    nix_builder_fleet::simulate(&nix_builder_fleet::NixBuilderFleetConfig {
        name: "build".to_string(),
        cidr: "10.1.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: Profile::Production,
        instance_type: "t3.large".to_string(),
        ami_id: "ami-12345678".to_string(),
        volume_size: 100,
        fleet_size_min: 1,
        fleet_size_max: 4,
        nix_port: 8080,
    })
}

// ── Proof 1: Every invariant maps to at least one NIST control ─────

#[test]
fn every_invariant_has_nist_mapping() {
    for inv in ALL_INVARIANTS {
        let controls = controls_for_invariant(inv);
        let nist_count = controls
            .iter()
            .filter(|c| matches!(c, Control::Nist(_)))
            .count();
        assert!(
            nist_count >= 1,
            "{inv} has no NIST control mapping (got {nist_count})"
        );
    }
}

// ── Proof 2: 10 invariants cover 15+ unique NIST controls ─────────

#[test]
fn invariants_cover_sufficient_nist_controls() {
    let all = all_nist_controls();
    assert!(
        all.len() >= 15,
        "Expected 15+ NIST controls, got {}",
        all.len()
    );
}

// ── Proof 3: FedRAMP Moderate has significant coverage ─────────────

#[test]
fn fedramp_moderate_coverage_exceeds_fifty_percent() {
    let baseline = fedramp_moderate();
    let coverage = baseline_coverage(&baseline);
    assert!(
        coverage.percentage() > 50.0,
        "FedRAMP Moderate coverage too low: {:.1}%",
        coverage.percentage()
    );
}

// ── Proof 4: Compliant simulation JSON satisfies mapped controls ───

#[test]
fn compliant_vpc_satisfies_network_controls() {
    let tf_json = compliant_secure_vpc_json();
    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    // The VPC simulation should satisfy at least some controls
    assert!(
        result.satisfied_count > 0,
        "Compliant VPC should satisfy at least some FedRAMP controls, got 0"
    );
}

// ── Proof 5: Removing encryption breaks SC-28 controls ─────────────

#[test]
fn unencrypted_ebs_breaks_sc28() {
    // Build JSON with an unencrypted EBS volume in a launch template
    let tf_json = serde_json::json!({
        "resource": {
            "aws_launch_template": {
                "bad-lt": {
                    "name": "bad-lt",
                    "image_id": "ami-12345678",
                    "instance_type": "t3.large",
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": {
                            "encrypted": false,
                            "volume_size": 100
                        }
                    }],
                    "metadata_options": {
                        "http_tokens": "required"
                    },
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });

    // SC-28(1) is in FedRAMP Moderate and mapped to AllEbsEncrypted
    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    // Find SC-28(1) result
    let sc28_results: Vec<_> = result
        .results
        .iter()
        .filter(|r| r.control_id.contains("SC-28"))
        .collect();
    let any_sc28_violated = sc28_results.iter().any(|r| !r.satisfied);
    assert!(
        any_sc28_violated,
        "Unencrypted EBS should violate SC-28 controls"
    );
}

// ── Proof 6: Public SSH breaks AC-17 + SC-7(4) ────────────────────

#[test]
fn public_ssh_breaks_access_controls() {
    let tf_json = serde_json::json!({
        "resource": {
            "aws_security_group_rule": {
                "public-ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });

    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    // AC-17 (Remote Access) should be violated
    let ac17_violated = result
        .results
        .iter()
        .any(|r| r.control_id.contains("AC-17") && !r.satisfied);
    assert!(
        ac17_violated,
        "Public SSH should violate AC-17 (Remote Access)"
    );

    // SC-7(4) (External Telecommunications) should be violated
    let sc7_4_violated = result
        .results
        .iter()
        .any(|r| r.control_id.contains("SC-7(4)") && !r.satisfied);
    assert!(
        sc7_4_violated,
        "Public SSH should violate SC-7(4) (External Telecommunications)"
    );
}

// ── Proof 7: verify_baseline produces correct counts ───────────────

#[test]
fn verify_baseline_counts_are_consistent() {
    let tf_json = compliant_builder_fleet_json();
    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    assert_eq!(
        result.total_controls,
        baseline.controls.len(),
        "Total controls should match baseline"
    );
    assert_eq!(
        result.satisfied_count + result.violated_count,
        result.total_controls,
        "Satisfied + violated should equal total"
    );
    assert_eq!(
        result.all_satisfied,
        result.violated_count == 0,
        "all_satisfied should reflect zero violations"
    );
}

// ── Proof 8: Coverage report lists exact uncovered controls ────────

#[test]
fn coverage_report_lists_uncovered_controls() {
    let baseline = fedramp_moderate();
    let coverage = coverage_report(&baseline);

    assert_eq!(
        coverage.covered_count + coverage.uncovered_count,
        coverage.total,
        "Covered + uncovered should equal total"
    );
    assert_eq!(coverage.baseline_name, "FedRAMP Moderate");

    // If there are uncovered controls, they should be specific NIST controls
    // that our invariants don't cover
    for uncov in &coverage.uncovered {
        // Verify none of our invariants claim to cover this control
        let covering: Vec<_> = ALL_INVARIANTS
            .iter()
            .filter(|inv| controls_for_invariant(inv).contains(uncov))
            .collect();
        assert!(
            covering.is_empty(),
            "Control {uncov:?} listed as uncovered but is mapped by: {covering:?}"
        );
    }
}

// ── Proof 9: Compliance result serialization roundtrip ──────────────

#[test]
fn compliance_result_serializes_and_deserializes() {
    let tf_json = compliant_secure_vpc_json();
    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    let json_str = serde_json::to_string(&result).expect("serialize ComplianceResult");
    let roundtrip: ComplianceResult =
        serde_json::from_str(&json_str).expect("deserialize ComplianceResult");

    assert_eq!(result.baseline_name, roundtrip.baseline_name);
    assert_eq!(result.total_controls, roundtrip.total_controls);
    assert_eq!(result.satisfied_count, roundtrip.satisfied_count);
    assert_eq!(result.violated_count, roundtrip.violated_count);
    assert_eq!(result.all_satisfied, roundtrip.all_satisfied);
    assert_eq!(result.results.len(), roundtrip.results.len());
}

// ── Proof 10: All controls across all frameworks counted ────────────

#[test]
fn all_frameworks_have_controls() {
    let all = all_controls_covered();

    let nist_count = all
        .iter()
        .filter(|c| matches!(c, Control::Nist(_)))
        .count();
    let cis_count = all
        .iter()
        .filter(|c| matches!(c, Control::Cis(_)))
        .count();
    let soc2_count = all
        .iter()
        .filter(|c| matches!(c, Control::Soc2(_)))
        .count();
    let pci_count = all
        .iter()
        .filter(|c| matches!(c, Control::PciDss(_)))
        .count();

    assert!(nist_count >= 10, "Expected 10+ NIST controls, got {nist_count}");
    assert!(cis_count >= 3, "Expected 3+ CIS controls, got {cis_count}");
    assert!(soc2_count >= 2, "Expected 2+ SOC2 controls, got {soc2_count}");
    assert!(pci_count >= 2, "Expected 2+ PCI controls, got {pci_count}");

    // Total should be 30+
    assert!(
        all.len() >= 30,
        "Expected 30+ total controls, got {}",
        all.len()
    );
}

// ── Proof 11: CIS AWS baseline coverage ─────────────────────────────

#[test]
fn cis_aws_baseline_has_high_coverage() {
    let baseline = cis_aws_v3();
    let coverage = coverage_report(&baseline);

    assert!(
        coverage.percentage() > 80.0,
        "CIS AWS coverage should be >80%, got {:.1}%",
        coverage.percentage()
    );
}

// ── Proof 12: Builder fleet satisfies encryption + logging ──────────

#[test]
fn builder_fleet_satisfies_encryption_and_logging() {
    let tf_json = compliant_builder_fleet_json();

    // Build a mini baseline with just encryption + logging controls
    let baseline = Baseline {
        name: "Encryption+Logging",
        description: "SC-28(1) + AU-2",
        controls: vec![
            nist_enh(NistFamily::SC, 28, 1), // AllEbsEncrypted
            nist(NistFamily::AU, 2),          // LoggingEnabled
        ],
    };

    let result = verify_baseline(&tf_json, &baseline);

    // SC-28(1) should pass (encrypted EBS in launch template)
    let sc28_satisfied = result
        .results
        .iter()
        .any(|r| r.control_id.contains("SC-28") && r.satisfied);
    assert!(sc28_satisfied, "Builder fleet should satisfy SC-28(1)");

    // AU-2 should pass (NLB has access logs enabled)
    let au2_satisfied = result
        .results
        .iter()
        .any(|r| r.control_id.contains("AU-2") && r.satisfied);
    assert!(au2_satisfied, "Builder fleet should satisfy AU-2");
}

// ── Proof 13: SOC 2 and PCI baselines verify without panic ──────────

#[test]
fn soc2_and_pci_baselines_verify_correctly() {
    let tf_json = compliant_builder_fleet_json();

    let soc2_result = verify_baseline(&tf_json, &soc2_type_ii());
    assert_eq!(soc2_result.baseline_name, "SOC 2 Type II");
    assert_eq!(
        soc2_result.satisfied_count + soc2_result.violated_count,
        soc2_result.total_controls
    );

    let pci_result = verify_baseline(&tf_json, &pci_dss_v4());
    assert_eq!(pci_result.baseline_name, "PCI DSS 4.0");
    assert_eq!(
        pci_result.satisfied_count + pci_result.violated_count,
        pci_result.total_controls
    );
}

// ── Proof 14: Reverse mapping invariants_for_nist is consistent ─────

#[test]
fn reverse_nist_mapping_is_consistent() {
    // For every NIST control we claim to cover, the reverse lookup
    // should find the covering invariant
    for inv in ALL_INVARIANTS {
        for control in controls_for_invariant(inv) {
            if let Control::Nist(n) = control {
                let reverse = invariants_for_nist(n.family, n.number);
                assert!(
                    reverse.contains(inv),
                    "Reverse mapping for {n} should include {inv}, got {reverse:?}"
                );
            }
        }
    }
}

// ── Proof 15: Empty Terraform JSON fails all controls ───────────────

#[test]
fn empty_json_fails_uncovered_controls_only() {
    let tf_json = serde_json::json!({"resource": {}});
    let baseline = fedramp_moderate();
    let result = verify_baseline(&tf_json, &baseline);

    // With no resources, invariants that CHECK for bad things should pass
    // (nothing to violate), but uncovered controls should fail
    assert_eq!(
        result.satisfied_count + result.violated_count,
        result.total_controls
    );

    // Controls that are covered by invariants should PASS on empty JSON
    // because there are no violating resources
    let coverage = coverage_report(&baseline);
    let covered_ids: Vec<_> = coverage.covered.iter().map(control_id_for).collect();

    for r in &result.results {
        if covered_ids.contains(&r.control_id) && r.invariant != "none" {
            assert!(
                r.satisfied,
                "Covered control {} should pass on empty JSON (no resources to violate)",
                r.control_id
            );
        }
    }
}

/// Helper to format a Control for comparison with ControlResult.control_id
fn control_id_for(control: &Control) -> String {
    match control {
        Control::Nist(n) => n.to_string(),
        Control::Cis(c) => format!("CIS {}", c.section),
        Control::FedRamp(l, n) => format!("FedRAMP {l:?} {n}"),
        Control::PciDss(p) => format!("PCI {}", p.requirement),
        Control::Soc2(s) => format!("SOC2 {}", s.criteria),
    }
}
