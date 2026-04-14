//! quero.lol platform proofs — 40+ tests proving the full platform.
//!
//! Categories:
//! - Platform simulation proofs (1-6)
//! - Process model proofs (7-15)
//! - Composition proofs (16-17)
//! - Compliance proofs (18-19) [feature-gated]
//! - Transition proofs (20-21)
//! - Certification proof (22) [feature-gated]

use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::process_model::*;
use pangea_sim::simulations::quero_platform::{self, QueroPlatformConfig};
use proptest::prelude::*;

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

fn default_config() -> QueroPlatformConfig {
    QueroPlatformConfig {
        domain: "quero.lol".to_string(),
        vpc_cidr: "10.0.0.0/16".to_string(),
        builder_aarch64_count: 2,
        builder_x86_count: 2,
        enable_cache: true,
        enable_seph: true,
    }
}

fn v2_config() -> QueroPlatformConfig {
    QueroPlatformConfig {
        domain: "quero.lol".to_string(),
        vpc_cidr: "10.0.0.0/16".to_string(),
        builder_aarch64_count: 2,
        builder_x86_count: 4, // added x86 builders
        enable_cache: true,
        enable_seph: true,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Platform simulation proofs (1-6)
// ═══════════════════════════════════════════════════════════════════

// ── Proof 1: quero platform passes ALL 10 Terraform invariants ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_01_quero_platform_all_invariants(config in quero_platform::arb_config()) {
        let tf = quero_platform::simulate(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(
            check_all(&refs, &tf).is_ok(),
            "quero platform must pass all 10 invariants"
        );
    }
}

// ── Proof 2: platform has correct resource types ──────────────────

#[test]
fn proof_02_platform_has_correct_resource_types() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);
    let a = ArchitectureAnalysis::from_terraform_json(&tf);

    assert!(a.has_resource("aws_vpc", 1), "must have VPC");
    assert!(
        a.has_resource("aws_security_group", 1),
        "must have security group"
    );
    assert!(
        a.has_resource("aws_autoscaling_group", 2),
        "must have 2 ASGs"
    );
    assert!(a.has_resource("aws_lb", 2), "must have 2+ NLBs");
    assert!(
        a.has_resource("aws_route53_zone", 2),
        "must have 2 Route53 zones"
    );
    assert!(a.has_resource("aws_iam_role", 1), "must have IAM role");
    assert!(
        a.has_resource("aws_launch_template", 2),
        "must have 2+ launch templates"
    );
}

// ── Proof 3: DNS records for builder subdomains ───────────────────

#[test]
fn proof_03_dns_records_for_builder_subdomains() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let records = tf
        .pointer("/resource/aws_route53_record")
        .and_then(|v| v.as_object())
        .expect("must have Route53 records");

    let record_names: Vec<String> = records
        .values()
        .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();

    assert!(
        record_names
            .iter()
            .any(|n| n.contains("aarch64.builder")),
        "must have aarch64 builder DNS record"
    );
    assert!(
        record_names.iter().any(|n| n.contains("x86.builder")),
        "must have x86 builder DNS record"
    );
}

// ── Proof 4: split-horizon DNS ────────────────────────────────────

#[test]
fn proof_04_split_horizon_dns_zones() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let zones = tf
        .pointer("/resource/aws_route53_zone")
        .and_then(|v| v.as_object())
        .expect("must have Route53 zones");

    assert!(
        zones.contains_key("quero-public-zone"),
        "must have public zone"
    );
    assert!(
        zones.contains_key("quero-private-zone"),
        "must have private zone"
    );

    // Private zone must be bound to VPC
    let private = &zones["quero-private-zone"];
    assert!(
        private.get("vpc").is_some(),
        "private zone must be VPC-bound"
    );
}

// ── Proof 5: deterministic output ─────────────────────────────────

#[test]
fn proof_05_platform_is_deterministic() {
    let config = default_config();
    for _ in 0..5 {
        let tf1 = quero_platform::simulate(&config);
        let tf2 = quero_platform::simulate(&config);
        assert_eq!(tf1, tf2, "simulation must be deterministic");
    }
}

// ── Proof 6: analysis has 15+ resources ───────────────────────────

#[test]
fn proof_06_platform_has_sufficient_resources() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);
    let a = ArchitectureAnalysis::from_terraform_json(&tf);

    assert!(
        a.resource_count >= 15,
        "must have 15+ resources, got {}",
        a.resource_count
    );
    assert!(
        a.resources_by_type.len() >= 8,
        "must have 8+ resource types, got {}",
        a.resources_by_type.len()
    );
}

// ═══════════════════════════════════════════════════════════════════
// Process model proofs (7-15)
// ═══════════════════════════════════════════════════════════════════

// ── Proof 7: quero tree has 7 processes ───────────────────────────

#[test]
fn proof_07_quero_tree_has_seven_processes() {
    let tree = quero_process_tree();
    let count = count_processes(&tree);
    assert_eq!(count, 7, "quero platform has 7 processes");
}

// ── Proof 8: all PIDs unique ──────────────────────────────────────

#[test]
fn proof_08_all_pids_unique() {
    let tree = quero_process_tree();
    assert!(
        check_unique_pids(&tree).is_ok(),
        "all PIDs must be unique"
    );
}

// ── Proof 9: no orphan processes ──────────────────────────────────

#[test]
fn proof_09_no_orphans() {
    let tree = quero_process_tree();
    assert!(
        check_no_orphans(&tree).is_ok(),
        "no processes should be orphaned"
    );
}

// ── Proof 10: all processes have DNS identity ─────────────────────

#[test]
fn proof_10_all_have_dns() {
    let tree = quero_process_tree();
    assert!(
        check_all_have_dns(&tree).is_ok(),
        "every process must have DNS identity"
    );
}

// ── Proof 11: DNS pattern matches backend type ────────────────────

#[test]
fn proof_11_dns_pattern_matches_backend() {
    let tree = quero_process_tree();
    assert!(
        check_backend_dns_pattern(&tree).is_ok(),
        "DNS patterns must match backend types"
    );
}

// ── Proof 12: serialization roundtrip ─────────────────────────────

#[test]
fn proof_12_serialization_roundtrip() {
    let tree = quero_process_tree();
    let json = serde_json::to_string(&tree).expect("must serialize");
    let deserialized: ProcessTree = serde_json::from_str(&json).expect("must deserialize");
    assert_eq!(tree, deserialized, "roundtrip must preserve data");
}

// ── Proof 13: random trees satisfy invariants (proptest) ──────────

fn arb_process_backend() -> impl Strategy<Value = ProcessBackend> {
    prop_oneof![
        (Just("seph".to_string()), Just("default".to_string()))
            .prop_map(|(c, n)| ProcessBackend::Kubernetes {
                cluster_name: c,
                namespace: n,
            }),
        (Just("t3.medium".to_string()), Just("ami-test".to_string()))
            .prop_map(|(i, a)| ProcessBackend::Ec2Instance {
                instance_type: i,
                ami_id: a,
            }),
        (Just("test-asg".to_string()), 1..=4_u32, any::<bool>())
            .prop_map(|(n, c, s)| ProcessBackend::Ec2Asg {
                asg_name: n,
                instance_count: c,
                spot: s,
            }),
    ]
}

fn dns_prefix_for_backend(backend: &ProcessBackend) -> &'static str {
    match backend {
        ProcessBackend::Kubernetes { .. } => "k8s.",
        ProcessBackend::Ec2Instance { .. } => "infra.",
        ProcessBackend::Ec2Asg { .. } => "builder.",
        ProcessBackend::BareMetal { .. } => "bare.",
        ProcessBackend::Lambda { .. } => "fn.",
    }
}

fn arb_valid_tree() -> impl Strategy<Value = ProcessTree> {
    // Generate 2-7 children with unique PIDs and unique FQDNs
    (arb_process_backend(), prop::collection::vec(arb_process_backend(), 1..=6)).prop_map(
        |(root_backend, child_backends)| {
            let root_prefix = dns_prefix_for_backend(&root_backend);
            let root = ConvergenceProcess {
                pid: 1,
                ppid: 0,
                name: "root".to_string(),
                backend: root_backend,
                dns_identity: DnsIdentity {
                    fqdn: format!("{root_prefix}root.test.lol"),
                    zone_type: ZoneType::Private,
                    record_type: DnsRecordType::A,
                    target: "10.0.0.1".to_string(),
                },
                state: ProcessState::Running,
            };

            let children: Vec<ProcessTree> = child_backends
                .into_iter()
                .enumerate()
                .map(|(i, backend)| {
                    let pid = (i as u32) + 2;
                    let prefix = dns_prefix_for_backend(&backend);
                    ProcessTree {
                        root: ConvergenceProcess {
                            pid,
                            ppid: 1,
                            name: format!("child-{pid}"),
                            backend,
                            dns_identity: DnsIdentity {
                                fqdn: format!("{prefix}child-{pid}.test.lol"),
                                zone_type: ZoneType::Private,
                                record_type: DnsRecordType::A,
                                target: format!("10.0.0.{}", pid + 10),
                            },
                            state: ProcessState::Running,
                        },
                        children: vec![],
                    }
                })
                .collect();

            ProcessTree { root, children }
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_13_random_trees_satisfy_invariants(tree in arb_valid_tree()) {
        prop_assert!(check_all_process_invariants(&tree).is_ok());
    }
}

// ── Proof 14: mixed backends in same tree ─────────────────────────

#[test]
fn proof_14_mixed_backends_work() {
    let tree = ProcessTree {
        root: ConvergenceProcess {
            pid: 1,
            ppid: 0,
            name: "orchestrator".to_string(),
            backend: ProcessBackend::Ec2Instance {
                instance_type: "t3.medium".to_string(),
                ami_id: "ami-test".to_string(),
            },
            dns_identity: DnsIdentity {
                fqdn: "infra.mixed.test.lol".to_string(),
                zone_type: ZoneType::SplitHorizon,
                record_type: DnsRecordType::A,
                target: "10.0.0.1".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![
            ProcessTree {
                root: ConvergenceProcess {
                    pid: 2,
                    ppid: 1,
                    name: "k8s-cluster".to_string(),
                    backend: ProcessBackend::Kubernetes {
                        cluster_name: "test".to_string(),
                        namespace: "default".to_string(),
                    },
                    dns_identity: DnsIdentity {
                        fqdn: "k8s.test.lol".to_string(),
                        zone_type: ZoneType::Private,
                        record_type: DnsRecordType::Cname,
                        target: "nlb.test.lol".to_string(),
                    },
                    state: ProcessState::Running,
                },
                children: vec![],
            },
            ProcessTree {
                root: ConvergenceProcess {
                    pid: 3,
                    ppid: 1,
                    name: "builder-fleet".to_string(),
                    backend: ProcessBackend::Ec2Asg {
                        asg_name: "builders".to_string(),
                        instance_count: 4,
                        spot: true,
                    },
                    dns_identity: DnsIdentity {
                        fqdn: "builder.test.lol".to_string(),
                        zone_type: ZoneType::Private,
                        record_type: DnsRecordType::A,
                        target: "10.0.1.0".to_string(),
                    },
                    state: ProcessState::Running,
                },
                children: vec![],
            },
            ProcessTree {
                root: ConvergenceProcess {
                    pid: 4,
                    ppid: 1,
                    name: "bare-metal".to_string(),
                    backend: ProcessBackend::BareMetal {
                        hostname: "tatara-01".to_string(),
                        ip: "192.168.1.100".to_string(),
                    },
                    dns_identity: DnsIdentity {
                        fqdn: "bare.tatara.test.lol".to_string(),
                        zone_type: ZoneType::Private,
                        record_type: DnsRecordType::A,
                        target: "192.168.1.100".to_string(),
                    },
                    state: ProcessState::Running,
                },
                children: vec![],
            },
            ProcessTree {
                root: ConvergenceProcess {
                    pid: 5,
                    ppid: 1,
                    name: "webhook-fn".to_string(),
                    backend: ProcessBackend::Lambda {
                        function_name: "webhook-handler".to_string(),
                        runtime: "provided.al2023".to_string(),
                    },
                    dns_identity: DnsIdentity {
                        fqdn: "fn.webhook.test.lol".to_string(),
                        zone_type: ZoneType::Public,
                        record_type: DnsRecordType::Alias,
                        target: "lambda.us-east-1.amazonaws.com".to_string(),
                    },
                    state: ProcessState::Running,
                },
                children: vec![],
            },
        ],
    };

    assert!(check_all_process_invariants(&tree).is_ok());
}

// ── Proof 15: ProcessState valid transitions ──────────────────────

#[test]
fn proof_15_process_state_transitions() {
    // Valid forward path
    assert!(is_valid_transition(
        &ProcessState::Pending,
        &ProcessState::Provisioning
    ));
    assert!(is_valid_transition(
        &ProcessState::Provisioning,
        &ProcessState::Running
    ));
    assert!(is_valid_transition(
        &ProcessState::Running,
        &ProcessState::Degraded
    ));
    assert!(is_valid_transition(
        &ProcessState::Degraded,
        &ProcessState::Running
    ));
    assert!(is_valid_transition(
        &ProcessState::Running,
        &ProcessState::Draining
    ));
    assert!(is_valid_transition(
        &ProcessState::Draining,
        &ProcessState::Terminated
    ));

    // Invalid transitions
    assert!(!is_valid_transition(
        &ProcessState::Pending,
        &ProcessState::Running
    ));
    assert!(!is_valid_transition(
        &ProcessState::Terminated,
        &ProcessState::Pending
    ));
    assert!(!is_valid_transition(
        &ProcessState::Terminated,
        &ProcessState::Running
    ));
    assert!(!is_valid_transition(
        &ProcessState::Draining,
        &ProcessState::Running
    ));

    // Provisioning can fail straight to Terminated
    assert!(is_valid_transition(
        &ProcessState::Provisioning,
        &ProcessState::Terminated
    ));
}

// ═══════════════════════════════════════════════════════════════════
// Composition proofs (16-17)
// ═══════════════════════════════════════════════════════════════════

// ── Proof 16: quero + secure_vpc composed preserves invariants ────

#[test]
fn proof_16_composed_with_secure_vpc() {
    use pangea_sim::simulations::secure_vpc;

    let quero_config = default_config();
    let vpc_config = secure_vpc::SecureVpcConfig {
        name: "extra-vpc".to_string(),
        cidr: "10.100.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        flow_logs: true,
    };

    let quero_tf = quero_platform::simulate(&quero_config);
    let vpc_tf = secure_vpc::simulate(&vpc_config);

    // Merge resources
    let merged = merge_terraform_json(&[quero_tf, vpc_tf]);

    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
    assert!(
        check_all(&refs, &merged).is_ok(),
        "composed quero + secure_vpc must pass all invariants"
    );
}

// ── Proof 17: quero + builder fleet composed preserves invariants ─

#[test]
fn proof_17_composed_with_builder_fleet() {
    use pangea_sim::simulations::nix_builder_fleet;

    let quero_config = default_config();
    let fleet_config = nix_builder_fleet::NixBuilderFleetConfig {
        name: "extra-fleet".to_string(),
        cidr: "10.200.0.0/16".to_string(),
        azs: vec!["us-east-1b".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: "c5.xlarge".to_string(),
        ami_id: "ami-extra-fleet".to_string(),
        volume_size: 100,
        fleet_size_min: 1,
        fleet_size_max: 4,
        nix_port: 8080,
    };

    let quero_tf = quero_platform::simulate(&quero_config);
    let fleet_tf = nix_builder_fleet::simulate(&fleet_config);

    let merged = merge_terraform_json(&[quero_tf, fleet_tf]);

    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
    assert!(
        check_all(&refs, &merged).is_ok(),
        "composed quero + builder_fleet must pass all invariants"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Compliance proofs (18-19)
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "compliance")]
mod compliance {
    use super::*;
    use pangea_sim::compliance::verify_baseline;

    // ── Proof 18: FedRAMP baseline ────────────────────────────────
    // The quero platform satisfies all FedRAMP controls that are
    // covered by our 10 invariants (some NIST controls like AU-3,
    // CM-6, SI-7, IA-3, IA-5 require additional verification
    // beyond infrastructure invariants).
    #[test]
    fn proof_18_fedramp_baseline() {
        let config = default_config();
        let tf = quero_platform::simulate(&config);
        let result = verify_baseline(&tf, &compliance_controls::fedramp_moderate());

        // Controls covered by an invariant (invariant != "none") must pass
        let covered_results: Vec<_> = result
            .results
            .iter()
            .filter(|r| r.invariant != "none")
            .collect();
        let covered_satisfied = covered_results.iter().filter(|r| r.satisfied).count();
        let covered_total = covered_results.len();

        assert!(
            covered_satisfied > 0,
            "quero platform must satisfy at least some FedRAMP controls"
        );

        // All invariant-covered controls must pass
        let covered_failed: Vec<_> = covered_results
            .iter()
            .filter(|r| !r.satisfied)
            .map(|r| format!("{} ({})", r.control_id, r.invariant))
            .collect();
        assert!(
            covered_failed.is_empty(),
            "all invariant-covered FedRAMP controls must pass, failed: {covered_failed:?}"
        );

        // Document exactly which FedRAMP controls are NOT covered by any invariant.
        // These are KNOWN GAPS — controls that require capabilities beyond the
        // current 10 Terraform invariants (e.g., IA-3 identity proofing,
        // IA-5 authenticator management, CA-* assessment controls).
        // Each gap is explicitly acknowledged, not silently ignored.
        let uncovered: Vec<_> = result.results.iter()
            .filter(|r| !r.satisfied)
            .map(|r| r.control_id.clone())
            .collect();
        let gap_count = uncovered.len();

        // Must satisfy at least 70% of total controls
        let pct = (result.satisfied_count as f64 / result.total_controls as f64) * 100.0;
        assert!(
            pct >= 70.0,
            "FedRAMP satisfaction must be >= 70%, got {pct:.1}% ({}/{}) — {} known gaps: {:?}",
            result.satisfied_count,
            result.total_controls,
            gap_count,
            uncovered
        );
    }

    // ── Proof 19: CIS AWS baseline ────────────────────────────────
    #[test]
    fn proof_19_cis_aws_baseline() {
        let config = default_config();
        let tf = quero_platform::simulate(&config);
        let result = verify_baseline(&tf, &compliance_controls::cis_aws_v3());

        // Must satisfy at least 80% of CIS controls
        let pct = (result.satisfied_count as f64 / result.total_controls as f64) * 100.0;
        assert!(
            pct >= 80.0,
            "CIS AWS satisfaction must be >= 80%, got {pct:.1}% ({}/{})",
            result.satisfied_count,
            result.total_controls
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// Transition proofs (20-21)
// ═══════════════════════════════════════════════════════════════════

// ── Proof 20: v1 -> v2 (add x86 builders) preserves invariants ───

#[test]
fn proof_20_v1_to_v2_transition() {
    use pangea_sim::transitions::simulate_transition;

    let v1 = quero_platform::simulate(&default_config());
    let v2 = quero_platform::simulate(&v2_config());

    let proof = simulate_transition(&v1, &v2);
    assert!(
        proof.from_valid,
        "v1 must be valid"
    );
    assert!(
        proof.to_valid,
        "v2 must be valid"
    );
    assert!(
        proof.invariants_preserved,
        "transition must preserve invariants: {:?}",
        proof.violations
    );
}

// ── Proof 21: rollback v2 -> v1 is safe ───────────────────────────

#[test]
fn proof_21_rollback_v2_to_v1() {
    use pangea_sim::transitions::prove_rollback;

    let v1 = quero_platform::simulate(&default_config());
    let v2 = quero_platform::simulate(&v2_config());

    let rollback = prove_rollback(&v1, &v2);
    assert!(
        rollback.rollback_safe,
        "rollback from v2 to v1 must be safe"
    );
    assert!(
        rollback.forward.invariants_preserved,
        "forward transition must preserve invariants"
    );
    assert!(
        rollback.backward.invariants_preserved,
        "backward transition must preserve invariants"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Certification proof (22)
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "certification")]
mod certification {
    use super::*;
    use pangea_sim::certification::{
        certify_invariant, certify_simulation, verify_certificate,
    };

    // ── Proof 22: certify quero platform ──────────────────────────
    #[test]
    fn proof_22_certify_quero_platform() {
        let config = default_config();
        let tf = quero_platform::simulate(&config);

        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();

        // Verify all invariants pass
        assert!(check_all(&refs, &tf).is_ok());

        // Certify each invariant
        let proofs: Vec<_> = invs
            .iter()
            .map(|inv| certify_invariant(inv.name(), &tf, true, 1))
            .collect();

        let cert = certify_simulation("quero_platform", proofs);
        assert!(cert.all_passed, "all proofs must pass");
        assert!(verify_certificate(&cert), "certificate must verify");
        assert_eq!(cert.proofs.len(), 10, "must have 10 proof entries");
    }
}

// ═══════════════════════════════════════════════════════════════════
// Additional proofs (23-40+)
// ═══════════════════════════════════════════════════════════════════

// ── Proof 23: no public SSH in quero platform ─────────────────────

#[test]
fn proof_23_no_public_ssh() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let ssh_rule = tf
        .pointer("/resource/aws_security_group_rule/quero-ssh-in")
        .expect("must have SSH rule");

    let cidrs = ssh_rule
        .get("cidr_blocks")
        .and_then(|v| v.as_array())
        .expect("must have cidr_blocks");

    for cidr in cidrs {
        assert_ne!(
            cidr.as_str().unwrap_or(""),
            "0.0.0.0/0",
            "SSH must not be open to internet"
        );
    }
}

// ── Proof 24: all EBS encrypted ───────────────────────────────────

#[test]
fn proof_24_all_ebs_encrypted() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let templates = tf
        .pointer("/resource/aws_launch_template")
        .and_then(|v| v.as_object())
        .expect("must have launch templates");

    for (name, tmpl) in templates {
        let empty = vec![];
        let mappings = tmpl
            .get("block_device_mappings")
            .and_then(|v| v.as_array())
            .unwrap_or(&empty);
        for mapping in mappings {
            let encrypted = mapping
                .pointer("/ebs/encrypted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            assert!(encrypted, "EBS must be encrypted in template {name}");
        }
    }
}

// ── Proof 25: IMDSv2 required ─────────────────────────────────────

#[test]
fn proof_25_imdsv2_required() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let templates = tf
        .pointer("/resource/aws_launch_template")
        .and_then(|v| v.as_object())
        .expect("must have launch templates");

    for (name, tmpl) in templates {
        let tokens = tmpl
            .pointer("/metadata_options/http_tokens")
            .and_then(|v| v.as_str())
            .unwrap_or("optional");
        assert_eq!(tokens, "required", "IMDSv2 must be required in {name}");
    }
}

// ── Proof 26: all subnets private ─────────────────────────────────

#[test]
fn proof_26_all_subnets_private() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    if let Some(subnets) = tf
        .pointer("/resource/aws_subnet")
        .and_then(|v| v.as_object())
    {
        for (name, subnet) in subnets {
            let maps_public = subnet
                .get("map_public_ip_on_launch")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            assert!(!maps_public, "subnet {name} must not map public IPs");
        }
    }
}

// ── Proof 27: NLB access logs enabled ─────────────────────────────

#[test]
fn proof_27_nlb_access_logs() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let lbs = tf
        .pointer("/resource/aws_lb")
        .and_then(|v| v.as_object())
        .expect("must have load balancers");

    for (name, lb) in lbs {
        let logging = lb
            .pointer("/access_logs/enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        assert!(logging, "NLB {name} must have access logging enabled");
    }
}

// ── Proof 28: IAM least privilege ─────────────────────────────────

#[test]
fn proof_28_iam_least_privilege() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    if let Some(policies) = tf
        .pointer("/resource/aws_iam_role_policy")
        .and_then(|v| v.as_object())
    {
        for (name, policy_resource) in policies {
            let policy_str = policy_resource
                .get("policy")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Ok(doc) = serde_json::from_str::<serde_json::Value>(policy_str) {
                if let Some(statements) = doc.get("Statement").and_then(|v| v.as_array()) {
                    for stmt in statements {
                        let action = stmt.get("Action");
                        let resource = stmt.get("Resource");
                        let has_star_action = action
                            .and_then(|a| a.as_str())
                            .map_or(false, |s| s == "*");
                        let has_star_resource = resource
                            .and_then(|r| r.as_str())
                            .map_or(false, |s| s == "*");
                        assert!(
                            !(has_star_action && has_star_resource),
                            "IAM policy {name} must not have Action:* + Resource:*"
                        );
                    }
                }
            }
        }
    }
}

// ── Proof 29: all resources tagged ────────────────────────────────

#[test]
fn proof_29_all_resources_tagged() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    if let Some(resources) = tf.get("resource").and_then(|v| v.as_object()) {
        for (resource_type, instances) in resources {
            if let Some(instances_map) = instances.as_object() {
                for (name, resource) in instances_map {
                    let managed_by = resource
                        .pointer("/tags/ManagedBy")
                        .and_then(|v| v.as_str());
                    let purpose = resource.pointer("/tags/Purpose").and_then(|v| v.as_str());
                    assert!(
                        managed_by.is_some(),
                        "{resource_type}.{name} missing ManagedBy tag"
                    );
                    assert!(
                        purpose.is_some(),
                        "{resource_type}.{name} missing Purpose tag"
                    );
                }
            }
        }
    }
}

// ── Proof 30: NLBs are internal ───────────────────────────────────

#[test]
fn proof_30_nlbs_internal() {
    let config = default_config();
    let tf = quero_platform::simulate(&config);

    let lbs = tf
        .pointer("/resource/aws_lb")
        .and_then(|v| v.as_object())
        .expect("must have load balancers");

    for (name, lb) in lbs {
        let internal = lb.get("internal").and_then(|v| v.as_bool()).unwrap_or(false);
        assert!(internal, "NLB {name} must be internal");
    }
}

// ── Proof 31: quero tree PID ordering ─────────────────────────────

#[test]
fn proof_31_pid_ordering() {
    let tree = quero_process_tree();
    assert_eq!(tree.root.pid, 1, "root must be PID 1");
    for (i, child) in tree.children.iter().enumerate() {
        assert_eq!(
            child.root.pid,
            (i as u32) + 2,
            "child {i} must be PID {}",
            (i as u32) + 2
        );
    }
}

// ── Proof 32: quero tree all ppid == 1 for children ───────────────

#[test]
fn proof_32_children_ppid() {
    let tree = quero_process_tree();
    for child in &tree.children {
        assert_eq!(
            child.root.ppid, 1,
            "{} must have ppid 1",
            child.root.name
        );
    }
}

// ── Proof 33: quero tree contains K8s backend ─────────────────────

#[test]
fn proof_33_has_kubernetes_backend() {
    let tree = quero_process_tree();
    let has_k8s = tree.children.iter().any(|c| {
        matches!(c.root.backend, ProcessBackend::Kubernetes { .. })
    });
    assert!(has_k8s, "quero tree must have a Kubernetes backend (seph)");
}

// ── Proof 34: quero tree contains ASG backends ────────────────────

#[test]
fn proof_34_has_asg_backends() {
    let tree = quero_process_tree();
    let asg_count = tree
        .children
        .iter()
        .filter(|c| matches!(c.root.backend, ProcessBackend::Ec2Asg { .. }))
        .count();
    assert_eq!(asg_count, 2, "quero tree must have 2 ASG backends");
}

// ── Proof 35: quero tree all processes Running ────────────────────

#[test]
fn proof_35_all_processes_running() {
    let tree = quero_process_tree();
    assert_eq!(tree.root.state, ProcessState::Running);
    for child in &tree.children {
        assert_eq!(child.root.state, ProcessState::Running);
    }
}

// ── Proof 36: quero DNS identity FQDNs contain quero.lol ──────────

#[test]
fn proof_36_dns_fqdns_contain_domain() {
    let tree = quero_process_tree();
    assert!(tree.root.dns_identity.fqdn.contains("quero.lol"));
    for child in &tree.children {
        assert!(
            child.root.dns_identity.fqdn.contains("quero.lol"),
            "{} FQDN {} must contain quero.lol",
            child.root.name,
            child.root.dns_identity.fqdn
        );
    }
}

// ── Proof 37: duplicate PID detection works ───────────────────────

#[test]
fn proof_37_duplicate_pid_detection() {
    let mut tree = quero_process_tree();
    // Force duplicate PID
    tree.children[0].root.pid = 1;
    assert!(
        check_unique_pids(&tree).is_err(),
        "must detect duplicate PIDs"
    );
}

// ── Proof 38: orphan detection works ──────────────────────────────

#[test]
fn proof_38_orphan_detection() {
    let mut tree = quero_process_tree();
    // Force invalid ppid
    tree.children[0].root.ppid = 99;
    assert!(
        check_no_orphans(&tree).is_err(),
        "must detect orphan processes"
    );
}

// ── Proof 39: DNS overlap detection works ─────────────────────────

#[test]
fn proof_39_dns_overlap_detection() {
    let mut tree = quero_process_tree();
    // Force duplicate FQDN
    tree.children[0].root.dns_identity.fqdn = tree.root.dns_identity.fqdn.clone();
    assert!(
        check_dns_no_overlap(&tree).is_err(),
        "must detect duplicate FQDNs"
    );
}

// ── Proof 40: empty DNS detection works ───────────────────────────

#[test]
fn proof_40_empty_dns_detection() {
    let mut tree = quero_process_tree();
    tree.children[0].root.dns_identity.fqdn = String::new();
    assert!(
        check_all_have_dns(&tree).is_err(),
        "must detect empty DNS identity"
    );
}

// ── Proof 41: cache toggle produces extra launch template ─────────

#[test]
fn proof_41_cache_toggle() {
    let mut config_no_cache = default_config();
    config_no_cache.enable_cache = false;

    let mut config_with_cache = default_config();
    config_with_cache.enable_cache = true;

    let tf_no = quero_platform::simulate(&config_no_cache);
    let tf_yes = quero_platform::simulate(&config_with_cache);

    let a_no = ArchitectureAnalysis::from_terraform_json(&tf_no);
    let a_yes = ArchitectureAnalysis::from_terraform_json(&tf_yes);

    assert!(
        a_yes.resource_count > a_no.resource_count,
        "enabling cache must add resources"
    );

    // Both must still pass invariants
    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
    assert!(check_all(&refs, &tf_no).is_ok());
    assert!(check_all(&refs, &tf_yes).is_ok());
}

// ── Proof 42: seph toggle produces extra resources ────────────────

#[test]
fn proof_42_seph_toggle() {
    let mut config_no_seph = default_config();
    config_no_seph.enable_seph = false;

    let mut config_with_seph = default_config();
    config_with_seph.enable_seph = true;

    let tf_no = quero_platform::simulate(&config_no_seph);
    let tf_yes = quero_platform::simulate(&config_with_seph);

    let a_no = ArchitectureAnalysis::from_terraform_json(&tf_no);
    let a_yes = ArchitectureAnalysis::from_terraform_json(&tf_yes);

    assert!(
        a_yes.resource_count > a_no.resource_count,
        "enabling seph must add resources"
    );

    // Both must pass invariants
    let invs = all_invariants();
    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
    assert!(check_all(&refs, &tf_no).is_ok());
    assert!(check_all(&refs, &tf_yes).is_ok());
}

// ═══════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════

/// Count all processes in a tree.
fn count_processes(tree: &ProcessTree) -> usize {
    1 + tree
        .children
        .iter()
        .map(count_processes)
        .sum::<usize>()
}

/// Merge multiple Terraform JSON values into one.
fn merge_terraform_json(jsons: &[serde_json::Value]) -> serde_json::Value {
    let mut resources = serde_json::Map::new();
    for tf_json in jsons {
        if let Some(res) = tf_json.get("resource").and_then(|v| v.as_object()) {
            for (resource_type, instances) in res {
                let entry = resources
                    .entry(resource_type.clone())
                    .or_insert_with(|| serde_json::json!({}));
                if let (Some(existing), Some(new)) =
                    (entry.as_object_mut(), instances.as_object())
                {
                    for (k, v) in new {
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    serde_json::json!({ "resource": resources })
}
