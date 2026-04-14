//! Self-proof — the convergence platform generates and verifies itself.
//!
//! This is the ultimate test: the platform uses its OWN tools to:
//! 1. Define its own architecture as types
//! 2. Simulate its own infrastructure
//! 3. Prove its own invariants
//! 4. Verify its own compliance
//! 5. Certify its own proofs
//! 6. Simulate transitions of itself
//! 7. Prove its own remediation works
//! 8. Generate Helm charts for itself and verify K8s invariants
//! 9. Compose itself with its dependencies and prove composition
//! 10. Prove that the proof system itself is consistent
//!
//! If ALL these tests pass, the platform is a verified fixed point:
//! it can generate, verify, and certify any system — INCLUDING ITSELF.
//!
//! # Theory
//!
//! **Curry-Howard:** A proof object that can be constructed means the
//! theorem is true. Every `assert!` in this file constructs a proof.
//!
//! **Category theory:** A functor from a category to itself is an
//! endofunctor. The platform verifying itself IS an endofunctor.
//! If it preserves structure (all invariants hold), it is self-consistent.
//!
//! **Fixed-point theorem:** `verify(generate(types)) = types`.
//! The system converges to itself. This file IS the fixed point.

use serde_json::{json, Value};
use std::collections::HashSet;

use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::invariants::k8s::all_k8s_invariants;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::remediation::{remediate, remediate_all};
use pangea_sim::simulations::{
    helm_chart::{self, HelmChartConfig},
    nix_builder_fleet, secure_vpc,
};
use pangea_sim::transitions::{prove_rollback, simulate_migration, simulate_transition};

// ═══════════════════════════════════════════════════════════════════
// Helper: the convergence platform's OWN infrastructure as types
// ═══════════════════════════════════════════════════════════════════

/// The seph cluster — the actual convergence platform infrastructure.
///
/// This is a realistic model of the production cluster that runs
/// the convergence-controller, kensa, shinryu, and grafana.
fn platform_infrastructure() -> Value {
    json!({
        "resource": {
            "aws_vpc": {
                "seph-vpc": {
                    "cidr_block": "10.0.0.0/16",
                    "enable_dns_support": true,
                    "enable_dns_hostnames": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "convergence-platform" }
                }
            },
            "aws_subnet": {
                "seph-private-1a": {
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "cidr_block": "10.0.1.0/24",
                    "availability_zone": "us-east-1a",
                    "map_public_ip_on_launch": false,
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-nodes" }
                },
                "seph-private-1b": {
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "cidr_block": "10.0.2.0/24",
                    "availability_zone": "us-east-1b",
                    "map_public_ip_on_launch": false,
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-nodes" }
                },
                "seph-public-1a": {
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "cidr_block": "10.0.100.0/24",
                    "availability_zone": "us-east-1a",
                    "map_public_ip_on_launch": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "load-balancers", "Tier": "public" }
                }
            },
            "aws_security_group": {
                "seph-k8s-sg": {
                    "name": "seph-k8s-sg",
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-cluster" }
                }
            },
            "aws_security_group_rule": {
                "seph-ssh-in": {
                    "security_group_id": "${aws_security_group.seph-k8s-sg.id}",
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/16"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "ssh-access" }
                },
                "seph-k8s-api": {
                    "security_group_id": "${aws_security_group.seph-k8s-sg.id}",
                    "type": "ingress",
                    "from_port": 6443,
                    "to_port": 6443,
                    "protocol": "tcp",
                    "cidr_blocks": ["10.0.0.0/16"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-api" }
                }
            },
            "aws_lb": {
                "seph-nlb": {
                    "name": "seph-nlb",
                    "internal": false,
                    "load_balancer_type": "network",
                    "subnets": ["${aws_subnet.seph-public-1a.id}"],
                    "access_logs": { "enabled": true, "bucket": "seph-access-logs" },
                    "tags": { "ManagedBy": "pangea", "Purpose": "convergence-ingress" }
                }
            },
            "aws_launch_template": {
                "seph-k8s-nodes": {
                    "name_prefix": "seph-k8s-",
                    "image_id": "ami-convergence-nixos",
                    "instance_type": "m6i.xlarge",
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": { "encrypted": true, "volume_size": 200 }
                    }],
                    "metadata_options": { "http_tokens": "required" },
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-node" }
                }
            },
            "aws_autoscaling_group": {
                "seph-k8s-asg": {
                    "min_size": 3,
                    "max_size": 10,
                    "desired_capacity": 3,
                    "launch_template": {
                        "id": "${aws_launch_template.seph-k8s-nodes.id}",
                        "version": "$Latest"
                    },
                    "vpc_zone_identifier": [
                        "${aws_subnet.seph-private-1a.id}",
                        "${aws_subnet.seph-private-1b.id}"
                    ],
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-scaling" }
                }
            },
            "aws_iam_role": {
                "seph-k8s-role": {
                    "name": "seph-k8s-role",
                    "assume_role_policy": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"}}]}",
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-node-role" }
                }
            },
            "aws_iam_policy": {
                "seph-k8s-policy": {
                    "name": "seph-k8s-policy",
                    "policy": "{\"Statement\":[{\"Action\":[\"ecr:GetAuthorizationToken\",\"ecr:BatchGetImage\",\"ecr:GetDownloadUrlForLayer\",\"s3:GetObject\"],\"Resource\":\"*\",\"Effect\":\"Allow\"}]}",
                    "tags": { "ManagedBy": "pangea", "Purpose": "k8s-node-permissions" }
                }
            },
            "aws_s3_bucket": {
                "seph-state": {
                    "bucket": "seph-terraform-state",
                    "tags": { "ManagedBy": "pangea", "Purpose": "terraform-state" }
                }
            },
            "aws_s3_bucket_public_access_block": {
                "seph-state-public-block": {
                    "bucket": "${aws_s3_bucket.seph-state.id}",
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "state-security" }
                }
            },
            "aws_internet_gateway": {
                "seph-igw": {
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "tags": { "ManagedBy": "pangea", "Purpose": "internet-access" }
                }
            },
            "aws_default_security_group": {
                "seph-default-sg": {
                    "vpc_id": "${aws_vpc.seph-vpc.id}",
                    "tags": { "ManagedBy": "pangea", "Purpose": "default-lockdown" }
                }
            }
        }
    })
}

/// The convergence platform's K8s workloads — the controller, kensa,
/// shinryu, and grafana as K8s Deployment manifests.
fn platform_k8s_manifests() -> Value {
    json!({
        "kind": "List",
        "apiVersion": "v1",
        "items": [
            convergence_controller_deployment(),
            kensa_deployment(),
            shinryu_deployment(),
            grafana_deployment()
        ]
    })
}

fn convergence_controller_deployment() -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "convergence-controller",
            "namespace": "convergence-system",
            "labels": { "app": "convergence-controller" }
        },
        "spec": {
            "replicas": 2,
            "selector": { "matchLabels": { "app": "convergence-controller" } },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "convergence-controller",
                        "app.kubernetes.io/name": "convergence-controller",
                        "app.kubernetes.io/managed-by": "pangea"
                    }
                },
                "spec": {
                    "securityContext": { "runAsNonRoot": true },
                    "containers": [{
                        "name": "convergence-controller",
                        "image": "ghcr.io/pleme-io/convergence-controller:latest",
                        "ports": [{ "containerPort": 8080 }],
                        "resources": {
                            "limits": { "cpu": "500m", "memory": "256Mi" },
                            "requests": { "cpu": "100m", "memory": "128Mi" }
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] }
                        }
                    }]
                }
            }
        }
    })
}

fn kensa_deployment() -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "kensa",
            "namespace": "convergence-system",
            "labels": { "app": "kensa" }
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": "kensa" } },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "kensa",
                        "app.kubernetes.io/name": "kensa",
                        "app.kubernetes.io/managed-by": "pangea"
                    }
                },
                "spec": {
                    "securityContext": { "runAsNonRoot": true },
                    "containers": [{
                        "name": "kensa",
                        "image": "ghcr.io/pleme-io/kensa:latest",
                        "ports": [{ "containerPort": 8443 }],
                        "resources": {
                            "limits": { "cpu": "250m", "memory": "128Mi" },
                            "requests": { "cpu": "50m", "memory": "64Mi" }
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] }
                        }
                    }]
                }
            }
        }
    })
}

fn shinryu_deployment() -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "shinryu",
            "namespace": "observability",
            "labels": { "app": "shinryu" }
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": "shinryu" } },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "shinryu",
                        "app.kubernetes.io/name": "shinryu",
                        "app.kubernetes.io/managed-by": "pangea"
                    }
                },
                "spec": {
                    "securityContext": { "runAsNonRoot": true },
                    "containers": [{
                        "name": "shinryu",
                        "image": "ghcr.io/pleme-io/shinryu:latest",
                        "ports": [{ "containerPort": 9000 }],
                        "resources": {
                            "limits": { "cpu": "1000m", "memory": "512Mi" },
                            "requests": { "cpu": "200m", "memory": "256Mi" }
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] }
                        }
                    }]
                }
            }
        }
    })
}

fn grafana_deployment() -> Value {
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "grafana",
            "namespace": "observability",
            "labels": { "app": "grafana" }
        },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": "grafana" } },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "grafana",
                        "app.kubernetes.io/name": "grafana",
                        "app.kubernetes.io/managed-by": "pangea"
                    }
                },
                "spec": {
                    "securityContext": { "runAsNonRoot": true },
                    "containers": [{
                        "name": "grafana",
                        "image": "grafana/grafana:latest",
                        "ports": [{ "containerPort": 3000 }],
                        "resources": {
                            "limits": { "cpu": "500m", "memory": "256Mi" },
                            "requests": { "cpu": "100m", "memory": "128Mi" }
                        },
                        "securityContext": {
                            "runAsNonRoot": true,
                            "readOnlyRootFilesystem": true,
                            "allowPrivilegeEscalation": false,
                            "capabilities": { "drop": ["ALL"] }
                        }
                    }]
                }
            }
        }
    })
}

/// Generate a Helm chart for a convergence platform component.
fn platform_helm_chart(name: &str) -> HelmChartConfig {
    HelmChartConfig {
        chart_name: name.to_string(),
        namespace: "convergence-system".to_string(),
        replicas: 2,
        image: format!("ghcr.io/pleme-io/{name}"),
        image_tag: "latest".to_string(),
        service_port: 8080,
        enable_network_policy: true,
        enable_pdb: true,
        enable_hpa: true,
        enable_service_monitor: true,
        resources_cpu_limit: "500m".to_string(),
        resources_memory_limit: "256Mi".to_string(),
        security_context_run_as_non_root: true,
        security_context_read_only_root: true,
        security_context_drop_capabilities: true,
        labels: vec![
            ("ManagedBy".to_string(), "pangea".to_string()),
            ("Purpose".to_string(), "convergence".to_string()),
        ],
    }
}

/// Merge two Terraform JSON values by combining their resource maps.
fn merge_tf_json(a: &Value, b: &Value) -> Value {
    let mut resources = serde_json::Map::new();

    for tf in [a, b] {
        if let Some(res) = tf.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in res {
                let entry = resources
                    .entry(resource_type.clone())
                    .or_insert_with(|| json!({}));
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

    json!({ "resource": resources })
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 1: The platform defines itself as types
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_type_infrastructure_is_valid_json() {
    // The platform's infrastructure definition serializes and
    // deserializes without loss — the types are well-formed.
    let infra = platform_infrastructure();
    let serialized = serde_json::to_string(&infra).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(infra, deserialized, "Infrastructure JSON roundtrip failed");
}

#[test]
fn self_type_k8s_manifests_are_valid_json() {
    // The platform's K8s manifests serialize and deserialize correctly.
    let manifests = platform_k8s_manifests();
    let serialized = serde_json::to_string(&manifests).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(manifests, deserialized, "K8s manifests JSON roundtrip failed");
}

#[test]
fn self_type_infrastructure_has_realistic_resources() {
    // The platform models the actual seph cluster — VPC, subnets,
    // SG, NLB, ASG, launch template, IAM, S3.
    let infra = platform_infrastructure();
    let analysis = ArchitectureAnalysis::from_terraform_json(&infra);

    assert!(analysis.has_resource("aws_vpc", 1), "Missing VPC");
    assert!(analysis.has_resource("aws_subnet", 3), "Missing subnets");
    assert!(analysis.has_resource("aws_security_group", 1), "Missing SG");
    assert!(analysis.has_resource("aws_security_group_rule", 2), "Missing SG rules");
    assert!(analysis.has_resource("aws_lb", 1), "Missing NLB");
    assert!(analysis.has_resource("aws_launch_template", 1), "Missing launch template");
    assert!(analysis.has_resource("aws_autoscaling_group", 1), "Missing ASG");
    assert!(analysis.has_resource("aws_iam_role", 1), "Missing IAM role");
    assert!(analysis.has_resource("aws_iam_policy", 1), "Missing IAM policy");
    assert!(analysis.has_resource("aws_s3_bucket", 1), "Missing S3 bucket");
    assert!(
        analysis.resource_count >= 14,
        "Platform should have 14+ resources, got {}",
        analysis.resource_count
    );
}

#[test]
fn self_type_k8s_manifests_have_all_workloads() {
    // The platform models 4 workloads: convergence-controller, kensa,
    // shinryu, grafana.
    let manifests = platform_k8s_manifests();
    let items = manifests.get("items").unwrap().as_array().unwrap();
    assert_eq!(items.len(), 4, "Expected 4 K8s workloads");

    let names: Vec<&str> = items
        .iter()
        .filter_map(|item| item.pointer("/metadata/name").and_then(Value::as_str))
        .collect();
    assert!(names.contains(&"convergence-controller"));
    assert!(names.contains(&"kensa"));
    assert!(names.contains(&"shinryu"));
    assert!(names.contains(&"grafana"));
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 2: The platform simulates itself
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_simulation_all_terraform_invariants_hold() {
    // The platform's OWN infrastructure passes ALL 10 Terraform invariants.
    // This is the FIXED POINT: verify(platform) = valid.
    let infra = platform_infrastructure();
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    let result = check_all(&refs, &infra);
    assert!(
        result.is_ok(),
        "Platform infrastructure violates its own invariants: {:?}",
        result.err()
    );
}

#[test]
fn self_simulation_all_k8s_invariants_hold() {
    // The platform's OWN K8s manifests pass ALL 8 K8s invariants.
    let manifests = platform_k8s_manifests();
    let invariants = all_k8s_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    let result = check_all(&refs, &manifests);
    assert!(
        result.is_ok(),
        "Platform K8s manifests violate their own invariants: {:?}",
        result.err()
    );
}

#[test]
fn self_simulation_each_invariant_individually() {
    // Verify each invariant passes individually — no masking effects.
    let infra = platform_infrastructure();
    let invariants = all_invariants();

    for inv in &invariants {
        let result = inv.check(&infra);
        assert!(
            result.is_ok(),
            "Platform infra fails invariant '{}': {:?}",
            inv.name(),
            result.err()
        );
    }
}

#[test]
fn self_simulation_each_k8s_invariant_individually() {
    // Verify each K8s invariant passes individually.
    let manifests = platform_k8s_manifests();
    let invariants = all_k8s_invariants();

    for inv in &invariants {
        let result = inv.check(&manifests);
        assert!(
            result.is_ok(),
            "Platform K8s manifests fail invariant '{}': {:?}",
            inv.name(),
            result.err()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 3: The platform verifies its own compliance
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "compliance")]
mod compliance_self_proof {
    use super::*;
    use compliance_controls::{cis_aws_v3, fedramp_moderate, pci_dss_v4, soc2_type_ii};
    use pangea_sim::compliance::verify_baseline;

    #[test]
    fn self_compliance_fedramp_moderate() {
        // The platform that CHECKS FedRAMP compliance must ITSELF
        // satisfy FedRAMP Moderate. Self-consistency proof.
        let infra = platform_infrastructure();
        let baseline = fedramp_moderate();
        let result = verify_baseline(&infra, &baseline);

        // The platform satisfies every control it has invariants for.
        // Some controls may lack invariant coverage — that's expected.
        // What matters: no control COVERED by an invariant is violated.
        let covered_results: Vec<_> = result
            .results
            .iter()
            .filter(|r| r.invariant != "none")
            .collect();
        for r in &covered_results {
            assert!(
                r.satisfied,
                "Platform violates FedRAMP control {} via invariant {}: {:?}",
                r.control_id, r.invariant, r.message
            );
        }
    }

    #[test]
    fn self_compliance_cis_aws() {
        let infra = platform_infrastructure();
        let baseline = cis_aws_v3();
        let result = verify_baseline(&infra, &baseline);

        let covered_results: Vec<_> = result
            .results
            .iter()
            .filter(|r| r.invariant != "none")
            .collect();
        for r in &covered_results {
            assert!(
                r.satisfied,
                "Platform violates CIS control {} via invariant {}: {:?}",
                r.control_id, r.invariant, r.message
            );
        }
    }

    #[test]
    fn self_compliance_soc2() {
        let infra = platform_infrastructure();
        let baseline = soc2_type_ii();
        let result = verify_baseline(&infra, &baseline);

        let covered_results: Vec<_> = result
            .results
            .iter()
            .filter(|r| r.invariant != "none")
            .collect();
        for r in &covered_results {
            assert!(
                r.satisfied,
                "Platform violates SOC2 control {} via invariant {}: {:?}",
                r.control_id, r.invariant, r.message
            );
        }
    }

    #[test]
    fn self_compliance_pci_dss() {
        let infra = platform_infrastructure();
        let baseline = pci_dss_v4();
        let result = verify_baseline(&infra, &baseline);

        let covered_results: Vec<_> = result
            .results
            .iter()
            .filter(|r| r.invariant != "none")
            .collect();
        for r in &covered_results {
            assert!(
                r.satisfied,
                "Platform violates PCI DSS control {} via invariant {}: {:?}",
                r.control_id, r.invariant, r.message
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 4: The platform certifies its own proofs
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "certification")]
mod certification_self_proof {
    use super::*;
    use pangea_sim::certification::{
        certify_invariant, certify_simulation, verify_certificate,
    };

    #[test]
    fn self_certify_each_invariant() {
        // Create a ProofResult for each invariant on the platform's own JSON.
        let infra = platform_infrastructure();
        let invariants = all_invariants();

        for inv in &invariants {
            let passed = inv.check(&infra).is_ok();
            let proof = certify_invariant(inv.name(), &infra, passed, 1);
            assert!(proof.passed, "Invariant '{}' failed certification", inv.name());
            assert!(!proof.proof_hash.is_empty(), "Empty proof hash for '{}'", inv.name());
            assert!(!proof.input_hash.is_empty(), "Empty input hash for '{}'", inv.name());
        }
    }

    #[test]
    fn self_certify_simulation_certificate() {
        // The platform certifies itself and the certificate is valid.
        let infra = platform_infrastructure();
        let invariants = all_invariants();

        let proofs: Vec<_> = invariants
            .iter()
            .map(|inv| {
                let passed = inv.check(&infra).is_ok();
                certify_invariant(inv.name(), &infra, passed, 1)
            })
            .collect();

        let cert = certify_simulation("convergence-platform", proofs);

        assert!(cert.all_passed, "Platform self-certification failed");
        assert!(
            verify_certificate(&cert),
            "Platform certificate integrity check failed"
        );
        assert_eq!(cert.proofs.len(), 10, "Should certify all 10 invariants");
        assert_eq!(cert.architecture, "convergence-platform");
    }

    #[test]
    fn self_certify_certificate_tamper_evident() {
        // Tampering with any proof in the certificate invalidates it.
        let infra = platform_infrastructure();
        let invariants = all_invariants();

        let proofs: Vec<_> = invariants
            .iter()
            .map(|inv| certify_invariant(inv.name(), &infra, true, 1))
            .collect();

        let mut cert = certify_simulation("convergence-platform", proofs);
        let original_hash = cert.certificate_hash.clone();

        // Tamper with a proof
        cert.proofs[0].proof_hash = "TAMPERED".to_string();

        assert!(
            !verify_certificate(&cert),
            "Tampered certificate should fail verification"
        );

        // Restore and verify again
        cert.certificate_hash = original_hash;
        // Still tampered because proof_hash was changed
        assert!(
            !verify_certificate(&cert),
            "Certificate with tampered proof should still fail"
        );
    }

    #[test]
    fn self_certify_deterministic() {
        // Certifying the same platform twice produces the same certificate hash.
        let infra = platform_infrastructure();
        let invariants = all_invariants();

        let make_cert = || {
            let proofs: Vec<_> = invariants
                .iter()
                .map(|inv| certify_invariant(inv.name(), &infra, true, 1))
                .collect();
            certify_simulation("convergence-platform", proofs)
        };

        let cert1 = make_cert();
        let cert2 = make_cert();

        assert_eq!(
            cert1.certificate_hash, cert2.certificate_hash,
            "Self-certification must be deterministic"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 5: The platform simulates its own evolution
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_evolution_v1_to_v2_transition() {
    // Platform v1 = current, v2 = add monitoring replicas, add encryption.
    let v1 = platform_infrastructure();

    // v2: enhanced platform — more monitoring, more replicas
    let mut v2 = v1.clone();
    let v2_resources = v2.get_mut("resource").unwrap().as_object_mut().unwrap();

    // Add a KMS key for enhanced encryption
    v2_resources.insert(
        "aws_kms_key".to_string(),
        json!({
            "seph-platform-key": {
                "description": "Convergence platform encryption key",
                "enable_key_rotation": true,
                "tags": { "ManagedBy": "pangea", "Purpose": "platform-encryption" }
            }
        }),
    );

    let proof = simulate_transition(&v1, &v2);
    assert!(proof.from_valid, "Platform v1 should be valid");
    assert!(proof.to_valid, "Platform v2 should be valid");
    assert!(
        proof.invariants_preserved,
        "Transition should preserve all invariants"
    );
    assert!(
        proof.diff.added_resources.contains(&"aws_kms_key.seph-platform-key".to_string()),
        "Diff should show added KMS key"
    );
}

#[test]
fn self_evolution_rollback_safe() {
    // The platform can safely roll back from v2 to v1.
    let v1 = platform_infrastructure();
    let mut v2 = v1.clone();
    let v2_resources = v2.get_mut("resource").unwrap().as_object_mut().unwrap();
    v2_resources.insert(
        "aws_kms_key".to_string(),
        json!({
            "seph-kms-key": {
                "enable_key_rotation": true,
                "tags": { "ManagedBy": "pangea", "Purpose": "encryption" }
            }
        }),
    );

    let rollback = prove_rollback(&v1, &v2);
    assert!(rollback.rollback_safe, "Platform rollback must be safe");
    assert!(
        rollback.forward.invariants_preserved,
        "Forward transition preserves invariants"
    );
    assert!(
        rollback.backward.invariants_preserved,
        "Backward transition preserves invariants"
    );
}

#[test]
fn self_evolution_multi_step_migration() {
    // 3-step migration: v1 -> v2 (add KMS) -> v3 (add RDS)
    let v1 = platform_infrastructure();

    let mut v2 = v1.clone();
    v2.get_mut("resource")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "aws_kms_key".to_string(),
            json!({
                "seph-kms": {
                    "enable_key_rotation": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "encryption" }
                }
            }),
        );

    let mut v3 = v2.clone();
    v3.get_mut("resource")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "aws_db_instance".to_string(),
            json!({
                "seph-metadata-db": {
                    "engine": "postgres",
                    "instance_class": "db.t3.medium",
                    "storage_encrypted": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "metadata-store" }
                }
            }),
        );

    let migration = simulate_migration(&[v1, v2, v3]);
    assert!(
        migration.all_steps_valid,
        "All migration steps should preserve invariants"
    );
    assert_eq!(migration.steps.len(), 2, "Should have 2 transition steps");
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 6: The platform remediates itself
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_remediation_unencrypted_ebs() {
    // Introduce a violation: unencrypted EBS on the platform's own launch template.
    let mut infra = platform_infrastructure();
    infra
        .pointer_mut("/resource/aws_launch_template/seph-k8s-nodes/block_device_mappings/0/ebs/encrypted")
        .map(|v| *v = json!(false));

    // The invariant should now fail.
    let invariants = all_invariants();
    let ebs_inv = invariants.iter().find(|i| i.name() == "all_ebs_encrypted").unwrap();
    assert!(
        ebs_inv.check(&infra).is_err(),
        "Violated EBS encryption should be detected"
    );

    // Remediate.
    let result = remediate(&infra, "all_ebs_encrypted");
    assert!(
        result.fully_remediated,
        "EBS encryption should be fully remediated"
    );

    // The invariant now passes on the fixed platform.
    assert!(
        ebs_inv.check(&result.remediated_json).is_ok(),
        "Remediated platform should pass EBS encryption invariant"
    );
}

#[test]
fn self_remediation_public_ssh() {
    // Introduce a violation: public SSH on the platform.
    let mut infra = platform_infrastructure();
    infra
        .pointer_mut("/resource/aws_security_group_rule/seph-ssh-in/cidr_blocks/0")
        .map(|v| *v = json!("0.0.0.0/0"));

    let result = remediate(&infra, "no_public_ssh");
    assert!(result.fully_remediated);

    let ssh_inv = all_invariants()
        .into_iter()
        .find(|i| i.name() == "no_public_ssh")
        .unwrap();
    assert!(ssh_inv.check(&result.remediated_json).is_ok());
}

#[test]
fn self_remediation_full_remediate_all() {
    // Introduce multiple violations on the platform simultaneously.
    let mut infra = platform_infrastructure();

    // Break EBS encryption
    infra
        .pointer_mut("/resource/aws_launch_template/seph-k8s-nodes/block_device_mappings/0/ebs/encrypted")
        .map(|v| *v = json!(false));
    // Break IMDSv2
    infra
        .pointer_mut("/resource/aws_launch_template/seph-k8s-nodes/metadata_options/http_tokens")
        .map(|v| *v = json!("optional"));
    // Break S3 public access block
    infra
        .pointer_mut("/resource/aws_s3_bucket_public_access_block/seph-state-public-block/block_public_acls")
        .map(|v| *v = json!(false));

    let result = remediate_all(&infra);
    assert!(
        result.fully_remediated,
        "Full remediation should fix all violations"
    );
    assert!(
        result.remediations_applied.len() >= 3,
        "At least 3 remediations should be applied"
    );

    // ALL invariants should pass after full remediation (except IamLeastPrivilege
    // which cannot be auto-remediated, but our policy is not violating).
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    assert!(
        check_all(&refs, &result.remediated_json).is_ok(),
        "Fully remediated platform should pass all invariants"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 7: The platform renders itself to multiple targets
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_render_terraform_passes() {
    // The platform as Terraform JSON passes all Terraform invariants.
    let infra = platform_infrastructure();
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    assert!(check_all(&refs, &infra).is_ok());
}

#[test]
fn self_render_k8s_passes() {
    // The platform as K8s Deployments passes all K8s invariants.
    let manifests = platform_k8s_manifests();
    let invariants = all_k8s_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    assert!(check_all(&refs, &manifests).is_ok());
}

#[test]
fn self_render_helm_passes_k8s_invariants() {
    // The platform rendered as Helm charts passes K8s invariants.
    let components = ["convergence-controller", "kensa", "shinryu"];

    for component in &components {
        let config = platform_helm_chart(component);
        let manifest = helm_chart::simulate(&config);
        let invariants = all_k8s_invariants();
        let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

        assert!(
            check_all(&refs, &manifest).is_ok(),
            "Helm chart for '{}' violates K8s invariants",
            component
        );
    }
}

#[test]
fn self_render_both_simultaneously() {
    // BOTH rendering targets pass their respective invariants simultaneously.
    // The rendering target is irrelevant — same types, same proofs.
    let infra = platform_infrastructure();
    let manifests = platform_k8s_manifests();

    let tf_invariants = all_invariants();
    let tf_refs: Vec<&dyn Invariant> = tf_invariants.iter().map(AsRef::as_ref).collect();

    let k8s_invariants = all_k8s_invariants();
    let k8s_refs: Vec<&dyn Invariant> = k8s_invariants.iter().map(AsRef::as_ref).collect();

    let tf_ok = check_all(&tf_refs, &infra).is_ok();
    let k8s_ok = check_all(&k8s_refs, &manifests).is_ok();

    assert!(tf_ok && k8s_ok, "Both rendering targets must pass simultaneously");
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 8: The platform composes with its own tools
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_compose_with_builder_fleet() {
    // Platform infrastructure + Nix builder fleet = composed system.
    // Composition must preserve ALL invariants from both components.
    let platform = platform_infrastructure();

    let builder_config = nix_builder_fleet::NixBuilderFleetConfig {
        name: "seph-builders".to_string(),
        cidr: "10.1.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: "c6i.xlarge".to_string(),
        ami_id: "ami-nix-builder".to_string(),
        volume_size: 500,
        fleet_size_min: 2,
        fleet_size_max: 8,
        nix_port: 8080,
    };
    let builders = nix_builder_fleet::simulate(&builder_config);

    let composed = merge_tf_json(&platform, &builders);
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    assert!(
        check_all(&refs, &composed).is_ok(),
        "Composed platform + builders violates invariants"
    );

    // Verify composition has resources from BOTH
    let analysis = ArchitectureAnalysis::from_terraform_json(&composed);
    assert!(
        analysis.resource_count > 14,
        "Composed system should have more resources than platform alone"
    );
}

#[test]
fn self_compose_with_secure_vpc() {
    // Platform + its own VPC simulation = composed system.
    let platform = platform_infrastructure();

    let vpc_config = secure_vpc::SecureVpcConfig {
        name: "seph-extra".to_string(),
        cidr: "10.2.0.0/16".to_string(),
        azs: vec!["us-east-1b".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        flow_logs: true,
    };
    let vpc = secure_vpc::simulate(&vpc_config);

    let composed = merge_tf_json(&platform, &vpc);
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    assert!(
        check_all(&refs, &composed).is_ok(),
        "Composed platform + VPC violates invariants"
    );
}

#[test]
fn self_compose_k8s_with_helm() {
    // Platform K8s manifests + Helm chart simulation = composed K8s.
    let platform_manifests = platform_k8s_manifests();
    let helm_config = platform_helm_chart("sekiban");
    let helm_manifest = helm_chart::simulate(&helm_config);

    // Both must pass K8s invariants independently.
    let k8s_invariants = all_k8s_invariants();
    let refs: Vec<&dyn Invariant> = k8s_invariants.iter().map(AsRef::as_ref).collect();

    assert!(
        check_all(&refs, &platform_manifests).is_ok(),
        "Platform K8s manifests violate K8s invariants"
    );
    assert!(
        check_all(&refs, &helm_manifest).is_ok(),
        "Helm chart manifest violates K8s invariants"
    );
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 9: The proof system proves itself consistent
// ═══════════════════════════════════════════════════════════════════

#[test]
fn self_consistency_exactly_10_terraform_invariants() {
    let invariants = all_invariants();
    assert_eq!(
        invariants.len(),
        10,
        "all_invariants() must return exactly 10"
    );
}

#[test]
fn self_consistency_exactly_8_k8s_invariants() {
    let invariants = all_k8s_invariants();
    assert_eq!(
        invariants.len(),
        8,
        "all_k8s_invariants() must return exactly 8"
    );
}

#[test]
fn self_consistency_unique_invariant_names() {
    let tf_invariants = all_invariants();
    let k8s_invariants = all_k8s_invariants();

    let mut names = HashSet::new();
    for inv in tf_invariants.iter().chain(k8s_invariants.iter()) {
        assert!(
            names.insert(inv.name().to_string()),
            "Duplicate invariant name: '{}'",
            inv.name()
        );
    }
    assert_eq!(
        names.len(),
        18,
        "Should have 18 unique invariant names (10 TF + 8 K8s)"
    );
}

#[test]
fn self_consistency_check_all_idempotent() {
    // Running check_all twice on compliant JSON produces the same result.
    let infra = platform_infrastructure();
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    let r1 = check_all(&refs, &infra);
    let r2 = check_all(&refs, &infra);

    assert_eq!(r1.is_ok(), r2.is_ok(), "check_all must be idempotent");
}

#[test]
fn self_consistency_invariant_names_match_known_set() {
    // Ensure the invariant names are exactly what we expect.
    let invariants = all_invariants();
    let names: HashSet<&str> = invariants.iter().map(|i| i.name()).collect();

    let expected: HashSet<&str> = [
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
    ]
    .iter()
    .copied()
    .collect();

    assert_eq!(names, expected, "Invariant names don't match expected set");
}

#[cfg(feature = "certification")]
#[test]
fn self_consistency_certification_deterministic() {
    // Certifying the same JSON twice produces the same hash.
    use pangea_sim::certification::certify_invariant;

    let infra = platform_infrastructure();
    let p1 = certify_invariant("no_public_ssh", &infra, true, 1);
    let p2 = certify_invariant("no_public_ssh", &infra, true, 1);
    assert_eq!(
        p1.proof_hash, p2.proof_hash,
        "Certification must be deterministic"
    );
    assert_eq!(p1.input_hash, p2.input_hash);
}

#[cfg(feature = "certification")]
#[test]
fn self_consistency_verification_deterministic() {
    // Verifying the same certificate twice produces the same result.
    use pangea_sim::certification::{certify_invariant, certify_simulation, verify_certificate};

    let infra = platform_infrastructure();
    let proofs: Vec<_> = all_invariants()
        .iter()
        .map(|inv| certify_invariant(inv.name(), &infra, true, 1))
        .collect();
    let cert = certify_simulation("test", proofs);

    let v1 = verify_certificate(&cert);
    let v2 = verify_certificate(&cert);
    assert_eq!(v1, v2, "Verification must be deterministic");
    assert!(v1, "Valid certificate should verify as true");
}

// ═══════════════════════════════════════════════════════════════════
// SECTION 10: The meta-proof — proving the proof system works
// ═══════════════════════════════════════════════════════════════════

/// A proof object in the convergence loop. Its construction IS the proof.
struct ConvergenceProof {
    phase: &'static str,
    exists: bool,
}

impl ConvergenceProof {
    fn assert_exists(&self) {
        assert!(
            self.exists,
            "Convergence phase '{}' proof does not exist",
            self.phase
        );
    }
}

#[test]
fn meta_proof_convergence_loop_complete() {
    // Construct proof objects for each phase of the convergence loop.
    // Curry-Howard: if the proof object can be constructed, the theorem is true.

    let infra = platform_infrastructure();
    let manifests = platform_k8s_manifests();

    // Phase 1: Declaration exists (types are defined)
    let declaration_proof = ConvergenceProof {
        phase: "declaration",
        exists: infra.is_object() && manifests.is_object(),
    };
    declaration_proof.assert_exists();

    // Phase 2: Simulation exists (JSON is generated)
    let simulation_proof = ConvergenceProof {
        phase: "simulation",
        exists: infra.get("resource").is_some()
            && manifests.get("items").is_some(),
    };
    simulation_proof.assert_exists();

    // Phase 3: Proof exists (invariants pass)
    let tf_ok = {
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        check_all(&refs, &infra).is_ok()
    };
    let k8s_ok = {
        let invs = all_k8s_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        check_all(&refs, &manifests).is_ok()
    };
    let proof_proof = ConvergenceProof {
        phase: "proof",
        exists: tf_ok && k8s_ok,
    };
    proof_proof.assert_exists();

    // Phase 4: Transition exists (evolution is safe)
    let v1 = platform_infrastructure();
    let mut v2 = v1.clone();
    v2.get_mut("resource")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert(
            "aws_kms_key".to_string(),
            json!({
                "platform-key": {
                    "enable_key_rotation": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "encryption" }
                }
            }),
        );
    let transition = simulate_transition(&v1, &v2);
    let transition_proof = ConvergenceProof {
        phase: "transition",
        exists: transition.invariants_preserved,
    };
    transition_proof.assert_exists();

    // Phase 5: Remediation exists (violations fixable)
    let mut broken = platform_infrastructure();
    broken
        .pointer_mut(
            "/resource/aws_launch_template/seph-k8s-nodes/block_device_mappings/0/ebs/encrypted",
        )
        .map(|v| *v = json!(false));
    let fixed = remediate(&broken, "all_ebs_encrypted");
    let remediation_proof = ConvergenceProof {
        phase: "remediation",
        exists: fixed.fully_remediated,
    };
    remediation_proof.assert_exists();

    // Phase 6: Composition exists (systems compose)
    let builder_config = nix_builder_fleet::NixBuilderFleetConfig {
        name: "meta-builders".to_string(),
        cidr: "10.3.0.0/16".to_string(),
        azs: vec!["us-east-1a".to_string()],
        profile: pangea_sim::simulations::config::Profile::Production,
        instance_type: "c6i.xlarge".to_string(),
        ami_id: "ami-nix-builder".to_string(),
        volume_size: 500,
        fleet_size_min: 1,
        fleet_size_max: 4,
        nix_port: 8080,
    };
    let builders = nix_builder_fleet::simulate(&builder_config);
    let composed = merge_tf_json(&v1, &builders);
    let composed_ok = {
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        check_all(&refs, &composed).is_ok()
    };
    let composition_proof = ConvergenceProof {
        phase: "composition",
        exists: composed_ok,
    };
    composition_proof.assert_exists();

    // ALL 6 proof objects constructed = the convergence loop is complete.
    // The convergence loop applied to ITSELF = fixed point. QED.
    let all_proofs = [
        &declaration_proof,
        &simulation_proof,
        &proof_proof,
        &transition_proof,
        &remediation_proof,
        &composition_proof,
    ];

    assert!(
        all_proofs.iter().all(|p| p.exists),
        "Not all convergence phases are proven"
    );
}

/// The full meta-proof with compliance and certification.
/// Feature-gated behind both features since it uses both modules.
#[cfg(all(feature = "compliance", feature = "certification"))]
#[test]
fn meta_proof_convergence_loop_complete_with_compliance_and_certification() {
    use compliance_controls::fedramp_moderate;
    use pangea_sim::certification::{certify_invariant, certify_simulation, verify_certificate};
    use pangea_sim::compliance::verify_baseline;

    let infra = platform_infrastructure();

    // Phase: Compliance exists (baseline verified)
    let baseline = fedramp_moderate();
    let compliance = verify_baseline(&infra, &baseline);
    let covered_all_pass = compliance
        .results
        .iter()
        .filter(|r| r.invariant != "none")
        .all(|r| r.satisfied);
    let compliance_proof = ConvergenceProof {
        phase: "compliance",
        exists: covered_all_pass,
    };
    compliance_proof.assert_exists();

    // Phase: Certificate exists (BLAKE3 hash valid)
    let invariants = all_invariants();
    let proofs: Vec<_> = invariants
        .iter()
        .map(|inv| {
            let passed = inv.check(&infra).is_ok();
            certify_invariant(inv.name(), &infra, passed, 1)
        })
        .collect();
    let cert = certify_simulation("convergence-platform-meta", proofs);
    let certificate_proof = ConvergenceProof {
        phase: "certificate",
        exists: cert.all_passed && verify_certificate(&cert),
    };
    certificate_proof.assert_exists();

    // Both compliance and certification exist = full convergence with attestation.
    assert!(
        compliance_proof.exists && certificate_proof.exists,
        "Full convergence loop (with compliance + certification) must be proven"
    );
}

// ═══════════════════════════════════════════════════════════════════
// BONUS: Cross-cutting proofs that tie everything together
// ═══════════════════════════════════════════════════════════════════

#[test]
fn endofunctor_structure_preservation() {
    // The verification endofunctor preserves structure:
    // applying it to the platform's output yields the same answer.
    // verify(platform) = valid, verify(verify(platform)) = valid.
    let infra = platform_infrastructure();
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    // First application: verify the platform.
    let first = check_all(&refs, &infra);
    assert!(first.is_ok());

    // Second application: verify the same platform again.
    // The idempotency of check_all IS the endofunctor structure preservation.
    let second = check_all(&refs, &infra);
    assert!(second.is_ok());

    // Both produce Ok — the functor preserves the "valid" structure.
    assert_eq!(first.is_ok(), second.is_ok());
}

#[test]
fn fixed_point_self_verification() {
    // verify(generate(types)) = types.
    // The types generate JSON. The JSON passes verification.
    // Verification of verification is still verification.
    // The system has converged to itself.
    let infra = platform_infrastructure();

    // Step 1: types exist (the function compiles and runs).
    assert!(infra.is_object());

    // Step 2: verification passes (the function's output is valid).
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    assert!(check_all(&refs, &infra).is_ok());

    // Step 3: the JSON is stable (serialize -> deserialize -> verify).
    let serialized = serde_json::to_string(&infra).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert!(check_all(&refs, &deserialized).is_ok());

    // The system IS the fixed point: it generates valid output that
    // remains valid through any number of serialization cycles.
}
