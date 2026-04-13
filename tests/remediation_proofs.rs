//! Remediation proofs -- prove that auto-remediation produces compliant output.
//!
//! The key property: `remediate(json, "X")` -> json passes invariant X.
//! This must hold for ALL inputs. Proven via proptest across 500 random configs.

use proptest::prelude::*;
use serde_json::{json, Value};
use std::collections::HashSet;

use pangea_sim::invariants::*;
use pangea_sim::remediation::{can_remediate, remediate, remediate_all};

// ── Strategies ──────────────────────────────────────────────────────

fn arb_resource_name() -> impl Strategy<Value = String> {
    "[a-z][a-z_]{1,12}"
}

/// Generate a security group rule that may or may not be compliant.
fn arb_sg_rule_mixed() -> impl Strategy<Value = Value> {
    let cidr_strategy = prop_oneof![
        Just(json!(["0.0.0.0/0"])),
        Just(json!(["10.0.0.0/8"])),
        Just(json!(["172.16.0.0/12"])),
        Just(json!(["0.0.0.0/0", "10.0.0.0/8"])),
    ];

    let port_strategy = prop_oneof![
        Just((22_i64, 22_i64)),
        Just((443_i64, 443_i64)),
        Just((80_i64, 80_i64)),
        Just((0_i64, 65535_i64)),
    ];

    let type_strategy = prop_oneof![Just("ingress".to_string()), Just("egress".to_string()),];

    (cidr_strategy, port_strategy, type_strategy).prop_map(|(cidrs, (from, to), rule_type)| {
        json!({
            "type": rule_type,
            "from_port": from,
            "to_port": to,
            "protocol": "tcp",
            "cidr_blocks": cidrs
        })
    })
}

/// Generate a launch template that may or may not be compliant.
fn arb_launch_template_mixed() -> impl Strategy<Value = Value> {
    (
        prop::bool::ANY,
        prop::bool::ANY,
        20..=500_i64,
    )
        .prop_map(|(encrypted, imdsv2, size)| {
            json!({
                "block_device_mappings": [{
                    "ebs": {
                        "encrypted": encrypted,
                        "volume_size": size
                    }
                }],
                "metadata_options": {
                    "http_tokens": if imdsv2 { "required" } else { "optional" }
                },
                "instance_type": "t3.medium"
            })
        })
}

/// Generate an S3 public access block that may or may not be compliant.
fn arb_s3_block_mixed() -> impl Strategy<Value = Value> {
    (prop::bool::ANY, prop::bool::ANY).prop_map(|(block_acls, block_policy)| {
        json!({
            "block_public_acls": block_acls,
            "block_public_policy": block_policy
        })
    })
}

/// Generate a VPC resource that may or may not use default VPC.
fn arb_vpc_resource_mixed() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({"vpc_id": "default", "instance_type": "t3.micro"})),
        Just(json!({"vpc_id": "vpc-abc123", "instance_type": "t3.micro"})),
        Just(json!({"vpc_id": "vpc-custom", "instance_type": "t3.micro"})),
    ]
}

/// Generate a subnet that may or may not be compliant.
fn arb_subnet_mixed() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!({"map_public_ip_on_launch": true, "cidr_block": "10.0.1.0/24"})),
        Just(json!({"map_public_ip_on_launch": false, "cidr_block": "10.0.2.0/24"})),
        Just(json!({"map_public_ip_on_launch": true, "cidr_block": "10.0.3.0/24", "tags": {"Tier": "public"}})),
    ]
}

/// Generate an RDS instance that may or may not be compliant.
fn arb_rds_mixed() -> impl Strategy<Value = Value> {
    prop::bool::ANY.prop_map(|encrypted| {
        json!({
            "storage_encrypted": encrypted,
            "engine": "postgres"
        })
    })
}

/// Generate a DynamoDB table that may or may not be compliant.
fn arb_dynamodb_mixed() -> impl Strategy<Value = Value> {
    prop::bool::ANY.prop_map(|sse| {
        let mut tbl = json!({"name": "test", "hash_key": "id"});
        if sse {
            tbl.as_object_mut()
                .unwrap()
                .insert("server_side_encryption".into(), json!({"enabled": true}));
        }
        tbl
    })
}

/// Generate a load balancer that may or may not be compliant.
fn arb_lb_mixed() -> impl Strategy<Value = Value> {
    prop::bool::ANY.prop_map(|logging| {
        let mut lb = json!({"name": "test-lb"});
        if logging {
            lb.as_object_mut()
                .unwrap()
                .insert("access_logs".into(), json!({"enabled": true, "bucket": "logs"}));
        }
        lb
    })
}

/// Build a Terraform JSON from mixed-compliance components.
fn arb_mixed_architecture() -> impl Strategy<Value = Value> {
    (
        prop::collection::vec((arb_resource_name(), arb_sg_rule_mixed()), 0..=3),
        prop::collection::vec((arb_resource_name(), arb_launch_template_mixed()), 0..=3),
        prop::collection::vec((arb_resource_name(), arb_s3_block_mixed()), 0..=2),
        prop::collection::vec((arb_resource_name(), arb_rds_mixed()), 0..=2),
        prop::collection::vec((arb_resource_name(), arb_dynamodb_mixed()), 0..=2),
        prop::collection::vec((arb_resource_name(), arb_lb_mixed()), 0..=2),
        prop::collection::vec((arb_resource_name(), arb_vpc_resource_mixed()), 0..=2),
        prop::collection::vec((arb_resource_name(), arb_subnet_mixed()), 0..=2),
    )
        .prop_map(
            |(sg_rules, templates, s3_blocks, rds, dynamo, lbs, vpc_resources, subnets)| {
                let mut tf = json!({"resource": {}});
                let resources = tf.get_mut("resource").unwrap().as_object_mut().unwrap();

                fn insert_resources(
                    resources: &mut serde_json::Map<String, Value>,
                    resource_type: &str,
                    items: Vec<(String, Value)>,
                ) {
                    if !items.is_empty() {
                        let mut map = serde_json::Map::new();
                        let mut seen = HashSet::new();
                        for (name, val) in items {
                            let unique = if seen.insert(name.clone()) {
                                name
                            } else {
                                format!("{name}_dup")
                            };
                            map.insert(unique, val);
                        }
                        resources.insert(resource_type.to_string(), Value::Object(map));
                    }
                }

                insert_resources(resources, "aws_security_group_rule", sg_rules);
                insert_resources(resources, "aws_launch_template", templates);
                insert_resources(resources, "aws_s3_bucket_public_access_block", s3_blocks);
                insert_resources(resources, "aws_db_instance", rds);
                insert_resources(resources, "aws_dynamodb_table", dynamo);
                insert_resources(resources, "aws_lb", lbs);
                insert_resources(resources, "aws_instance", vpc_resources);
                insert_resources(resources, "aws_subnet", subnets);

                tf
            },
        )
}

// ── Core proofs (1-5): specific remediation correctness ───────────

#[test]
fn proof_01_remediate_public_ssh_restricts_cidr() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "open_ssh": {
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
    let result = remediate(&tf, "no_public_ssh");
    assert!(result.fully_remediated, "SSH remediation must produce compliant output");
    assert_eq!(result.original_violations, 1);
    assert_eq!(result.remaining_violations, 0);

    let cidr = result
        .remediated_json
        .pointer("/resource/aws_security_group_rule/open_ssh/cidr_blocks/0")
        .unwrap();
    assert_eq!(cidr, "10.0.0.0/8", "CIDR must be restricted to private range");
}

#[test]
fn proof_02_remediate_ebs_encryption_sets_encrypted() {
    let tf = json!({
        "resource": {
            "aws_launch_template": {
                "plain": {
                    "block_device_mappings": [{"ebs": {"encrypted": false, "volume_size": 50}}],
                    "metadata_options": {"http_tokens": "required"},
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });
    let result = remediate(&tf, "all_ebs_encrypted");
    assert!(result.fully_remediated, "EBS encryption remediation must succeed");

    let encrypted = result
        .remediated_json
        .pointer("/resource/aws_launch_template/plain/block_device_mappings/0/ebs/encrypted")
        .unwrap();
    assert_eq!(encrypted, true);
}

#[test]
fn proof_03_remediate_imds_v2_sets_required() {
    let tf = json!({
        "resource": {
            "aws_launch_template": {
                "missing_imds": {
                    "instance_type": "t3.micro",
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });
    let result = remediate(&tf, "imdsv2_required");
    assert!(result.fully_remediated, "IMDSv2 remediation must succeed");

    let tokens = result
        .remediated_json
        .pointer("/resource/aws_launch_template/missing_imds/metadata_options/http_tokens")
        .unwrap();
    assert_eq!(tokens, "required");
}

#[test]
fn proof_04_remediate_public_s3_blocks_all_access() {
    let tf = json!({
        "resource": {
            "aws_s3_bucket_public_access_block": {
                "wide_open": {
                    "block_public_acls": false,
                    "block_public_policy": false,
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });
    let result = remediate(&tf, "no_public_s3");
    assert!(result.fully_remediated, "S3 public access remediation must succeed");
    assert_eq!(result.remediations_applied.len(), 2, "Two fields fixed (acls + policy)");
}

#[test]
fn proof_05_remediate_tags_adds_managed_by_and_purpose() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            },
            "aws_subnet": {
                "private": {"cidr_block": "10.0.1.0/24"}
            }
        }
    });
    let result = remediate(&tf, "tagging_complete");
    assert!(result.fully_remediated, "Tagging remediation must succeed");

    // Both resources should have tags
    for path in &[
        "/resource/aws_vpc/main/tags/ManagedBy",
        "/resource/aws_vpc/main/tags/Purpose",
        "/resource/aws_subnet/private/tags/ManagedBy",
        "/resource/aws_subnet/private/tags/Purpose",
    ] {
        assert!(
            result.remediated_json.pointer(path).is_some(),
            "Tag {path} must exist after remediation"
        );
    }
}

// ── Closure proofs (6-9): remediate -> invariant passes (proptest) ─

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// PROOF 6: After remediate("no_public_ssh"), NoPublicSsh invariant passes.
    #[test]
    fn proof_06_closure_no_public_ssh(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "no_public_ssh");
        let check = NoPublicSsh.check(&result.remediated_json);
        prop_assert!(
            check.is_ok(),
            "NoPublicSsh must pass after remediation. Violations: {:?}",
            check.err()
        );
    }

    /// PROOF 7: After remediate("all_ebs_encrypted"), AllEbsEncrypted invariant passes.
    #[test]
    fn proof_07_closure_all_ebs_encrypted(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "all_ebs_encrypted");
        let check = AllEbsEncrypted.check(&result.remediated_json);
        prop_assert!(
            check.is_ok(),
            "AllEbsEncrypted must pass after remediation. Violations: {:?}",
            check.err()
        );
    }

    /// PROOF 8: After remediate("tagging_complete"), TaggingComplete invariant passes.
    #[test]
    fn proof_08_closure_tagging_complete(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "tagging_complete");
        let check = TaggingComplete.check(&result.remediated_json);
        prop_assert!(
            check.is_ok(),
            "TaggingComplete must pass after remediation. Violations: {:?}",
            check.err()
        );
    }

    /// PROOF 9: remediate_all on arbitrary JSON -> all fixable invariants pass.
    #[test]
    fn proof_09_closure_remediate_all(tf in arb_mixed_architecture()) {
        let result = remediate_all(&tf);
        let json = &result.remediated_json;

        // Check every remediated invariant
        prop_assert!(NoPublicSsh.check(json).is_ok(), "NoPublicSsh failed after remediate_all");
        prop_assert!(AllEbsEncrypted.check(json).is_ok(), "AllEbsEncrypted failed after remediate_all");
        prop_assert!(ImdsV2Required.check(json).is_ok(), "ImdsV2Required failed after remediate_all");
        prop_assert!(NoPublicS3.check(json).is_ok(), "NoPublicS3 failed after remediate_all");
        prop_assert!(NoDefaultVpcUsage.check(json).is_ok(), "NoDefaultVpcUsage failed after remediate_all");
        prop_assert!(AllSubnetsPrivate.check(json).is_ok(), "AllSubnetsPrivate failed after remediate_all");
        prop_assert!(EncryptionAtRest.check(json).is_ok(), "EncryptionAtRest failed after remediate_all");
        prop_assert!(LoggingEnabled.check(json).is_ok(), "LoggingEnabled failed after remediate_all");
        prop_assert!(TaggingComplete.check(json).is_ok(), "TaggingComplete failed after remediate_all");

        prop_assert!(
            result.fully_remediated,
            "remediate_all must report fully_remediated=true. remaining={}",
            result.remaining_violations
        );
    }
}

// ── Idempotency proofs (10-11) ────────────────────────────────────

#[test]
fn proof_10_remediate_already_compliant_is_noop() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["10.0.0.0/8"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "access" }
                }
            },
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": true, "volume_size": 100}}],
                    "metadata_options": {"http_tokens": "required"},
                    "tags": { "ManagedBy": "pangea", "Purpose": "compute" }
                }
            },
            "aws_s3_bucket_public_access_block": {
                "block": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "storage" }
                }
            }
        }
    });

    let result = remediate_all(&tf);
    assert!(result.fully_remediated);
    assert_eq!(
        result.remediations_applied.len(),
        0,
        "No remediations should be applied to already-compliant JSON"
    );
    assert_eq!(result.remediated_json, tf, "JSON should be unchanged");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// PROOF 11: remediate(remediate(json)) == remediate(json) (idempotent).
    #[test]
    fn proof_11_remediate_is_idempotent(tf in arb_mixed_architecture()) {
        let first = remediate_all(&tf);
        let second = remediate_all(&first.remediated_json);

        prop_assert_eq!(
            &first.remediated_json,
            &second.remediated_json,
            "Applying remediation twice must produce the same result"
        );
        prop_assert_eq!(
            second.remediations_applied.len(),
            0,
            "Second remediation pass should apply zero changes"
        );
    }
}

// ── Determinism proof (12) ────────────────────────────────────────

#[test]
fn proof_12_remediation_is_deterministic() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh_open": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            },
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false}}],
                    "metadata_options": {"http_tokens": "optional"}
                }
            },
            "aws_s3_bucket_public_access_block": {
                "s3": {
                    "block_public_acls": false,
                    "block_public_policy": false
                }
            },
            "aws_db_instance": {
                "db": {"storage_encrypted": false}
            },
            "aws_lb": {
                "lb": {"name": "test"}
            }
        }
    });

    // Run remediation 10 times, verify identical output each time
    let baseline = remediate_all(&tf);
    for _ in 0..10 {
        let run = remediate_all(&tf);
        assert_eq!(
            baseline.remediated_json, run.remediated_json,
            "Remediation must be deterministic across runs"
        );
        assert_eq!(
            baseline.remediations_applied.len(),
            run.remediations_applied.len(),
            "Remediation count must be deterministic"
        );
    }
}

// ── Integration proofs (13-15) ────────────────────────────────────

#[test]
fn proof_13_remediate_then_verify_all_invariants() {
    // Build maximally non-compliant JSON
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            },
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false, "volume_size": 100}}],
                    "metadata_options": {"http_tokens": "optional"}
                }
            },
            "aws_s3_bucket_public_access_block": {
                "s3": {"block_public_acls": false, "block_public_policy": false}
            },
            "aws_instance": {
                "server": {"vpc_id": "default"}
            },
            "aws_subnet": {
                "exposed": {"map_public_ip_on_launch": true, "cidr_block": "10.0.1.0/24"}
            },
            "aws_db_instance": {
                "db": {"storage_encrypted": false, "engine": "postgres"}
            },
            "aws_dynamodb_table": {
                "tbl": {"name": "test", "hash_key": "id"}
            },
            "aws_lb": {
                "lb": {"name": "main-lb"}
            }
        }
    });

    // Verify it IS non-compliant before remediation
    let invs = all_invariants();
    let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
    let pre_check = check_all(&inv_refs, &tf);
    assert!(pre_check.is_err(), "Input must be non-compliant");

    // Remediate
    let result = remediate_all(&tf);
    assert!(result.fully_remediated);

    // Verify all fixable invariants pass
    for inv in &invs {
        if can_remediate(inv.name()) {
            let check = inv.check(&result.remediated_json);
            assert!(
                check.is_ok(),
                "Invariant {} should pass after remediate_all. Violations: {:?}",
                inv.name(),
                check.err()
            );
        }
    }
}

#[test]
fn proof_14_remediation_preserves_resources() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            },
            "aws_security_group_rule": {
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            },
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false}}],
                    "metadata_options": {"http_tokens": "optional"},
                    "instance_type": "t3.medium"
                }
            }
        }
    });

    let result = remediate_all(&tf);

    // All original resource types still exist
    let original_types: HashSet<String> = tf
        .get("resource")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let remediated_types: HashSet<String> = result
        .remediated_json
        .get("resource")
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();

    assert!(
        original_types.is_subset(&remediated_types),
        "Remediation must not delete any resource type. Missing: {:?}",
        original_types.difference(&remediated_types)
    );

    // All original resource names still exist within their types
    for (rtype, instances) in tf.get("resource").unwrap().as_object().unwrap() {
        let original_names: HashSet<String> = instances
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let remediated_names: HashSet<String> = result
            .remediated_json
            .pointer(&format!("/resource/{rtype}"))
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        assert!(
            original_names.is_subset(&remediated_names),
            "Remediation must not delete resources of type {rtype}. Missing: {:?}",
            original_names.difference(&remediated_names)
        );
    }

    // Non-security fields are preserved (instance_type on launch template)
    assert_eq!(
        result
            .remediated_json
            .pointer("/resource/aws_launch_template/lt/instance_type"),
        Some(&json!("t3.medium")),
        "Non-security fields must be preserved"
    );
}

#[test]
fn proof_15_remediation_count_matches_violations() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh1": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                },
                "ssh2": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                }
            }
        }
    });

    let result = remediate(&tf, "no_public_ssh");
    assert_eq!(
        result.original_violations,
        result.remediations_applied.len(),
        "Number of remediations should match number of original violations"
    );
    assert_eq!(result.original_violations, 2);
    assert_eq!(result.remaining_violations, 0);
}

// ── Additional closure proofs for remaining invariants ─────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Closure proof: After remediate("imdsv2_required"), ImdsV2Required passes.
    #[test]
    fn proof_closure_imdsv2(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "imdsv2_required");
        let check = ImdsV2Required.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "ImdsV2Required must pass after remediation");
    }

    /// Closure proof: After remediate("no_public_s3"), NoPublicS3 passes.
    #[test]
    fn proof_closure_no_public_s3(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "no_public_s3");
        let check = NoPublicS3.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "NoPublicS3 must pass after remediation");
    }

    /// Closure proof: After remediate("no_default_vpc_usage"), NoDefaultVpcUsage passes.
    #[test]
    fn proof_closure_no_default_vpc(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "no_default_vpc_usage");
        let check = NoDefaultVpcUsage.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "NoDefaultVpcUsage must pass after remediation");
    }

    /// Closure proof: After remediate("all_subnets_private"), AllSubnetsPrivate passes.
    #[test]
    fn proof_closure_all_subnets_private(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "all_subnets_private");
        let check = AllSubnetsPrivate.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "AllSubnetsPrivate must pass after remediation");
    }

    /// Closure proof: After remediate("encryption_at_rest"), EncryptionAtRest passes.
    #[test]
    fn proof_closure_encryption_at_rest(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "encryption_at_rest");
        let check = EncryptionAtRest.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "EncryptionAtRest must pass after remediation");
    }

    /// Closure proof: After remediate("logging_enabled"), LoggingEnabled passes.
    #[test]
    fn proof_closure_logging_enabled(tf in arb_mixed_architecture()) {
        let result = remediate(&tf, "logging_enabled");
        let check = LoggingEnabled.check(&result.remediated_json);
        prop_assert!(check.is_ok(), "LoggingEnabled must pass after remediation");
    }
}
