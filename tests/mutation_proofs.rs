//! Mutation engine proofs -- 30+ tests proving the mutation and migration
//! engine transforms systems correctly and monotonically.

use pangea_sim::mutations::{
    apply_migration, apply_mutation, count_satisfied_invariants, optimize_system, plan_migration,
    Mutation, MutationPlan,
};
use proptest::prelude::*;
use serde_json::{json, Value};

// ── Helpers ─────────────────────────────────────────────────────────

/// Build a fully compliant Terraform JSON value.
fn compliant_json() -> Value {
    json!({
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
                    "metadata_options": { "http_tokens": "required" },
                    "block_device_mappings": [{ "ebs": { "encrypted": true } }],
                    "tags": { "ManagedBy": "pangea", "Purpose": "compute" }
                }
            },
            "aws_s3_bucket_public_access_block": {
                "bucket": {
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "storage" }
                }
            },
            "aws_subnet": {
                "private": {
                    "map_public_ip_on_launch": false,
                    "tags": { "ManagedBy": "pangea", "Purpose": "network" }
                }
            },
            "aws_db_instance": {
                "db": {
                    "storage_encrypted": true,
                    "tags": { "ManagedBy": "pangea", "Purpose": "data" }
                }
            },
            "aws_dynamodb_table": {
                "table": {
                    "server_side_encryption": { "enabled": true },
                    "tags": { "ManagedBy": "pangea", "Purpose": "data" }
                }
            },
            "aws_lb": {
                "nlb": {
                    "access_logs": { "enabled": true, "bucket": "logs" },
                    "tags": { "ManagedBy": "pangea", "Purpose": "routing" }
                }
            }
        }
    })
}

/// Build a non-compliant Terraform JSON with multiple violations.
fn non_compliant_json() -> Value {
    json!({
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
                    "metadata_options": { "http_tokens": "optional" },
                    "block_device_mappings": [{ "ebs": { "encrypted": false } }]
                }
            },
            "aws_s3_bucket_public_access_block": {
                "bucket": {
                    "block_public_acls": false,
                    "block_public_policy": false
                }
            },
            "aws_subnet": {
                "exposed": {
                    "map_public_ip_on_launch": true
                }
            },
            "aws_db_instance": {
                "db": {
                    "storage_encrypted": false
                }
            },
            "aws_dynamodb_table": {
                "table": {
                    "name": "test"
                }
            },
            "aws_lb": {
                "nlb": {
                    "name": "test-lb"
                }
            }
        }
    })
}

// ── Test 1: AddResource adds the resource ───────────────────────────

#[test]
fn apply_mutation_add_resource_adds_the_resource() {
    let tf = json!({"resource": {}});
    let result = apply_mutation(
        &tf,
        &Mutation::AddResource {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            config: json!({"cidr_block": "10.0.0.0/16"}),
        },
    );
    assert_eq!(
        result.pointer("/resource/aws_vpc/main/cidr_block"),
        Some(&json!("10.0.0.0/16"))
    );
}

// ── Test 2: RemoveResource removes it ───────────────────────────────

#[test]
fn apply_mutation_remove_resource_removes_it() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::RemoveResource {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
        },
    );
    assert!(result.pointer("/resource/aws_vpc/main").is_none());
}

// ── Test 3: ModifyField changes the value ───────────────────────────

#[test]
fn apply_mutation_modify_field_changes_the_value() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::ModifyField {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            field: "cidr_block".into(),
            value: json!("172.16.0.0/12"),
        },
    );
    assert_eq!(
        result.pointer("/resource/aws_vpc/main/cidr_block"),
        Some(&json!("172.16.0.0/12"))
    );
}

// ── Test 4: AddTags merges correctly ────────────────────────────────

#[test]
fn apply_mutation_add_tags_merges_correctly() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {
                    "cidr_block": "10.0.0.0/16",
                    "tags": {"Existing": "yes"}
                }
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::AddTags {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            tags: vec![
                ("ManagedBy".into(), "pangea".into()),
                ("Purpose".into(), "network".into()),
            ],
        },
    );
    let tags = result.pointer("/resource/aws_vpc/main/tags").unwrap();
    assert_eq!(tags.get("Existing"), Some(&json!("yes")));
    assert_eq!(tags.get("ManagedBy"), Some(&json!("pangea")));
    assert_eq!(tags.get("Purpose"), Some(&json!("network")));
}

// ── Test 5: EnableEncryption sets encrypted: true ───────────────────

#[test]
fn apply_mutation_enable_encryption_sets_encrypted_true() {
    let tf = json!({
        "resource": {
            "aws_ebs_volume": {
                "vol": {"size": 100}
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::EnableEncryption {
            resource_type: "aws_ebs_volume".into(),
            name: "vol".into(),
        },
    );
    assert_eq!(
        result.pointer("/resource/aws_ebs_volume/vol/encrypted"),
        Some(&json!(true))
    );
}

// ── Test 6: RestrictCidr changes CIDR ───────────────────────────────

#[test]
fn apply_mutation_restrict_cidr_changes_cidr() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::RestrictCidr {
            resource_type: "aws_security_group_rule".into(),
            name: "ssh".into(),
            field: "cidr_blocks".into(),
            cidr: "10.0.0.0/8".into(),
        },
    );
    let cidr = result
        .pointer("/resource/aws_security_group_rule/ssh/cidr_blocks/0")
        .unwrap();
    assert_eq!(cidr, &json!("10.0.0.0/8"));
}

// ── Test 7: count_satisfied_invariants on compliant JSON = 10 ───────

#[test]
fn count_satisfied_invariants_on_compliant_json_is_ten() {
    let tf = compliant_json();
    assert_eq!(count_satisfied_invariants(&tf), 10);
}

// ── Test 8: count_satisfied_invariants on empty JSON = 10 ───────────

#[test]
fn count_satisfied_invariants_on_empty_json_is_ten() {
    // Empty JSON has no resources to violate -- all 10 invariants pass vacuously
    assert_eq!(count_satisfied_invariants(&json!({})), 10);
}

// ── Test 9: optimize_system on non-compliant JSON improves count ────

#[test]
fn optimize_system_on_non_compliant_json_improves_invariant_count() {
    let tf = non_compliant_json();
    let before = count_satisfied_invariants(&tf);
    let plan = optimize_system(&tf);
    assert!(
        plan.invariants_after > before,
        "Expected improvement: before={before}, after={}",
        plan.invariants_after
    );
    assert!(!plan.mutations.is_empty());
}

// ── Test 10: optimize_system on already-compliant JSON is idempotent ─

#[test]
fn optimize_system_on_compliant_json_makes_no_mutations() {
    let tf = compliant_json();
    let plan = optimize_system(&tf);
    assert!(
        plan.mutations.is_empty(),
        "Expected no mutations on compliant JSON, got {}",
        plan.mutations.len()
    );
    assert_eq!(plan.invariants_before, 10);
    assert_eq!(plan.invariants_after, 10);
}

// ── Test 11: optimize_system never decreases invariant count ────────

#[test]
fn optimize_system_never_decreases_invariant_count() {
    let tf = non_compliant_json();
    let plan = optimize_system(&tf);
    assert!(
        plan.invariants_after >= plan.invariants_before,
        "Monotonic violation: before={}, after={}",
        plan.invariants_before,
        plan.invariants_after
    );
    assert!(plan.all_steps_safe);
}

// ── Test 12: plan_migration produces correct mutations ──────────────

#[test]
fn plan_migration_produces_correct_mutations_for_add_remove_modify() {
    let current = json!({
        "resource": {
            "aws_vpc": {
                "old": {"cidr_block": "10.0.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "test"}},
                "keep": {"cidr_block": "172.16.0.0/12", "tags": {"ManagedBy": "pangea", "Purpose": "test"}}
            }
        }
    });
    let target = json!({
        "resource": {
            "aws_vpc": {
                "keep": {"cidr_block": "192.168.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "test"}},
                "new": {"cidr_block": "10.10.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "test"}}
            }
        }
    });
    let plan = plan_migration(&current, &target);

    // Should have: 1 remove (old), 1 modify (keep.cidr_block), 1 add (new)
    let has_remove = plan.mutations.iter().any(|m| matches!(m, Mutation::RemoveResource { name, .. } if name == "old"));
    let has_add = plan.mutations.iter().any(|m| matches!(m, Mutation::AddResource { name, .. } if name == "new"));
    let has_modify = plan.mutations.iter().any(|m| matches!(m, Mutation::ModifyField { name, field, .. } if name == "keep" && field == "cidr_block"));

    assert!(has_remove, "Missing remove mutation for 'old'");
    assert!(has_add, "Missing add mutation for 'new'");
    assert!(has_modify, "Missing modify mutation for 'keep'");
}

// ── Test 13: apply_migration tracks invariant status at each step ───

#[test]
fn apply_migration_tracks_invariant_status_at_each_step() {
    let tf = json!({"resource": {}});
    let plan = MutationPlan {
        mutations: vec![
            Mutation::AddResource {
                resource_type: "aws_vpc".into(),
                name: "main".into(),
                config: json!({"cidr_block": "10.0.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "net"}}),
            },
            Mutation::AddResource {
                resource_type: "aws_security_group_rule".into(),
                name: "ssh".into(),
                config: json!({
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": {"ManagedBy": "pangea", "Purpose": "access"}
                }),
            },
        ],
        invariants_before: 10,
        invariants_after: 9,
        all_steps_safe: false,
    };
    let results = apply_migration(&tf, &plan);
    assert_eq!(results.len(), 2);
    // First step: add a VPC -- still compliant
    assert!(results[0].1);
    // Second step: add open SSH rule -- not compliant
    assert!(!results[1].1);
}

// ── Test 14: Each optimization mutation individually preserves existing invariants ─

#[test]
fn each_optimization_mutation_individually_preserves_existing_invariants() {
    let tf = non_compliant_json();
    let before = count_satisfied_invariants(&tf);
    let plan = optimize_system(&tf);

    let mut current = tf.clone();
    for mutation in &plan.mutations {
        current = apply_mutation(&current, mutation);
        let after = count_satisfied_invariants(&current);
        assert!(
            after >= before,
            "Mutation {:?} reduced invariant count from {before} to {after}",
            mutation
        );
    }
}

// ── Test 15: proptest -- random non-compliant systems optimize ──────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proptest_random_non_compliant_systems_optimize(
        has_ssh in any::<bool>(),
        has_ebs in any::<bool>(),
        has_s3 in any::<bool>(),
        has_lb in any::<bool>(),
        has_rds in any::<bool>(),
    ) {
        let mut resources = serde_json::Map::new();

        if has_ssh {
            resources.insert("aws_security_group_rule".into(), json!({
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }));
        }
        if has_ebs {
            resources.insert("aws_launch_template".into(), json!({
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false}}],
                    "metadata_options": {"http_tokens": "optional"}
                }
            }));
        }
        if has_s3 {
            resources.insert("aws_s3_bucket_public_access_block".into(), json!({
                "bucket": {
                    "block_public_acls": false,
                    "block_public_policy": false
                }
            }));
        }
        if has_lb {
            resources.insert("aws_lb".into(), json!({
                "nlb": {"name": "test"}
            }));
        }
        if has_rds {
            resources.insert("aws_db_instance".into(), json!({
                "db": {"storage_encrypted": false}
            }));
        }

        let tf = json!({"resource": resources});
        let before = count_satisfied_invariants(&tf);
        let plan = optimize_system(&tf);
        prop_assert!(
            plan.invariants_after >= before,
            "Invariant count decreased: before={before}, after={}",
            plan.invariants_after
        );
    }
}

// ── Test 16: proptest -- optimize is idempotent ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proptest_optimize_is_idempotent(
        has_ssh in any::<bool>(),
        has_ebs in any::<bool>(),
        has_rds in any::<bool>(),
    ) {
        let mut resources = serde_json::Map::new();

        if has_ssh {
            resources.insert("aws_security_group_rule".into(), json!({
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"]
                }
            }));
        }
        if has_ebs {
            resources.insert("aws_launch_template".into(), json!({
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false}}],
                    "metadata_options": {"http_tokens": "optional"}
                }
            }));
        }
        if has_rds {
            resources.insert("aws_db_instance".into(), json!({
                "db": {"storage_encrypted": false}
            }));
        }

        let tf = json!({"resource": resources});

        // First optimization
        let plan1 = optimize_system(&tf);
        let mut optimized = tf.clone();
        for m in &plan1.mutations {
            optimized = apply_mutation(&optimized, m);
        }

        // Second optimization -- should produce no new mutations
        let plan2 = optimize_system(&optimized);
        prop_assert!(
            plan2.mutations.is_empty(),
            "Second optimize produced {} mutations (not idempotent)",
            plan2.mutations.len()
        );
        prop_assert_eq!(plan2.invariants_before, plan2.invariants_after);
    }
}

// ── Test 17: Migration serialization roundtrip ──────────────────────

#[test]
fn migration_serialization_roundtrip() {
    let plan = MutationPlan {
        mutations: vec![
            Mutation::AddResource {
                resource_type: "aws_vpc".into(),
                name: "main".into(),
                config: json!({"cidr_block": "10.0.0.0/16"}),
            },
            Mutation::ModifyField {
                resource_type: "aws_vpc".into(),
                name: "main".into(),
                field: "cidr_block".into(),
                value: json!("172.16.0.0/12"),
            },
            Mutation::RemoveResource {
                resource_type: "aws_vpc".into(),
                name: "old".into(),
            },
        ],
        invariants_before: 8,
        invariants_after: 10,
        all_steps_safe: true,
    };
    let serialized = serde_json::to_string(&plan).unwrap();
    let deserialized: MutationPlan = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.mutations.len(), 3);
    assert_eq!(deserialized.invariants_before, 8);
    assert_eq!(deserialized.invariants_after, 10);
    assert!(deserialized.all_steps_safe);
}

// ── Test 18: Mutation composition ───────────────────────────────────

#[test]
fn mutation_composition_apply_two_equals_combined_effect() {
    let tf = json!({"resource": {}});

    let m1 = Mutation::AddResource {
        resource_type: "aws_vpc".into(),
        name: "main".into(),
        config: json!({"cidr_block": "10.0.0.0/16"}),
    };
    let m2 = Mutation::ModifyField {
        resource_type: "aws_vpc".into(),
        name: "main".into(),
        field: "cidr_block".into(),
        value: json!("172.16.0.0/12"),
    };

    let step1 = apply_mutation(&tf, &m1);
    let step2 = apply_mutation(&step1, &m2);

    // The composed effect: a VPC with cidr 172.16.0.0/12
    assert_eq!(
        step2.pointer("/resource/aws_vpc/main/cidr_block"),
        Some(&json!("172.16.0.0/12"))
    );
}

// ── Test 19: Mutation reversibility ─────────────────────────────────

#[test]
fn mutation_reversibility_add_then_remove_returns_to_original() {
    let tf = json!({"resource": {"aws_vpc": {}}});

    let add = Mutation::AddResource {
        resource_type: "aws_vpc".into(),
        name: "temp".into(),
        config: json!({"cidr_block": "10.0.0.0/16"}),
    };
    let remove = Mutation::RemoveResource {
        resource_type: "aws_vpc".into(),
        name: "temp".into(),
    };

    let with_resource = apply_mutation(&tf, &add);
    assert!(with_resource.pointer("/resource/aws_vpc/temp").is_some());

    let back = apply_mutation(&with_resource, &remove);
    assert!(back.pointer("/resource/aws_vpc/temp").is_none());
}

// ── Test 20: optimize + count >= count before ───────────────────────

#[test]
fn optimize_system_plus_count_satisfied_at_least_before() {
    let tf = non_compliant_json();
    let before = count_satisfied_invariants(&tf);
    let plan = optimize_system(&tf);

    let mut optimized = tf.clone();
    for m in &plan.mutations {
        optimized = apply_mutation(&optimized, m);
    }
    let after = count_satisfied_invariants(&optimized);
    assert!(after >= before);
    assert_eq!(after, plan.invariants_after);
}

// ── Test 21: Empty system has no mutations ──────────────────────────

#[test]
fn empty_system_produces_no_mutations() {
    let tf = json!({});
    let plan = optimize_system(&tf);
    assert!(plan.mutations.is_empty());
    assert_eq!(plan.invariants_before, 10);
    assert_eq!(plan.invariants_after, 10);
}

// ── Test 22: AddResource to empty root creates resource section ─────

#[test]
fn add_resource_to_empty_root_creates_resource_section() {
    let tf = json!({});
    let result = apply_mutation(
        &tf,
        &Mutation::AddResource {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            config: json!({"cidr_block": "10.0.0.0/16"}),
        },
    );
    assert!(result.get("resource").is_some());
    assert_eq!(
        result.pointer("/resource/aws_vpc/main/cidr_block"),
        Some(&json!("10.0.0.0/16"))
    );
}

// ── Test 23: ModifyField with nested path ───────────────────────────

#[test]
fn modify_field_with_nested_path_works() {
    let tf = json!({
        "resource": {
            "aws_launch_template": {
                "lt": {
                    "metadata_options": {"http_tokens": "optional"}
                }
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::ModifyField {
            resource_type: "aws_launch_template".into(),
            name: "lt".into(),
            field: "metadata_options.http_tokens".into(),
            value: json!("required"),
        },
    );
    assert_eq!(
        result.pointer("/resource/aws_launch_template/lt/metadata_options/http_tokens"),
        Some(&json!("required"))
    );
}

// ── Test 24: AddTags creates tags object when missing ───────────────

#[test]
fn add_tags_creates_tags_object_when_missing() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::AddTags {
            resource_type: "aws_vpc".into(),
            name: "main".into(),
            tags: vec![("ManagedBy".into(), "pangea".into())],
        },
    );
    assert_eq!(
        result.pointer("/resource/aws_vpc/main/tags/ManagedBy"),
        Some(&json!("pangea"))
    );
}

// ── Test 25: plan_migration from identical states produces no mutations ─

#[test]
fn plan_migration_identical_states_produces_no_mutations() {
    let tf = compliant_json();
    let plan = plan_migration(&tf, &tf);
    assert!(
        plan.mutations.is_empty(),
        "Expected no mutations for identical states, got {}",
        plan.mutations.len()
    );
}

// ── Test 26: optimize_system fixes public SSH ───────────────────────

#[test]
fn optimize_system_fixes_public_ssh() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh": {
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "cidr_blocks": ["0.0.0.0/0"],
                    "tags": {"ManagedBy": "pangea", "Purpose": "access"}
                }
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_cidr_fix = plan.mutations.iter().any(|m| {
        matches!(m, Mutation::RestrictCidr { cidr, .. } if cidr == "10.0.0.0/8")
    });
    assert!(has_cidr_fix, "Expected RestrictCidr mutation");
}

// ── Test 27: optimize_system fixes unencrypted EBS ──────────────────

#[test]
fn optimize_system_fixes_unencrypted_ebs() {
    let tf = json!({
        "resource": {
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": false}}],
                    "metadata_options": {"http_tokens": "required"},
                    "tags": {"ManagedBy": "pangea", "Purpose": "compute"}
                }
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_ebs_fix = plan.mutations.iter().any(|m| {
        matches!(m, Mutation::ModifyField { field, .. } if field == "block_device_mappings")
    });
    assert!(has_ebs_fix, "Expected EBS encryption mutation");
}

// ── Test 28: optimize_system adds missing tags ──────────────────────

#[test]
fn optimize_system_adds_missing_tags() {
    let tf = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16"}
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_tags = plan.mutations.iter().any(|m| matches!(m, Mutation::AddTags { .. }));
    assert!(has_tags, "Expected AddTags mutation");
}

// ── Test 29: RemoveResource on non-existent resource is safe ────────

#[test]
fn remove_resource_on_nonexistent_resource_is_safe() {
    let tf = json!({"resource": {"aws_vpc": {}}});
    let result = apply_mutation(
        &tf,
        &Mutation::RemoveResource {
            resource_type: "aws_vpc".into(),
            name: "doesnt_exist".into(),
        },
    );
    // Should not panic, just return unchanged JSON
    assert!(result.pointer("/resource/aws_vpc").is_some());
}

// ── Test 30: Multiple resources all get optimized ───────────────────

#[test]
fn multiple_resources_all_get_optimized() {
    let tf = json!({
        "resource": {
            "aws_db_instance": {
                "db1": {"storage_encrypted": false},
                "db2": {"storage_encrypted": false}
            }
        }
    });
    let plan = optimize_system(&tf);

    // Should have fixes for both db instances + tags for both
    let modify_count = plan
        .mutations
        .iter()
        .filter(|m| matches!(m, Mutation::ModifyField { field, .. } if field == "storage_encrypted"))
        .count();
    assert_eq!(modify_count, 2, "Expected 2 encryption fixes, got {modify_count}");
}

// ── Test 31: optimize_system reaches max invariants ─────────────────

#[test]
fn optimize_system_reaches_max_invariants_on_full_non_compliant() {
    let tf = non_compliant_json();
    let plan = optimize_system(&tf);

    let mut optimized = tf.clone();
    for m in &plan.mutations {
        optimized = apply_mutation(&optimized, m);
    }

    // After optimization, all 10 invariants should pass
    assert_eq!(
        count_satisfied_invariants(&optimized),
        10,
        "Expected all 10 invariants satisfied after optimization"
    );
}

// ── Test 32: plan_migration add-only case ───────────────────────────

#[test]
fn plan_migration_add_only_case() {
    let current = json!({"resource": {}});
    let target = json!({
        "resource": {
            "aws_vpc": {
                "main": {"cidr_block": "10.0.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "net"}}
            }
        }
    });
    let plan = plan_migration(&current, &target);
    assert_eq!(plan.mutations.len(), 1);
    assert!(matches!(&plan.mutations[0], Mutation::AddResource { name, .. } if name == "main"));
}

// ── Test 33: plan_migration remove-only case ────────────────────────

#[test]
fn plan_migration_remove_only_case() {
    let current = json!({
        "resource": {
            "aws_vpc": {
                "old": {"cidr_block": "10.0.0.0/16", "tags": {"ManagedBy": "pangea", "Purpose": "net"}}
            }
        }
    });
    let target = json!({"resource": {}});
    let plan = plan_migration(&current, &target);
    assert_eq!(plan.mutations.len(), 1);
    assert!(matches!(&plan.mutations[0], Mutation::RemoveResource { name, .. } if name == "old"));
}

// ── Test 34: RestrictCidr only affects 0.0.0.0/0 entries ────────────

#[test]
fn restrict_cidr_only_affects_open_cidrs() {
    let tf = json!({
        "resource": {
            "aws_security_group_rule": {
                "ssh": {
                    "cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0", "172.16.0.0/12"]
                }
            }
        }
    });
    let result = apply_mutation(
        &tf,
        &Mutation::RestrictCidr {
            resource_type: "aws_security_group_rule".into(),
            name: "ssh".into(),
            field: "cidr_blocks".into(),
            cidr: "10.0.0.0/8".into(),
        },
    );
    let cidrs = result
        .pointer("/resource/aws_security_group_rule/ssh/cidr_blocks")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(cidrs[0], json!("10.0.0.0/8"));
    assert_eq!(cidrs[1], json!("10.0.0.0/8")); // was 0.0.0.0/0
    assert_eq!(cidrs[2], json!("172.16.0.0/12")); // unchanged
}

// ── Test 35: Mutation enum variant serialization ────────────────────

#[test]
fn mutation_enum_serialization_all_variants() {
    let mutations = vec![
        Mutation::AddResource {
            resource_type: "t".into(),
            name: "n".into(),
            config: json!({}),
        },
        Mutation::RemoveResource {
            resource_type: "t".into(),
            name: "n".into(),
        },
        Mutation::ModifyField {
            resource_type: "t".into(),
            name: "n".into(),
            field: "f".into(),
            value: json!(42),
        },
        Mutation::AddTags {
            resource_type: "t".into(),
            name: "n".into(),
            tags: vec![("k".into(), "v".into())],
        },
        Mutation::EnableEncryption {
            resource_type: "t".into(),
            name: "n".into(),
        },
        Mutation::RestrictCidr {
            resource_type: "t".into(),
            name: "n".into(),
            field: "f".into(),
            cidr: "10.0.0.0/8".into(),
        },
    ];
    for m in &mutations {
        let s = serde_json::to_string(m).unwrap();
        let d: Mutation = serde_json::from_str(&s).unwrap();
        assert_eq!(m, &d);
    }
}

// ── Test 36: optimize_system fixes S3 public access ─────────────────

#[test]
fn optimize_system_fixes_s3_public_access() {
    let tf = json!({
        "resource": {
            "aws_s3_bucket_public_access_block": {
                "bucket": {
                    "block_public_acls": false,
                    "block_public_policy": false,
                    "tags": {"ManagedBy": "pangea", "Purpose": "storage"}
                }
            }
        }
    });
    let before = count_satisfied_invariants(&tf);
    let plan = optimize_system(&tf);
    assert!(plan.invariants_after > before);

    let mut optimized = tf.clone();
    for m in &plan.mutations {
        optimized = apply_mutation(&optimized, m);
    }
    assert_eq!(
        optimized.pointer("/resource/aws_s3_bucket_public_access_block/bucket/block_public_acls"),
        Some(&json!(true))
    );
    assert_eq!(
        optimized.pointer("/resource/aws_s3_bucket_public_access_block/bucket/block_public_policy"),
        Some(&json!(true))
    );
}

// ── Test 37: optimize_system fixes default VPC ──────────────────────

#[test]
fn optimize_system_fixes_default_vpc() {
    let tf = json!({
        "resource": {
            "aws_instance": {
                "server": {
                    "vpc_id": "default",
                    "tags": {"ManagedBy": "pangea", "Purpose": "compute"}
                }
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_vpc_fix = plan.mutations.iter().any(|m| {
        matches!(m, Mutation::ModifyField { field, value, .. } if field == "vpc_id" && value == &json!("vpc-custom"))
    });
    assert!(has_vpc_fix, "Expected vpc_id fix");
}

// ── Test 38: optimize_system enables logging on LBs ─────────────────

#[test]
fn optimize_system_enables_logging_on_lbs() {
    let tf = json!({
        "resource": {
            "aws_lb": {
                "nlb": {
                    "name": "test",
                    "tags": {"ManagedBy": "pangea", "Purpose": "routing"}
                }
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_logging_fix = plan.mutations.iter().any(|m| {
        matches!(m, Mutation::ModifyField { field, .. } if field == "access_logs.enabled")
    });
    assert!(has_logging_fix, "Expected access_logs.enabled fix");
}

// ── Test 39: apply_migration returns correct length ─────────────────

#[test]
fn apply_migration_returns_correct_length() {
    let tf = json!({"resource": {}});
    let plan = MutationPlan {
        mutations: vec![
            Mutation::AddResource {
                resource_type: "aws_vpc".into(),
                name: "a".into(),
                config: json!({"tags": {"ManagedBy": "pangea", "Purpose": "x"}}),
            },
            Mutation::AddResource {
                resource_type: "aws_vpc".into(),
                name: "b".into(),
                config: json!({"tags": {"ManagedBy": "pangea", "Purpose": "y"}}),
            },
            Mutation::AddResource {
                resource_type: "aws_vpc".into(),
                name: "c".into(),
                config: json!({"tags": {"ManagedBy": "pangea", "Purpose": "z"}}),
            },
        ],
        invariants_before: 10,
        invariants_after: 10,
        all_steps_safe: true,
    };
    let results = apply_migration(&tf, &plan);
    assert_eq!(results.len(), 3);
}

// ── Test 40: optimize_system on single-resource JSON ────────────────

#[test]
fn optimize_single_resource_type_dynamodb_encryption() {
    let tf = json!({
        "resource": {
            "aws_dynamodb_table": {
                "table": {
                    "name": "orders",
                    "tags": {"ManagedBy": "pangea", "Purpose": "data"}
                }
            }
        }
    });
    let plan = optimize_system(&tf);
    let has_sse_fix = plan.mutations.iter().any(|m| {
        matches!(m, Mutation::ModifyField { field, .. } if field == "server_side_encryption.enabled")
    });
    assert!(has_sse_fix, "Expected server_side_encryption fix");
}
