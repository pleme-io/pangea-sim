//! Invariant proofs — 16 proptest proofs verifying security invariants
//! hold across random Terraform architectures.

use proptest::prelude::*;
use serde_json::{json, Value};
use std::collections::HashSet;

use pangea_sim::invariants::*;

// ── Strategies ──────────────────────────────────────────────────────

fn arb_resource_name() -> impl Strategy<Value = String> {
    "[a-z][a-z_]{1,12}"
}

fn arb_private_cidr() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("10.0.0.0/8".to_string()),
        Just("10.0.0.0/16".to_string()),
        Just("172.16.0.0/12".to_string()),
        Just("192.168.0.0/16".to_string()),
        Just("10.1.0.0/24".to_string()),
        Just("172.31.0.0/16".to_string()),
    ]
}

/// Required tags for TaggingComplete invariant.
fn required_tags() -> Value {
    json!({
        "ManagedBy": "pangea",
        "Purpose": "test"
    })
}

fn arb_sg_rule(allow_public: bool) -> impl Strategy<Value = Value> {
    let cidr_strategy = if allow_public {
        prop_oneof![
            Just(json!(["0.0.0.0/0"])),
            Just(json!(["::/0"])),
            Just(json!(["0.0.0.0/0", "10.0.0.0/8"])),
        ]
        .boxed()
    } else {
        arb_private_cidr()
            .prop_map(|c| json!([c]))
            .boxed()
    };

    let port_strategy = if allow_public {
        // Specifically include port 22 for public rules
        Just((22_i64, 22_i64)).boxed()
    } else {
        prop_oneof![
            Just((443_i64, 443_i64)),
            Just((80_i64, 80_i64)),
            Just((8080_i64, 8080_i64)),
            Just((3000_i64, 3000_i64)),
            // Port 22 with private CIDRs is fine
            Just((22_i64, 22_i64)),
        ]
        .boxed()
    };

    (cidr_strategy, port_strategy).prop_map(|(cidrs, (from, to))| {
        json!({
            "type": "ingress",
            "from_port": from,
            "to_port": to,
            "protocol": "tcp",
            "cidr_blocks": cidrs,
            "tags": required_tags()
        })
    })
}

fn arb_launch_template(encrypted: bool, imdsv2: bool) -> impl Strategy<Value = Value> {
    let volume_size = 20..=500_i64;
    volume_size.prop_map(move |size| {
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
            "instance_type": "t3.medium",
            "tags": required_tags()
        })
    })
}

fn arb_compliant_architecture() -> impl Strategy<Value = Value> {
    (
        prop::collection::vec(
            (arb_resource_name(), arb_sg_rule(false)),
            0..=4,
        ),
        prop::collection::vec(
            (arb_resource_name(), arb_launch_template(true, true)),
            0..=3,
        ),
    )
        .prop_map(|(sg_rules, templates)| {
            let mut tf = json!({"resource": {}});
            let resources = tf.get_mut("resource").unwrap().as_object_mut().unwrap();

            if !sg_rules.is_empty() {
                let mut sg_map = serde_json::Map::new();
                let mut seen = HashSet::new();
                for (name, rule) in sg_rules {
                    let unique_name = if seen.insert(name.clone()) {
                        name
                    } else {
                        format!("{name}_dup")
                    };
                    sg_map.insert(unique_name, rule);
                }
                resources.insert(
                    "aws_security_group_rule".to_string(),
                    Value::Object(sg_map),
                );
            }

            if !templates.is_empty() {
                let mut lt_map = serde_json::Map::new();
                let mut seen = HashSet::new();
                for (name, tmpl) in templates {
                    let unique_name = if seen.insert(name.clone()) {
                        name
                    } else {
                        format!("{name}_dup")
                    };
                    lt_map.insert(unique_name, tmpl);
                }
                resources.insert(
                    "aws_launch_template".to_string(),
                    Value::Object(lt_map),
                );
            }

            tf
        })
}

fn arb_noncompliant_architecture() -> impl Strategy<Value = Value> {
    // Each variant violates at least one invariant.
    // All resources deliberately omit tags so TaggingComplete always fires.
    prop_oneof![
        // Public SSH violation (0.0.0.0/0 on port 22) + missing tags
        arb_resource_name().prop_map(|name| {
            json!({
                "resource": {
                    "aws_security_group_rule": {
                        name: {
                            "type": "ingress",
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"]
                        }
                    }
                }
            })
        }),
        // Unencrypted EBS violation + missing tags
        (arb_resource_name(), 20..=500_i64).prop_map(|(name, size)| {
            json!({
                "resource": {
                    "aws_launch_template": {
                        name: {
                            "block_device_mappings": [{"ebs": {"encrypted": false, "volume_size": size}}],
                            "metadata_options": {"http_tokens": "required"}
                        }
                    }
                }
            })
        }),
        // Missing IMDSv2 violation + missing tags
        (arb_resource_name(), 20..=500_i64).prop_map(|(name, size)| {
            json!({
                "resource": {
                    "aws_launch_template": {
                        name: {
                            "block_device_mappings": [{"ebs": {"encrypted": true, "volume_size": size}}],
                            "metadata_options": {"http_tokens": "optional"}
                        }
                    }
                }
            })
        }),
    ]
}

/// Strategy for arbitrary JSON (limited depth for performance).
fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        "[a-zA-Z0-9_/.:]{0,30}".prop_map(|s| Value::String(s)),
    ];

    leaf.prop_recursive(
        3,  // depth
        64, // max nodes
        8,  // items per collection
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..=4)
                    .prop_map(Value::Array),
                prop::collection::vec(
                    ("[a-z_]{1,10}", inner),
                    0..=4,
                )
                    .prop_map(|pairs| {
                        let map: serde_json::Map<String, Value> = pairs.into_iter().collect();
                        Value::Object(map)
                    }),
            ]
        },
    )
}

// ── Helper ──────────────────────────────────────────────────────────

// ── Proofs 1-3: Existing invariants pass on compliant architectures ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Proof 1: NoPublicSsh passes on compliant architectures.
    #[test]
    fn no_public_ssh_passes_compliant(arch in arb_compliant_architecture()) {
        prop_assert!(
            NoPublicSsh.check(&arch).is_ok(),
            "NoPublicSsh failed on compliant architecture: {arch}"
        );
    }

    /// Proof 2: AllEbsEncrypted passes on compliant architectures.
    #[test]
    fn all_ebs_encrypted_passes_compliant(arch in arb_compliant_architecture()) {
        prop_assert!(
            AllEbsEncrypted.check(&arch).is_ok(),
            "AllEbsEncrypted failed on compliant architecture: {arch}"
        );
    }

    /// Proof 3: ImdsV2Required passes on compliant architectures.
    #[test]
    fn imdsv2_required_passes_compliant(arch in arb_compliant_architecture()) {
        prop_assert!(
            ImdsV2Required.check(&arch).is_ok(),
            "ImdsV2Required failed on compliant architecture: {arch}"
        );
    }
}

// ── Proofs 4-10: All invariants pass individually on compliant archs ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Proof 4: check_all passes on compliant architectures.
    #[test]
    fn check_all_passes_compliant(arch in arb_compliant_architecture()) {
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        prop_assert!(
            check_all(&inv_refs, &arch).is_ok(),
            "check_all failed on compliant architecture"
        );
    }

    /// Proof 5: NoPublicSsh correctly detects public SSH.
    #[test]
    fn no_public_ssh_detects_violations(arch in arb_noncompliant_architecture()) {
        // Only check architectures that have SG rules with public CIDRs on port 22
        if let Some(rules) = arch.pointer("/resource/aws_security_group_rule") {
            if let Some(rules_map) = rules.as_object() {
                let has_public_ssh = rules_map.values().any(|rule| {
                    let from = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
                    let to = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
                    let is_ingress = rule.get("type").and_then(Value::as_str) == Some("ingress");
                    let has_public = rule.get("cidr_blocks")
                        .and_then(Value::as_array)
                        .map_or(false, |cidrs| {
                            cidrs.iter().any(|c| c.as_str() == Some("0.0.0.0/0"))
                        });
                    is_ingress && from <= 22 && to >= 22 && has_public
                });
                if has_public_ssh {
                    prop_assert!(
                        NoPublicSsh.check(&arch).is_err(),
                        "NoPublicSsh should have detected public SSH"
                    );
                }
            }
        }
    }

    /// Proof 6: AllEbsEncrypted correctly detects unencrypted volumes.
    #[test]
    fn all_ebs_encrypted_detects_violations(arch in arb_noncompliant_architecture()) {
        if let Some(templates) = arch.pointer("/resource/aws_launch_template") {
            if let Some(tmpl_map) = templates.as_object() {
                let has_unencrypted = tmpl_map.values().any(|tmpl| {
                    tmpl.get("block_device_mappings")
                        .and_then(Value::as_array)
                        .map_or(false, |mappings| {
                            mappings.iter().any(|m| {
                                m.pointer("/ebs/encrypted")
                                    .and_then(Value::as_bool)
                                    == Some(false)
                            })
                        })
                });
                if has_unencrypted {
                    prop_assert!(
                        AllEbsEncrypted.check(&arch).is_err(),
                        "AllEbsEncrypted should have detected unencrypted EBS"
                    );
                }
            }
        }
    }

    /// Proof 7: ImdsV2Required correctly detects missing IMDSv2.
    #[test]
    fn imdsv2_detects_violations(arch in arb_noncompliant_architecture()) {
        if let Some(templates) = arch.pointer("/resource/aws_launch_template") {
            if let Some(tmpl_map) = templates.as_object() {
                let has_optional = tmpl_map.values().any(|tmpl| {
                    tmpl.pointer("/metadata_options/http_tokens")
                        .and_then(Value::as_str)
                        != Some("required")
                });
                if has_optional {
                    prop_assert!(
                        ImdsV2Required.check(&arch).is_err(),
                        "ImdsV2Required should have detected missing IMDSv2"
                    );
                }
            }
        }
    }

    /// Proof 8: Noncompliant architectures fail at least one invariant.
    #[test]
    fn noncompliant_fails_at_least_one(arch in arb_noncompliant_architecture()) {
        let invs = all_invariants();
        let any_failed = invs.iter().any(|inv| inv.check(&arch).is_err());
        prop_assert!(
            any_failed,
            "noncompliant architecture passed all invariants: {arch}"
        );
    }

    /// Proof 9: Compliant arch with extra non-security resources still passes.
    #[test]
    fn compliant_with_extra_resources_passes(
        arch in arb_compliant_architecture(),
        extra_name in arb_resource_name(),
    ) {
        let mut enriched = arch.clone();
        // Add a non-security resource with required tags
        if let Some(resources) = enriched.get_mut("resource").and_then(Value::as_object_mut) {
            let mut vpc = serde_json::Map::new();
            vpc.insert(extra_name, json!({
                "cidr_block": "10.0.0.0/16",
                "tags": required_tags()
            }));
            resources.insert("aws_vpc".to_string(), Value::Object(vpc));
        }
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        prop_assert!(check_all(&inv_refs, &enriched).is_ok());
    }

    /// Proof 10: Each invariant on a compliant arch passes independently.
    #[test]
    fn each_invariant_independent_on_compliant(arch in arb_compliant_architecture()) {
        let invs = all_invariants();
        for inv in &invs {
            prop_assert!(
                inv.check(&arch).is_ok(),
                "invariant '{}' failed independently on compliant arch",
                inv.name()
            );
        }
    }
}

// ── Proof 11: Empty JSON passes all invariants ──────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1))]

    /// Proof 11: Empty JSON value passes all invariants.
    #[test]
    fn empty_json_passes_all(_ in Just(())) {
        let empty_cases: Vec<Value> = vec![
            json!({}),
            json!({"resource": {}}),
            json!(null),
            json!({"resource": {"aws_security_group_rule": {}}}),
            json!({"resource": {"aws_launch_template": {}}}),
        ];
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        for tf in &empty_cases {
            prop_assert!(
                check_all(&inv_refs, tf).is_ok(),
                "empty-ish JSON failed: {tf}"
            );
        }
    }
}

// ── Proof 12: Invariant check is pure ───────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    /// Proof 12: Same input always produces same result (purity).
    #[test]
    fn invariant_check_is_pure(arch in arb_compliant_architecture()) {
        let invs = all_invariants();
        for inv in &invs {
            let r1 = inv.check(&arch);
            let r2 = inv.check(&arch);
            match (&r1, &r2) {
                (Ok(()), Ok(())) => {}
                (Err(v1), Err(v2)) => {
                    prop_assert_eq!(
                        v1.len(), v2.len(),
                        "invariant '{}' returned different violation counts",
                        inv.name()
                    );
                }
                _ => prop_assert!(
                    false,
                    "invariant '{}' returned different Ok/Err across runs",
                    inv.name()
                ),
            }
        }
    }
}

// ── Proof 13: check_all violations == union of individual checks ────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5_000))]

    /// Proof 13: check_all violations are the union of individual checks.
    #[test]
    fn check_all_is_union_of_individual(arch in arb_noncompliant_architecture()) {
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();

        // Collect individual violations
        let mut individual_total = 0_usize;
        for inv in &invs {
            if let Err(violations) = inv.check(&arch) {
                individual_total += violations.len();
            }
        }

        // Collect check_all violations
        let all_total = match check_all(&inv_refs, &arch) {
            Ok(()) => 0,
            Err(violations) => violations.len(),
        };

        prop_assert!(
            individual_total == all_total,
            "individual sum ({}) != check_all ({})",
            individual_total, all_total
        );
    }
}

// ── Proof 14: Violation count is monotone ───────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Proof 14: Adding a bad resource never decreases violation count.
    #[test]
    fn violation_count_monotone(
        arch in arb_compliant_architecture(),
        bad_name in arb_resource_name(),
    ) {
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();

        let base_violations = match check_all(&inv_refs, &arch) {
            Ok(()) => 0,
            Err(v) => v.len(),
        };

        // Add a noncompliant resource (unencrypted EBS + optional IMDSv2)
        let mut bad_arch = arch.clone();
        let resources = bad_arch
            .as_object_mut()
            .unwrap()
            .entry("resource")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .unwrap();

        let mut lt_map = resources
            .get("aws_launch_template")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        lt_map.insert(
            format!("bad_{bad_name}"),
            json!({
                "block_device_mappings": [{"ebs": {"encrypted": false}}],
                "metadata_options": {"http_tokens": "optional"}
            }),
        );
        resources.insert(
            "aws_launch_template".to_string(),
            Value::Object(lt_map),
        );

        let invs2 = all_invariants();
        let inv_refs2: Vec<&dyn Invariant> = invs2.iter().map(AsRef::as_ref).collect();
        let new_violations = match check_all(&inv_refs2, &bad_arch) {
            Ok(()) => 0,
            Err(v) => v.len(),
        };

        prop_assert!(
            new_violations >= base_violations,
            "violations decreased: {base_violations} -> {new_violations}"
        );
    }
}

// ── Proof 15: Invariant names are unique ────────────────────────────

#[test]
fn invariant_names_are_unique() {
    let invs = all_invariants();
    let mut names = HashSet::new();
    for inv in &invs {
        assert!(
            names.insert(inv.name().to_string()),
            "duplicate invariant name: {}",
            inv.name()
        );
    }
    // Also verify we actually have invariants
    assert!(
        !invs.is_empty(),
        "all_invariants() returned no invariants"
    );
}

// ── Proof 16: No invariant panics on arbitrary JSON ─────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Proof 16: No invariant panics on arbitrary JSON.
    #[test]
    fn no_invariant_panics_on_arbitrary_json(val in arb_json()) {
        let invs = all_invariants();
        for inv in &invs {
            // This must not panic — Ok or Err are both acceptable
            let _result = inv.check(&val);
        }
    }
}
