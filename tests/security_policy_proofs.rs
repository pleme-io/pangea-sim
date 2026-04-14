//! Security policy proofs -- the Rust type system enforces security policy consistency.
//!
//! These tests prove that:
//! 1. Valid policies pass all invariant checks
//! 2. Conflicting allow/deny rules are detected
//! 3. Wildcard resources and unjustified Admin access fail least-privilege
//! 4. Separation of duties violations are caught
//! 5. Defense in depth requires multiple policy layers
//! 6. Policies serialize and deserialize without loss
//! 7. Real-world IAM, RBAC, and NetworkPolicy models are verified
//! 8. Random valid policies satisfy no-conflicts (500 cases via proptest)

use pangea_sim::security_policies::*;
use proptest::prelude::*;

// ── Helpers ──────────────────────────────────────────────────────

fn valid_iam_policy() -> SecurityPolicy {
    SecurityPolicy {
        name: "production-iam".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![
            PolicyRule {
                subject: "developer".to_string(),
                action: Action::Read,
                resource: "s3://app-data".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
            PolicyRule {
                subject: "developer".to_string(),
                action: Action::Write,
                resource: "s3://app-data".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
            PolicyRule {
                subject: "default".to_string(),
                action: Action::Read,
                resource: "s3://app-data".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
            PolicyRule {
                subject: "default".to_string(),
                action: Action::Write,
                resource: "s3://app-data".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    }
}

fn valid_rbac_policy() -> SecurityPolicy {
    SecurityPolicy {
        name: "k8s-rbac".to_string(),
        layer: PolicyLayer::KubernetesRbac,
        rules: vec![
            PolicyRule {
                subject: "sa:app".to_string(),
                action: Action::Read,
                resource: "pods".to_string(),
                effect: Effect::Allow,
                conditions: vec!["namespace=production".to_string()],
            },
            PolicyRule {
                subject: "sa:app".to_string(),
                action: Action::Read,
                resource: "configmaps".to_string(),
                effect: Effect::Allow,
                conditions: vec!["namespace=production".to_string()],
            },
            PolicyRule {
                subject: "default".to_string(),
                action: Action::Admin,
                resource: "pods".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    }
}

fn valid_network_policy() -> SecurityPolicy {
    SecurityPolicy {
        name: "network-policy".to_string(),
        layer: PolicyLayer::Network,
        rules: vec![
            PolicyRule {
                subject: "10.0.0.0/8".to_string(),
                action: Action::Read,
                resource: "port:443".to_string(),
                effect: Effect::Allow,
                conditions: vec!["protocol=tcp".to_string()],
            },
            PolicyRule {
                subject: "0.0.0.0/0".to_string(),
                action: Action::Read,
                resource: "port:22".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 1: Valid policy passes no-conflicts check
// ══════════════════════════════════════════════════════════════════

#[test]
fn valid_policy_passes_no_conflicts() {
    let policy = valid_iam_policy();
    assert!(
        check_no_conflicts(&policy).is_ok(),
        "Valid IAM policy should have no conflicts"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 2: Conflicting allow/deny detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn conflicting_allow_deny_detected() {
    let policy = SecurityPolicy {
        name: "conflicting".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![
            PolicyRule {
                subject: "admin".to_string(),
                action: Action::Write,
                resource: "s3://secrets".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
            PolicyRule {
                subject: "admin".to_string(),
                action: Action::Write,
                resource: "s3://secrets".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    };

    let result = check_no_conflicts(&policy);
    assert!(result.is_err(), "Should detect allow/deny conflict");
    let msg = result.unwrap_err();
    assert!(
        msg.contains("admin"),
        "Error should mention conflicting subject"
    );
    assert!(
        msg.contains("s3://secrets"),
        "Error should mention conflicting resource"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 3: Wildcard resource fails least-privilege
// ══════════════════════════════════════════════════════════════════

#[test]
fn wildcard_resource_fails_least_privilege() {
    let policy = SecurityPolicy {
        name: "wildcard".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![PolicyRule {
            subject: "developer".to_string(),
            action: Action::Read,
            resource: "*".to_string(),
            effect: Effect::Allow,
            conditions: vec![],
        }],
    };

    let result = check_least_privilege(&policy);
    assert!(result.is_err(), "Wildcard resource should fail least-privilege");
    assert!(result.unwrap_err().contains("wildcard resource '*'"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 4: Admin without justification fails
// ══════════════════════════════════════════════════════════════════

#[test]
fn admin_without_justification_fails() {
    let policy = SecurityPolicy {
        name: "unjustified-admin".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![PolicyRule {
            subject: "user".to_string(),
            action: Action::Admin,
            resource: "database".to_string(),
            effect: Effect::Allow,
            conditions: vec![], // no justification
        }],
    };

    let result = check_least_privilege(&policy);
    assert!(
        result.is_err(),
        "Admin without conditions should fail least-privilege"
    );
    assert!(result.unwrap_err().contains("Admin access"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 5: Admin WITH justification passes
// ══════════════════════════════════════════════════════════════════

#[test]
fn admin_with_justification_passes() {
    let policy = SecurityPolicy {
        name: "justified-admin".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![PolicyRule {
            subject: "break-glass".to_string(),
            action: Action::Admin,
            resource: "database".to_string(),
            effect: Effect::Allow,
            conditions: vec!["MFA required".to_string(), "Incident ticket".to_string()],
        }],
    };

    assert!(
        check_least_privilege(&policy).is_ok(),
        "Admin with conditions should pass least-privilege"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 6: Separation of duties detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn separation_of_duties_violation_detected() {
    let policy = SecurityPolicy {
        name: "duty-violation".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![
            PolicyRule {
                subject: "devops".to_string(),
                action: Action::Write,
                resource: "production-db".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
            PolicyRule {
                subject: "devops".to_string(),
                action: Action::Admin,
                resource: "production-db".to_string(),
                effect: Effect::Allow,
                conditions: vec!["MFA".to_string()],
            },
        ],
    };

    let result = check_separation_of_duties(&policy);
    assert!(result.is_err(), "Write + Admin on same resource should violate SoD");
    assert!(result.unwrap_err().contains("separation of duties"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 7: Valid policy passes separation of duties
// ══════════════════════════════════════════════════════════════════

#[test]
fn valid_policy_passes_separation_of_duties() {
    let policy = SecurityPolicy {
        name: "proper-sod".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![
            PolicyRule {
                subject: "developer".to_string(),
                action: Action::Write,
                resource: "production-db".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
            PolicyRule {
                subject: "admin".to_string(),
                action: Action::Admin,
                resource: "production-db".to_string(),
                effect: Effect::Allow,
                conditions: vec!["MFA".to_string()],
            },
        ],
    };

    assert!(
        check_separation_of_duties(&policy).is_ok(),
        "Different subjects for Write and Admin should pass SoD"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 8: Defense in depth requires multiple policy layers
// ══════════════════════════════════════════════════════════════════

#[test]
fn defense_in_depth_requires_multiple_layers() {
    // Single layer fails
    let single = vec![valid_iam_policy()];
    let result = check_defense_in_depth(&single);
    assert!(
        result.is_err(),
        "Single policy layer should fail defense-in-depth"
    );

    // Two layers passes
    let multi = vec![valid_iam_policy(), valid_network_policy()];
    assert!(
        check_defense_in_depth(&multi).is_ok(),
        "IAM + Network layers should pass defense-in-depth"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 9: Policy serialization roundtrip
// ══════════════════════════════════════════════════════════════════

#[test]
fn policy_serialization_roundtrip() {
    let policy = valid_iam_policy();
    let json_str = serde_json::to_string(&policy).expect("serialize SecurityPolicy");
    let roundtrip: SecurityPolicy =
        serde_json::from_str(&json_str).expect("deserialize SecurityPolicy");

    assert_eq!(policy.name, roundtrip.name);
    assert_eq!(policy.layer, roundtrip.layer);
    assert_eq!(policy.rules.len(), roundtrip.rules.len());
    for (orig, rt) in policy.rules.iter().zip(roundtrip.rules.iter()) {
        assert_eq!(orig.subject, rt.subject);
        assert_eq!(orig.action, rt.action);
        assert_eq!(orig.resource, rt.resource);
        assert_eq!(orig.effect, rt.effect);
        assert_eq!(orig.conditions, rt.conditions);
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 10: Proptest -- random valid policies satisfy no-conflicts (500 cases)
// ══════════════════════════════════════════════════════════════════

fn arb_effect() -> impl Strategy<Value = Effect> {
    prop_oneof![Just(Effect::Allow), Just(Effect::Deny)]
}

fn arb_action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Read),
        Just(Action::Write),
        Just(Action::Delete),
    ]
}

fn arb_layer() -> impl Strategy<Value = PolicyLayer> {
    prop_oneof![
        Just(PolicyLayer::Iam),
        Just(PolicyLayer::KubernetesRbac),
        Just(PolicyLayer::Network),
        Just(PolicyLayer::Application),
    ]
}

/// Generate a valid (conflict-free) policy: each (subject, resource, action) pair
/// appears at most once, so no allow/deny conflict can exist.
fn arb_valid_policy() -> impl Strategy<Value = SecurityPolicy> {
    (
        "[a-z][a-z0-9-]{2,10}",
        arb_layer(),
        prop::collection::vec(
            (
                prop::sample::select(vec![
                    "user-a".to_string(),
                    "user-b".to_string(),
                    "sa:app".to_string(),
                    "role:admin".to_string(),
                ]),
                arb_action(),
                prop::sample::select(vec![
                    "bucket-logs".to_string(),
                    "table-users".to_string(),
                    "namespace-prod".to_string(),
                    "port:443".to_string(),
                ]),
                arb_effect(),
            ),
            1..=8,
        ),
    )
        .prop_map(|(name, layer, raw_rules)| {
            // Deduplicate by (subject, resource, action) to prevent conflicts
            let mut seen = std::collections::BTreeSet::new();
            let mut rules = Vec::new();
            for (subject, action, resource, effect) in raw_rules {
                let key = format!("{subject}:{resource}:{action:?}");
                if seen.insert(key) {
                    rules.push(PolicyRule {
                        subject,
                        action,
                        resource,
                        effect,
                        conditions: vec![],
                    });
                }
            }
            SecurityPolicy {
                name,
                layer,
                rules,
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn random_valid_policies_have_no_conflicts(policy in arb_valid_policy()) {
        prop_assert!(
            check_no_conflicts(&policy).is_ok(),
            "Deduplicated policy should never have conflicts: {:?}",
            policy.name
        );
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 11: Real-world IAM policy modeled and verified
// ══════════════════════════════════════════════════════════════════

#[test]
fn real_world_iam_policy_verified() {
    let policy = SecurityPolicy {
        name: "aws-iam-s3-readonly".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![
            // Allow read to specific bucket
            PolicyRule {
                subject: "role:s3-reader".to_string(),
                action: Action::Read,
                resource: "arn:aws:s3:::production-assets".to_string(),
                effect: Effect::Allow,
                conditions: vec!["aws:SourceIp=10.0.0.0/8".to_string()],
            },
            // Deny all writes
            PolicyRule {
                subject: "role:s3-reader".to_string(),
                action: Action::Write,
                resource: "arn:aws:s3:::production-assets".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
            // Deny delete
            PolicyRule {
                subject: "role:s3-reader".to_string(),
                action: Action::Delete,
                resource: "arn:aws:s3:::production-assets".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    };

    assert!(check_no_conflicts(&policy).is_ok(), "No conflicts");
    assert!(check_least_privilege(&policy).is_ok(), "No wildcard resources");
    assert!(check_deny_by_default(&policy).is_ok(), "Has deny rules");
    assert!(
        check_separation_of_duties(&policy).is_ok(),
        "No Write+Admin on same resource"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 12: K8s RBAC policy modeled and verified
// ══════════════════════════════════════════════════════════════════

#[test]
fn k8s_rbac_policy_verified() {
    let policy = valid_rbac_policy();

    assert!(check_no_conflicts(&policy).is_ok(), "No conflicts in RBAC policy");
    assert!(
        check_least_privilege(&policy).is_ok(),
        "RBAC policy uses specific resources"
    );
    assert!(check_deny_by_default(&policy).is_ok(), "Has deny rules");
}

// ══════════════════════════════════════════════════════════════════
// Proof 13: Network policy modeled and verified
// ══════════════════════════════════════════════════════════════════

#[test]
fn network_policy_verified() {
    let policy = valid_network_policy();

    assert!(check_no_conflicts(&policy).is_ok(), "No conflicts");
    assert!(
        check_least_privilege(&policy).is_ok(),
        "No wildcard resources"
    );
    assert!(check_deny_by_default(&policy).is_ok(), "SSH denied from 0.0.0.0/0");
}

// ══════════════════════════════════════════════════════════════════
// Proof 14: Combined IAM + RBAC + NetworkPolicy passes defense-in-depth
// ══════════════════════════════════════════════════════════════════

#[test]
fn combined_policies_pass_defense_in_depth() {
    let policies = vec![
        valid_iam_policy(),
        valid_rbac_policy(),
        valid_network_policy(),
    ];

    // Defense in depth: 3 layers (IAM, RBAC, Network)
    assert!(
        check_defense_in_depth(&policies).is_ok(),
        "3 policy layers should satisfy defense-in-depth"
    );

    // Each individual policy should also pass its own invariants
    for policy in &policies {
        assert!(
            check_no_conflicts(policy).is_ok(),
            "Policy '{}' should have no conflicts",
            policy.name
        );
        assert!(
            check_least_privilege(policy).is_ok(),
            "Policy '{}' should satisfy least-privilege",
            policy.name
        );
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 15: Deny-by-default fails when no deny rules exist
// ══════════════════════════════════════════════════════════════════

#[test]
fn deny_by_default_fails_without_deny_rules() {
    let policy = SecurityPolicy {
        name: "allow-only".to_string(),
        layer: PolicyLayer::Application,
        rules: vec![
            PolicyRule {
                subject: "anyone".to_string(),
                action: Action::Read,
                resource: "public-api".to_string(),
                effect: Effect::Allow,
                conditions: vec![],
            },
        ],
    };

    let result = check_deny_by_default(&policy);
    assert!(
        result.is_err(),
        "Policy with only Allow rules should fail deny-by-default"
    );
    assert!(result.unwrap_err().contains("no explicit Deny rules"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 16: Custom action type serializes correctly
// ══════════════════════════════════════════════════════════════════

#[test]
fn custom_action_serializes_correctly() {
    let rule = PolicyRule {
        subject: "service".to_string(),
        action: Action::Custom("deploy".to_string()),
        resource: "namespace:production".to_string(),
        effect: Effect::Allow,
        conditions: vec!["ci-pipeline=true".to_string()],
    };

    let json_str = serde_json::to_string(&rule).expect("serialize PolicyRule");
    let roundtrip: PolicyRule = serde_json::from_str(&json_str).expect("deserialize PolicyRule");
    assert_eq!(rule.action, roundtrip.action);
    assert_eq!(rule.conditions, roundtrip.conditions);
}

// ══════════════════════════════════════════════════════════════════
// Proof 17: Empty policy passes no-conflicts and least-privilege
// ══════════════════════════════════════════════════════════════════

#[test]
fn empty_policy_passes_structural_checks() {
    let policy = SecurityPolicy {
        name: "empty".to_string(),
        layer: PolicyLayer::Iam,
        rules: vec![],
    };

    assert!(check_no_conflicts(&policy).is_ok(), "Empty policy has no conflicts");
    assert!(
        check_least_privilege(&policy).is_ok(),
        "Empty policy has no privilege violations"
    );
    assert!(
        check_separation_of_duties(&policy).is_ok(),
        "Empty policy has no duty violations"
    );
    // But it fails deny-by-default (no deny rules)
    assert!(
        check_deny_by_default(&policy).is_err(),
        "Empty policy should fail deny-by-default"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 18: Application layer policy with all checks
// ══════════════════════════════════════════════════════════════════

#[test]
fn application_layer_policy_full_verification() {
    let policy = SecurityPolicy {
        name: "api-gateway".to_string(),
        layer: PolicyLayer::Application,
        rules: vec![
            PolicyRule {
                subject: "authenticated-user".to_string(),
                action: Action::Read,
                resource: "/api/v1/data".to_string(),
                effect: Effect::Allow,
                conditions: vec!["Bearer token valid".to_string()],
            },
            PolicyRule {
                subject: "admin".to_string(),
                action: Action::Write,
                resource: "/api/v1/data".to_string(),
                effect: Effect::Allow,
                conditions: vec!["Bearer token valid".to_string()],
            },
            PolicyRule {
                subject: "anonymous".to_string(),
                action: Action::Read,
                resource: "/api/v1/data".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
            PolicyRule {
                subject: "anonymous".to_string(),
                action: Action::Write,
                resource: "/api/v1/data".to_string(),
                effect: Effect::Deny,
                conditions: vec![],
            },
        ],
    };

    assert!(check_no_conflicts(&policy).is_ok());
    assert!(check_least_privilege(&policy).is_ok());
    assert!(check_deny_by_default(&policy).is_ok());
    assert!(check_separation_of_duties(&policy).is_ok());
}
