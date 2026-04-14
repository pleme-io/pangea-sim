//! Business environment proofs -- prove that entire businesses can be modeled,
//! verified, and rendered to working infrastructure through the convergence platform.
//!
//! These tests prove that:
//! 1. Business environments satisfy business-level invariants
//! 2. The SAME business declaration renders to BOTH Terraform JSON and K8s manifests
//! 3. Rendered infrastructure passes ALL existing infrastructure invariants
//! 4. Rendered K8s manifests pass ALL existing K8s manifest invariants
//! 5. Different business tiers produce correct, proven infrastructure
//! 6. Business evolution (tier upgrades) preserves invariants at every stage
//! 7. Multi-tenant environments with different baselines are all proven correct

use pangea_sim::business::*;
use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::invariants::k8s::all_k8s_invariants;
use proptest::prelude::*;

// ── Helpers ──────────────────────────────────────────────────────

fn startup_env() -> BusinessEnvironment {
    BusinessEnvironment {
        name: "acme-startup".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![Service {
            name: "api".to_string(),
            replicas: 1,
            cpu_limit: "500m".to_string(),
            memory_limit: "256Mi".to_string(),
            public: false,
        }],
        data_stores: vec![DataStore {
            name: "db".to_string(),
            store_type: DataStoreType::Postgres,
            encrypted: true,
            backup_enabled: true,
        }],
        integrations: vec![],
    }
}

fn enterprise_env() -> BusinessEnvironment {
    BusinessEnvironment {
        name: "globex-enterprise".to_string(),
        tier: Tier::Enterprise,
        compliance_baselines: vec!["SOC2".to_string()],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 3,
                cpu_limit: "1".to_string(),
                memory_limit: "1Gi".to_string(),
                public: true,
            },
            Service {
                name: "worker".to_string(),
                replicas: 2,
                cpu_limit: "500m".to_string(),
                memory_limit: "512Mi".to_string(),
                public: false,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "primary-db".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "cache".to_string(),
                store_type: DataStoreType::Redis,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "assets".to_string(),
                store_type: DataStoreType::S3,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![
            Integration {
                name: "auth-provider".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
            Integration {
                name: "monitoring".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
        ],
    }
}

fn regulated_env() -> BusinessEnvironment {
    BusinessEnvironment {
        name: "fintech-regulated".to_string(),
        tier: Tier::Regulated,
        compliance_baselines: vec!["FedRAMP".to_string(), "SOC2".to_string(), "PCI-DSS".to_string()],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 4,
                cpu_limit: "2".to_string(),
                memory_limit: "2Gi".to_string(),
                public: true,
            },
            Service {
                name: "worker".to_string(),
                replicas: 3,
                cpu_limit: "1".to_string(),
                memory_limit: "1Gi".to_string(),
                public: false,
            },
            Service {
                name: "audit".to_string(),
                replicas: 2,
                cpu_limit: "500m".to_string(),
                memory_limit: "512Mi".to_string(),
                public: false,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "primary-db".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "audit-log".to_string(),
                store_type: DataStoreType::DynamoDB,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "documents".to_string(),
                store_type: DataStoreType::S3,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![
            Integration {
                name: "okta-sso".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
            Integration {
                name: "stripe-payments".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
        ],
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 1: Startup environment passes basic invariants
// ══════════════════════════════════════════════════════════════════

#[test]
fn startup_passes_basic_invariants() {
    let env = startup_env();
    assert!(check_data_encrypted(&env).is_ok(), "Data should be encrypted");
    assert!(check_backups_enabled(&env).is_ok(), "Backups should be enabled");
    assert!(
        check_services_have_limits(&env).is_ok(),
        "Services should have limits"
    );
    assert!(
        check_compliance_covered(&env).is_ok(),
        "Startup tier has no compliance requirement"
    );
    assert!(
        check_all_invariants(&env).is_ok(),
        "All invariants should pass for startup"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 2: Enterprise environment passes all invariants
// ══════════════════════════════════════════════════════════════════

#[test]
fn enterprise_passes_all_invariants() {
    let env = enterprise_env();
    assert!(
        check_all_invariants(&env).is_ok(),
        "All invariants should pass for enterprise: {:?}",
        check_all_invariants(&env).err()
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 3: Regulated environment passes compliance check
// ══════════════════════════════════════════════════════════════════

#[test]
fn regulated_passes_compliance_check() {
    let env = regulated_env();
    assert!(
        check_compliance_covered(&env).is_ok(),
        "Regulated env with 3 baselines should pass compliance check"
    );
    assert!(
        check_all_invariants(&env).is_ok(),
        "All invariants should pass for regulated"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 4: Missing encryption detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn missing_encryption_detected() {
    let env = BusinessEnvironment {
        name: "unencrypted".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![],
        data_stores: vec![DataStore {
            name: "secrets-db".to_string(),
            store_type: DataStoreType::Postgres,
            encrypted: false,
            backup_enabled: true,
        }],
        integrations: vec![],
    };

    let result = check_data_encrypted(&env);
    assert!(result.is_err(), "Unencrypted data store should be detected");
    assert!(result.unwrap_err().contains("secrets-db"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 5: Missing backups detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn missing_backups_detected() {
    let env = BusinessEnvironment {
        name: "no-backup".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![],
        data_stores: vec![DataStore {
            name: "critical-data".to_string(),
            store_type: DataStoreType::DynamoDB,
            encrypted: true,
            backup_enabled: false,
        }],
        integrations: vec![],
    };

    let result = check_backups_enabled(&env);
    assert!(result.is_err(), "Missing backups should be detected");
    assert!(result.unwrap_err().contains("critical-data"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 6: Public service without auth detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn public_service_without_auth_detected() {
    let env = BusinessEnvironment {
        name: "insecure".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![Service {
            name: "open-api".to_string(),
            replicas: 1,
            cpu_limit: "500m".to_string(),
            memory_limit: "256Mi".to_string(),
            public: true,
        }],
        data_stores: vec![],
        integrations: vec![], // No authenticated integration
    };

    let result = check_public_services_authenticated(&env);
    assert!(result.is_err(), "Public service without auth should be detected");
    assert!(result.unwrap_err().contains("open-api"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 7: Business env -> Terraform JSON -> passes Terraform invariants
// ══════════════════════════════════════════════════════════════════

#[test]
fn business_to_terraform_passes_invariants() {
    let env = enterprise_env();
    let tf_json = simulate_infrastructure(&env);

    // Verify it has resources
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf_json);
    assert!(analysis.resource_count >= 5, "Should produce 5+ resources");
    assert!(
        analysis.has_resource("aws_vpc", 1),
        "Should have a VPC"
    );

    // Verify ALL 10 Terraform invariants hold
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    check_all(&refs, &tf_json).expect("All Terraform invariants should hold for business env");
}

// ══════════════════════════════════════════════════════════════════
// Proof 8: Business env -> K8s JSON -> passes K8s invariants
// ══════════════════════════════════════════════════════════════════

#[test]
fn business_to_k8s_passes_invariants() {
    let env = enterprise_env();
    let k8s_json = simulate_k8s(&env);

    // Verify it has the expected structure
    assert_eq!(
        k8s_json.get("kind").and_then(serde_json::Value::as_str),
        Some("List"),
        "Should produce a K8s List"
    );
    let items = k8s_json
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("Should have items");
    assert_eq!(items.len(), 2, "Enterprise env has 2 services");

    // Verify K8s invariants hold on each item
    let k8s_invs = all_k8s_invariants();
    for item in items {
        let k8s_refs: Vec<&dyn Invariant> = k8s_invs.iter().map(AsRef::as_ref).collect();
        check_all(&k8s_refs, item)
            .expect("All K8s invariants should hold for business env service");
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 9: SAME business env -> BOTH targets -> BOTH pass
// ══════════════════════════════════════════════════════════════════

#[test]
fn same_env_renders_to_both_targets_correctly() {
    let env = regulated_env();

    // Render to Terraform
    let tf_json = simulate_infrastructure(&env);
    let tf_invs = all_invariants();
    let tf_refs: Vec<&dyn Invariant> = tf_invs.iter().map(AsRef::as_ref).collect();
    check_all(&tf_refs, &tf_json).expect("Terraform invariants hold");

    // Render to K8s
    let k8s_json = simulate_k8s(&env);
    let k8s_invs = all_k8s_invariants();
    let items = k8s_json
        .get("items")
        .and_then(serde_json::Value::as_array)
        .expect("Should have items");
    for item in items {
        let k8s_refs: Vec<&dyn Invariant> = k8s_invs.iter().map(AsRef::as_ref).collect();
        check_all(&k8s_refs, item).expect("K8s invariants hold");
    }

    // Both passed from the SAME declaration -- render anywhere is proven
    let analysis = ArchitectureAnalysis::from_terraform_json(&tf_json);
    assert!(analysis.resource_count >= 5, "Terraform has resources");
    assert_eq!(items.len(), 3, "K8s has 3 services");
}

// ══════════════════════════════════════════════════════════════════
// Proof 10: Customer onboarding -- 3 tiers, all proven correct
// ══════════════════════════════════════════════════════════════════

#[test]
fn three_customer_tiers_all_proven() {
    let customers = vec![
        startup_env(),
        enterprise_env(),
        regulated_env(),
    ];

    for customer in &customers {
        // Business invariants
        assert!(
            check_all_invariants(customer).is_ok(),
            "Business invariants failed for '{}' ({:?}): {:?}",
            customer.name,
            customer.tier,
            check_all_invariants(customer).err()
        );

        // Terraform invariants
        let tf_json = simulate_infrastructure(customer);
        let tf_invs = all_invariants();
        let tf_refs: Vec<&dyn Invariant> = tf_invs.iter().map(AsRef::as_ref).collect();
        check_all(&tf_refs, &tf_json).unwrap_or_else(|_| {
            panic!(
                "Terraform invariants failed for '{}' ({:?})",
                customer.name, customer.tier
            );
        });

        // K8s invariants
        let k8s_json = simulate_k8s(customer);
        let k8s_invs = all_k8s_invariants();
        let items = k8s_json
            .get("items")
            .and_then(serde_json::Value::as_array)
            .expect("items");
        for item in items {
            let k8s_refs: Vec<&dyn Invariant> = k8s_invs.iter().map(AsRef::as_ref).collect();
            check_all(&k8s_refs, item).unwrap_or_else(|_| {
                panic!(
                    "K8s invariants failed for '{}' ({:?})",
                    customer.name, customer.tier
                );
            });
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 11: Proptest -- random valid business environments (500 cases)
// ══════════════════════════════════════════════════════════════════

fn arb_tier() -> impl Strategy<Value = Tier> {
    prop_oneof![
        Just(Tier::Startup),
        Just(Tier::Growth),
    ]
}

fn arb_data_store_type() -> impl Strategy<Value = DataStoreType> {
    prop_oneof![
        Just(DataStoreType::Postgres),
        Just(DataStoreType::S3),
        Just(DataStoreType::DynamoDB),
    ]
}

fn arb_valid_env() -> impl Strategy<Value = BusinessEnvironment> {
    (
        "[a-z][a-z0-9]{2,10}",
        arb_tier(),
        prop::collection::vec(
            (
                "[a-z]{3,8}",
                1..=4u32,
                prop::sample::select(vec![
                    "500m".to_string(),
                    "1".to_string(),
                    "2".to_string(),
                ]),
                prop::sample::select(vec![
                    "256Mi".to_string(),
                    "512Mi".to_string(),
                    "1Gi".to_string(),
                ]),
            ),
            1..=3,
        ),
        prop::collection::vec(
            ("[a-z]{3,8}", arb_data_store_type()),
            0..=2,
        ),
    )
        .prop_map(|(name, tier, services, data_stores)| {
            let services = services
                .into_iter()
                .map(|(svc_name, replicas, cpu, mem)| Service {
                    name: svc_name,
                    replicas,
                    cpu_limit: cpu,
                    memory_limit: mem,
                    public: false,
                })
                .collect();

            let data_stores = data_stores
                .into_iter()
                .map(|(ds_name, ds_type)| DataStore {
                    name: ds_name,
                    store_type: ds_type,
                    encrypted: true,
                    backup_enabled: true,
                })
                .collect();

            BusinessEnvironment {
                name,
                tier,
                compliance_baselines: vec![],
                services,
                data_stores,
                integrations: vec![],
            }
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn random_valid_envs_satisfy_all_invariants(env in arb_valid_env()) {
        // Business invariants
        prop_assert!(
            check_all_invariants(&env).is_ok(),
            "Business invariants failed for '{}'",
            env.name
        );

        // Terraform invariants
        let tf_json = simulate_infrastructure(&env);
        let tf_invs = all_invariants();
        let tf_refs: Vec<&dyn Invariant> = tf_invs.iter().map(AsRef::as_ref).collect();
        prop_assert!(
            check_all(&tf_refs, &tf_json).is_ok(),
            "Terraform invariants failed for '{}'",
            env.name
        );
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 12: Business evolution -- startup -> growth -> enterprise
// ══════════════════════════════════════════════════════════════════

#[test]
fn business_evolution_preserves_invariants() {
    // Stage 1: Startup
    let stage1 = BusinessEnvironment {
        name: "evolving-co".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![Service {
            name: "api".to_string(),
            replicas: 1,
            cpu_limit: "500m".to_string(),
            memory_limit: "256Mi".to_string(),
            public: false,
        }],
        data_stores: vec![DataStore {
            name: "db".to_string(),
            store_type: DataStoreType::Postgres,
            encrypted: true,
            backup_enabled: true,
        }],
        integrations: vec![],
    };

    // Stage 2: Growth -- add services and a cache
    let stage2 = BusinessEnvironment {
        name: "evolving-co".to_string(),
        tier: Tier::Growth,
        compliance_baselines: vec![],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 2,
                cpu_limit: "1".to_string(),
                memory_limit: "512Mi".to_string(),
                public: true,
            },
            Service {
                name: "worker".to_string(),
                replicas: 1,
                cpu_limit: "500m".to_string(),
                memory_limit: "256Mi".to_string(),
                public: false,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "db".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "cache".to_string(),
                store_type: DataStoreType::Redis,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![Integration {
            name: "auth0".to_string(),
            protocol: "https".to_string(),
            authenticated: true,
        }],
    };

    // Stage 3: Enterprise -- compliance + more services
    let stage3 = BusinessEnvironment {
        name: "evolving-co".to_string(),
        tier: Tier::Enterprise,
        compliance_baselines: vec!["SOC2".to_string()],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 3,
                cpu_limit: "2".to_string(),
                memory_limit: "1Gi".to_string(),
                public: true,
            },
            Service {
                name: "worker".to_string(),
                replicas: 2,
                cpu_limit: "1".to_string(),
                memory_limit: "512Mi".to_string(),
                public: false,
            },
            Service {
                name: "analytics".to_string(),
                replicas: 1,
                cpu_limit: "500m".to_string(),
                memory_limit: "256Mi".to_string(),
                public: false,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "db".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "cache".to_string(),
                store_type: DataStoreType::Redis,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "assets".to_string(),
                store_type: DataStoreType::S3,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![
            Integration {
                name: "auth0".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
            Integration {
                name: "datadog".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
        ],
    };

    // Every stage must pass ALL checks
    for (stage_num, env) in [&stage1, &stage2, &stage3].iter().enumerate() {
        assert!(
            check_all_invariants(env).is_ok(),
            "Stage {} business invariants failed: {:?}",
            stage_num + 1,
            check_all_invariants(env).err()
        );

        let tf_json = simulate_infrastructure(env);
        let tf_invs = all_invariants();
        let tf_refs: Vec<&dyn Invariant> = tf_invs.iter().map(AsRef::as_ref).collect();
        check_all(&tf_refs, &tf_json).unwrap_or_else(|violations| {
            panic!(
                "Stage {} Terraform invariants failed: {:?}",
                stage_num + 1,
                violations
            );
        });
    }

    // Resource count should increase with each stage
    let r1 = ArchitectureAnalysis::from_terraform_json(&simulate_infrastructure(&stage1));
    let r3 = ArchitectureAnalysis::from_terraform_json(&simulate_infrastructure(&stage3));
    assert!(
        r3.resource_count >= r1.resource_count,
        "Enterprise should have >= resources than startup"
    );
}

// ══════════════════════════════════════════════════════════════════
// Proof 13: Multi-tenant -- 3 customers, different baselines, all proven
// ══════════════════════════════════════════════════════════════════

#[test]
fn multi_tenant_different_baselines_all_proven() {
    let tenant_a = BusinessEnvironment {
        name: "tenant-alpha".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![Service {
            name: "app".to_string(),
            replicas: 1,
            cpu_limit: "250m".to_string(),
            memory_limit: "128Mi".to_string(),
            public: false,
        }],
        data_stores: vec![DataStore {
            name: "db".to_string(),
            store_type: DataStoreType::Postgres,
            encrypted: true,
            backup_enabled: true,
        }],
        integrations: vec![],
    };

    let tenant_b = BusinessEnvironment {
        name: "tenant-beta".to_string(),
        tier: Tier::Enterprise,
        compliance_baselines: vec!["SOC2".to_string()],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 3,
                cpu_limit: "1".to_string(),
                memory_limit: "512Mi".to_string(),
                public: true,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "primary".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "events".to_string(),
                store_type: DataStoreType::DynamoDB,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![Integration {
            name: "okta".to_string(),
            protocol: "https".to_string(),
            authenticated: true,
        }],
    };

    let tenant_c = BusinessEnvironment {
        name: "tenant-gamma".to_string(),
        tier: Tier::Regulated,
        compliance_baselines: vec!["FedRAMP".to_string(), "HIPAA".to_string()],
        services: vec![
            Service {
                name: "api".to_string(),
                replicas: 4,
                cpu_limit: "2".to_string(),
                memory_limit: "2Gi".to_string(),
                public: true,
            },
            Service {
                name: "processor".to_string(),
                replicas: 2,
                cpu_limit: "1".to_string(),
                memory_limit: "1Gi".to_string(),
                public: false,
            },
        ],
        data_stores: vec![
            DataStore {
                name: "patient-records".to_string(),
                store_type: DataStoreType::Postgres,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "audit-trail".to_string(),
                store_type: DataStoreType::DynamoDB,
                encrypted: true,
                backup_enabled: true,
            },
            DataStore {
                name: "documents".to_string(),
                store_type: DataStoreType::S3,
                encrypted: true,
                backup_enabled: true,
            },
        ],
        integrations: vec![
            Integration {
                name: "auth".to_string(),
                protocol: "https".to_string(),
                authenticated: true,
            },
        ],
    };

    for tenant in &[&tenant_a, &tenant_b, &tenant_c] {
        // Business invariants
        assert!(
            check_all_invariants(tenant).is_ok(),
            "Tenant '{}' business invariants failed: {:?}",
            tenant.name,
            check_all_invariants(tenant).err()
        );

        // Terraform invariants
        let tf_json = simulate_infrastructure(tenant);
        let tf_invs = all_invariants();
        let tf_refs: Vec<&dyn Invariant> = tf_invs.iter().map(AsRef::as_ref).collect();
        check_all(&tf_refs, &tf_json).unwrap_or_else(|v| {
            panic!("Tenant '{}' Terraform invariants failed: {:?}", tenant.name, v);
        });

        // K8s invariants
        let k8s_json = simulate_k8s(tenant);
        let k8s_invs = all_k8s_invariants();
        let items = k8s_json
            .get("items")
            .and_then(serde_json::Value::as_array)
            .expect("items");
        for item in items {
            let k8s_refs: Vec<&dyn Invariant> = k8s_invs.iter().map(AsRef::as_ref).collect();
            check_all(&k8s_refs, item).unwrap_or_else(|v| {
                panic!("Tenant '{}' K8s invariants failed: {:?}", tenant.name, v);
            });
        }
    }
}

// ══════════════════════════════════════════════════════════════════
// Proof 14: Business environment serialization roundtrip
// ══════════════════════════════════════════════════════════════════

#[test]
fn business_environment_serialization_roundtrip() {
    let env = regulated_env();
    let json_str = serde_json::to_string(&env).expect("serialize BusinessEnvironment");
    let roundtrip: BusinessEnvironment =
        serde_json::from_str(&json_str).expect("deserialize BusinessEnvironment");

    assert_eq!(env.name, roundtrip.name);
    assert_eq!(env.tier, roundtrip.tier);
    assert_eq!(env.compliance_baselines, roundtrip.compliance_baselines);
    assert_eq!(env.services.len(), roundtrip.services.len());
    assert_eq!(env.data_stores.len(), roundtrip.data_stores.len());
    assert_eq!(env.integrations.len(), roundtrip.integrations.len());
}

// ══════════════════════════════════════════════════════════════════
// Proof 15: Simulate infrastructure is deterministic
// ══════════════════════════════════════════════════════════════════

#[test]
fn simulate_infrastructure_is_deterministic() {
    let env = enterprise_env();
    let tf1 = simulate_infrastructure(&env);
    let tf2 = simulate_infrastructure(&env);
    assert_eq!(tf1, tf2, "Same input should produce identical Terraform JSON");
}

// ══════════════════════════════════════════════════════════════════
// Proof 16: Simulate K8s is deterministic
// ══════════════════════════════════════════════════════════════════

#[test]
fn simulate_k8s_is_deterministic() {
    let env = enterprise_env();
    let k1 = simulate_k8s(&env);
    let k2 = simulate_k8s(&env);
    assert_eq!(k1, k2, "Same input should produce identical K8s JSON");
}

// ══════════════════════════════════════════════════════════════════
// Proof 17: Missing service limits detected
// ══════════════════════════════════════════════════════════════════

#[test]
fn missing_service_limits_detected() {
    let env = BusinessEnvironment {
        name: "no-limits".to_string(),
        tier: Tier::Startup,
        compliance_baselines: vec![],
        services: vec![Service {
            name: "unbounded".to_string(),
            replicas: 1,
            cpu_limit: String::new(),
            memory_limit: "256Mi".to_string(),
            public: false,
        }],
        data_stores: vec![],
        integrations: vec![],
    };

    let result = check_services_have_limits(&env);
    assert!(result.is_err(), "Missing CPU limit should be detected");
    assert!(result.unwrap_err().contains("unbounded"));
}

// ══════════════════════════════════════════════════════════════════
// Proof 18: Regulated tier with insufficient baselines fails
// ══════════════════════════════════════════════════════════════════

#[test]
fn regulated_tier_requires_two_baselines() {
    let env = BusinessEnvironment {
        name: "under-compliant".to_string(),
        tier: Tier::Regulated,
        compliance_baselines: vec!["SOC2".to_string()], // only 1
        services: vec![],
        data_stores: vec![],
        integrations: vec![],
    };

    let result = check_compliance_covered(&env);
    assert!(
        result.is_err(),
        "Regulated tier with 1 baseline should fail compliance check"
    );
}
