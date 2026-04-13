//! Composed system proofs — prove that multi-architecture compositions
//! preserve ALL invariants. The whole is as secure as its parts.

use proptest::prelude::*;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};
use pangea_sim::analysis::ArchitectureAnalysis;
use pangea_sim::simulations::composed;

// ── Production K8s Platform ──────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn production_k8s_all_invariants(config in composed::arb_production_k8s()) {
        let tf = composed::simulate_production_k8s(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(check_all(&refs, &tf).is_ok(), "production K8s invariant violation");
    }

    #[test]
    fn production_k8s_has_many_resources(config in composed::arb_production_k8s()) {
        let tf = composed::simulate_production_k8s(&config);
        let a = ArchitectureAnalysis::from_terraform_json(&tf);
        // A full production stack should have many resource types
        prop_assert!(a.resource_count >= 15, "only {} resources", a.resource_count);
        prop_assert!(a.resources_by_type.len() >= 5, "only {} types", a.resources_by_type.len());
    }

    #[test]
    fn production_k8s_deterministic(config in composed::arb_production_k8s()) {
        let tf1 = composed::simulate_production_k8s(&config);
        let tf2 = composed::simulate_production_k8s(&config);
        prop_assert_eq!(tf1, tf2);
    }
}

// ── Builder Fleet + VPN ──────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn builder_infra_all_invariants(config in composed::arb_builder_infra()) {
        let tf = composed::simulate_builder_infra(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(check_all(&refs, &tf).is_ok(), "builder infra invariant violation");
    }

    #[test]
    fn builder_infra_has_resources(config in composed::arb_builder_infra()) {
        let tf = composed::simulate_builder_infra(&config);
        let a = ArchitectureAnalysis::from_terraform_json(&tf);
        prop_assert!(a.resource_count >= 10, "only {} resources", a.resource_count);
    }

    #[test]
    fn builder_infra_deterministic(config in composed::arb_builder_infra()) {
        let tf1 = composed::simulate_builder_infra(&config);
        let tf2 = composed::simulate_builder_infra(&config);
        prop_assert_eq!(tf1, tf2);
    }
}

// ── Data Platform ────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn data_platform_all_invariants(config in composed::arb_data_platform()) {
        let tf = composed::simulate_data_platform(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        prop_assert!(check_all(&refs, &tf).is_ok(), "data platform invariant violation");
    }

    #[test]
    fn data_platform_has_database(config in composed::arb_data_platform()) {
        let tf = composed::simulate_data_platform(&config);
        let a = ArchitectureAnalysis::from_terraform_json(&tf);
        prop_assert!(a.has_resource("aws_db_instance", 1), "no RDS instance");
        prop_assert!(a.has_resource("aws_kms_key", 1), "no KMS key");
    }

    #[test]
    fn data_platform_deterministic(config in composed::arb_data_platform()) {
        let tf1 = composed::simulate_data_platform(&config);
        let tf2 = composed::simulate_data_platform(&config);
        prop_assert_eq!(tf1, tf2);
    }
}
