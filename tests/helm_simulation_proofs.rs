//! Helm chart simulation proofs — same invariant system, different rendering target.
//!
//! Proves that Helm chart rendering preserves security properties.
//! The simulation platform does not care about the rendering target —
//! it proves TYPES are correct. Helm just slots in.
//!
//! K8s manifest invariants are DIFFERENT from Terraform invariants
//! (no VPC, no EBS — instead: securityContext, capabilities, resource limits).
//! But the PATTERN is identical: generate JSON, check invariants, prove over
//! random configs.

use pangea_sim::simulations::helm_chart::*;
use proptest::prelude::*;
use serde_json::Value;

// ── K8s Manifest Invariant Checkers ─────────────────────────────

/// No container runs as root.
fn check_no_root(manifest: &Value) -> bool {
    let containers = manifest
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array);
    match containers {
        Some(cs) => cs.iter().all(|c| {
            c.pointer("/securityContext/runAsNonRoot")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }),
        None => true,
    }
}

/// All containers drop ALL capabilities.
fn check_drop_capabilities(manifest: &Value) -> bool {
    let containers = manifest
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array);
    match containers {
        Some(cs) => cs.iter().all(|c| {
            let caps = c
                .pointer("/securityContext/capabilities/drop")
                .and_then(Value::as_array);
            match caps {
                Some(arr) => arr.iter().any(|v| v.as_str() == Some("ALL")),
                None => false,
            }
        }),
        None => true,
    }
}

/// All containers have resource limits.
fn check_resource_limits(manifest: &Value) -> bool {
    let containers = manifest
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array);
    match containers {
        Some(cs) => cs.iter().all(|c| {
            let has_cpu = c
                .pointer("/resources/limits/cpu")
                .and_then(Value::as_str)
                .is_some();
            let has_mem = c
                .pointer("/resources/limits/memory")
                .and_then(Value::as_str)
                .is_some();
            has_cpu && has_mem
        }),
        None => true,
    }
}

/// No container allows privilege escalation.
fn check_no_privilege_escalation(manifest: &Value) -> bool {
    let containers = manifest
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array);
    match containers {
        Some(cs) => cs.iter().all(|c| {
            c.pointer("/securityContext/allowPrivilegeEscalation")
                .and_then(Value::as_bool)
                == Some(false)
        }),
        None => true,
    }
}

/// Read-only root filesystem.
fn check_readonly_root(manifest: &Value) -> bool {
    let containers = manifest
        .pointer("/spec/template/spec/containers")
        .and_then(Value::as_array);
    match containers {
        Some(cs) => cs.iter().all(|c| {
            c.pointer("/securityContext/readOnlyRootFilesystem")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }),
        None => true,
    }
}

/// All deployments have labels on metadata.
fn check_labels_present(manifest: &Value) -> bool {
    let labels = manifest
        .pointer("/metadata/labels")
        .and_then(Value::as_object);
    match labels {
        Some(l) => !l.is_empty(),
        None => false,
    }
}

// ── Proofs ──────────────────────────────────────────────────────

// 1. Hardened config (nonroot=true, drop_caps=true, readonly=true) passes ALL K8s invariants
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_01_hardened_config_passes_all_k8s_invariants(config in arb_hardened_helm_config()) {
        let manifest = simulate(&config);
        prop_assert!(check_no_root(&manifest), "no-root failed");
        prop_assert!(check_drop_capabilities(&manifest), "drop-caps failed");
        prop_assert!(check_resource_limits(&manifest), "resource-limits failed");
        prop_assert!(check_no_privilege_escalation(&manifest), "no-priv-esc failed");
        prop_assert!(check_readonly_root(&manifest), "readonly-root failed");
        prop_assert!(check_labels_present(&manifest), "labels-present failed");
    }
}

// 2. Resource limits always present regardless of security settings
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_02_resource_limits_always_present(config in arb_helm_config()) {
        let manifest = simulate(&config);
        prop_assert!(check_resource_limits(&manifest));
    }
}

// 3. No privilege escalation ever, regardless of config
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_03_no_privilege_escalation_ever(config in arb_helm_config()) {
        let manifest = simulate(&config);
        prop_assert!(check_no_privilege_escalation(&manifest));
    }
}

// 4. Labels always present on metadata
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_04_labels_always_present(config in arb_helm_config()) {
        let manifest = simulate(&config);
        prop_assert!(check_labels_present(&manifest));
    }
}

// 5. Simulation is deterministic — same config produces same manifest
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_05_simulation_is_deterministic(config in arb_helm_config()) {
        let a = simulate(&config);
        let b = simulate(&config);
        prop_assert_eq!(a, b);
    }
}

// 6. Compliant Helm config produces valid K8s apiVersion and kind
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_06_valid_k8s_api_version_and_kind(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let api = manifest.get("apiVersion").and_then(Value::as_str);
        let kind = manifest.get("kind").and_then(Value::as_str);
        prop_assert_eq!(api, Some("apps/v1"));
        prop_assert_eq!(kind, Some("Deployment"));
    }
}

// 7. Chart name appears in manifest metadata
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_07_chart_name_in_metadata(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let name = manifest.pointer("/metadata/name").and_then(Value::as_str);
        prop_assert_eq!(name, Some(config.chart_name.as_str()));
    }
}

// 8. Namespace is set correctly
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_08_namespace_set_correctly(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let ns = manifest.pointer("/metadata/namespace").and_then(Value::as_str);
        prop_assert_eq!(ns, Some(config.namespace.as_str()));
    }
}

// 9. Replicas match config
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_09_replicas_match_config(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let replicas = manifest.pointer("/spec/replicas").and_then(Value::as_u64);
        prop_assert_eq!(replicas, Some(u64::from(config.replicas)));
    }
}

// 10. Image tag is set correctly in the container spec
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_10_image_tag_set_correctly(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let image = manifest
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(Value::as_str)
            .unwrap_or("");
        let expected = format!("{}:{}", config.image, config.image_tag);
        prop_assert_eq!(image, expected.as_str());
    }
}

// 11. Port mapping is correct
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_11_port_mapping_correct(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let port = manifest
            .pointer("/spec/template/spec/containers/0/ports/0/containerPort")
            .and_then(Value::as_u64);
        prop_assert_eq!(port, Some(u64::from(config.service_port)));
    }
}

// 12. Security context is complete for hardened configs
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_12_security_context_complete_for_hardened(config in arb_hardened_helm_config()) {
        let manifest = simulate(&config);
        let container = &manifest.pointer("/spec/template/spec/containers/0").unwrap();

        // All five security properties present and correct
        let non_root = container
            .pointer("/securityContext/runAsNonRoot")
            .and_then(Value::as_bool);
        let readonly = container
            .pointer("/securityContext/readOnlyRootFilesystem")
            .and_then(Value::as_bool);
        let no_priv_esc = container
            .pointer("/securityContext/allowPrivilegeEscalation")
            .and_then(Value::as_bool);
        let drop_caps = container
            .pointer("/securityContext/capabilities/drop")
            .and_then(Value::as_array);

        prop_assert_eq!(non_root, Some(true));
        prop_assert_eq!(readonly, Some(true));
        prop_assert_eq!(no_priv_esc, Some(false));
        prop_assert!(drop_caps.is_some());
        prop_assert!(drop_caps.unwrap().iter().any(|v| v.as_str() == Some("ALL")));
    }
}

// 13. HPA/PDB/NetworkPolicy flags do not affect security invariants
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_13_optional_features_do_not_affect_security(
        nonroot in prop::bool::ANY,
        readonly in prop::bool::ANY,
        drop_caps in prop::bool::ANY,
        np in prop::bool::ANY,
        pdb in prop::bool::ANY,
        hpa in prop::bool::ANY,
        sm in prop::bool::ANY,
    ) {
        let config_a = HelmChartConfig {
            chart_name: "test-app".into(),
            namespace: "default".into(),
            replicas: 3,
            image: "ghcr.io/pleme-io/app".into(),
            image_tag: "v1.0".into(),
            service_port: 8080,
            enable_network_policy: np,
            enable_pdb: pdb,
            enable_hpa: hpa,
            enable_service_monitor: sm,
            resources_cpu_limit: "500m".into(),
            resources_memory_limit: "256Mi".into(),
            security_context_run_as_non_root: nonroot,
            security_context_read_only_root: readonly,
            security_context_drop_capabilities: drop_caps,
            labels: vec![
                ("ManagedBy".into(), "pangea".into()),
                ("Purpose".into(), "convergence".into()),
            ],
        };
        let config_b = HelmChartConfig {
            enable_network_policy: !np,
            enable_pdb: !pdb,
            enable_hpa: !hpa,
            enable_service_monitor: !sm,
            ..config_a.clone()
        };

        let manifest_a = simulate(&config_a);
        let manifest_b = simulate(&config_b);

        // Security properties are identical regardless of optional feature flags
        let sec_a = manifest_a.pointer("/spec/template/spec/containers/0/securityContext");
        let sec_b = manifest_b.pointer("/spec/template/spec/containers/0/securityContext");
        prop_assert_eq!(sec_a, sec_b);

        let res_a = manifest_a.pointer("/spec/template/spec/containers/0/resources");
        let res_b = manifest_b.pointer("/spec/template/spec/containers/0/resources");
        prop_assert_eq!(res_a, res_b);
    }
}

// 14. The container name matches the chart name
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_14_container_name_matches_chart(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let container_name = manifest
            .pointer("/spec/template/spec/containers/0/name")
            .and_then(Value::as_str);
        prop_assert_eq!(container_name, Some(config.chart_name.as_str()));
    }
}

// 15. Selector matchLabels align with template labels
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn proof_15_selector_matches_template_labels(config in arb_helm_config()) {
        let manifest = simulate(&config);
        let selector = manifest.pointer("/spec/selector/matchLabels/app")
            .and_then(Value::as_str);
        let template_label = manifest.pointer("/spec/template/metadata/labels/app")
            .and_then(Value::as_str);
        prop_assert_eq!(selector, template_label);
        prop_assert_eq!(selector, Some(config.chart_name.as_str()));
    }
}

// ── Non-proptest unit proofs ────────────────────────────────────

#[test]
fn proof_16_non_hardened_config_fails_security_invariants() {
    // A config with all security flags disabled should fail the security checks
    let config = HelmChartConfig {
        chart_name: "insecure-app".into(),
        namespace: "default".into(),
        replicas: 1,
        image: "ghcr.io/pleme-io/app".into(),
        image_tag: "latest".into(),
        service_port: 8080,
        enable_network_policy: false,
        enable_pdb: false,
        enable_hpa: false,
        enable_service_monitor: false,
        resources_cpu_limit: "500m".into(),
        resources_memory_limit: "256Mi".into(),
        security_context_run_as_non_root: false,
        security_context_read_only_root: false,
        security_context_drop_capabilities: false,
        labels: vec![
            ("ManagedBy".into(), "pangea".into()),
            ("Purpose".into(), "convergence".into()),
        ],
    };
    let manifest = simulate(&config);

    // These should fail — the config is not hardened
    assert!(!check_no_root(&manifest));
    assert!(!check_drop_capabilities(&manifest));
    assert!(!check_readonly_root(&manifest));

    // These always hold by construction
    assert!(check_resource_limits(&manifest));
    assert!(check_no_privilege_escalation(&manifest));
    assert!(check_labels_present(&manifest));
}

#[test]
fn proof_17_rendering_target_irrelevant_same_types_same_proofs() {
    // The key insight: Helm is just another rendering target.
    // Given the same typed config, the security properties are identical
    // regardless of whether we render to Terraform JSON or K8s manifest.
    //
    // Both rendering paths start from the same IacResource types.
    // Terraform invariants check VPC/EBS/IAM properties.
    // K8s invariants check securityContext/capabilities/resources.
    // Both are checked the same way: generate JSON, check properties.
    let config = HelmChartConfig {
        chart_name: "convergence-proof".into(),
        namespace: "production".into(),
        replicas: 3,
        image: "ghcr.io/pleme-io/app".into(),
        image_tag: "v2.0.0".into(),
        service_port: 8080,
        enable_network_policy: true,
        enable_pdb: true,
        enable_hpa: true,
        enable_service_monitor: true,
        resources_cpu_limit: "1000m".into(),
        resources_memory_limit: "512Mi".into(),
        security_context_run_as_non_root: true,
        security_context_read_only_root: true,
        security_context_drop_capabilities: true,
        labels: vec![
            ("ManagedBy".into(), "pangea".into()),
            ("Purpose".into(), "convergence".into()),
        ],
    };

    let manifest = simulate(&config);

    // All 6 K8s invariants hold for a fully hardened config
    assert!(check_no_root(&manifest));
    assert!(check_drop_capabilities(&manifest));
    assert!(check_resource_limits(&manifest));
    assert!(check_no_privilege_escalation(&manifest));
    assert!(check_readonly_root(&manifest));
    assert!(check_labels_present(&manifest));

    // Structural validity
    assert_eq!(
        manifest.get("apiVersion").and_then(Value::as_str),
        Some("apps/v1")
    );
    assert_eq!(
        manifest.get("kind").and_then(Value::as_str),
        Some("Deployment")
    );
}

#[test]
fn proof_18_pod_security_context_set_at_pod_level() {
    let config = HelmChartConfig {
        chart_name: "pod-sec".into(),
        namespace: "default".into(),
        replicas: 1,
        image: "ghcr.io/pleme-io/app".into(),
        image_tag: "latest".into(),
        service_port: 8080,
        enable_network_policy: false,
        enable_pdb: false,
        enable_hpa: false,
        enable_service_monitor: false,
        resources_cpu_limit: "500m".into(),
        resources_memory_limit: "256Mi".into(),
        security_context_run_as_non_root: true,
        security_context_read_only_root: true,
        security_context_drop_capabilities: true,
        labels: vec![
            ("ManagedBy".into(), "pangea".into()),
            ("Purpose".into(), "convergence".into()),
        ],
    };
    let manifest = simulate(&config);

    // Pod-level securityContext also enforces runAsNonRoot
    let pod_non_root = manifest
        .pointer("/spec/template/spec/securityContext/runAsNonRoot")
        .and_then(Value::as_bool);
    assert_eq!(pod_non_root, Some(true));
}
