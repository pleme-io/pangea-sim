//! Helm chart simulation — prove Helm renderings preserve invariants.
//!
//! The same `IacResource` types that produce proven Terraform JSON also produce
//! Helm charts via `helm-forge`. This module simulates Helm chart output as K8s
//! manifest JSON and proves K8s manifest invariants.
//!
//! The simulation platform does not care about the rendering target — it proves
//! the TYPES are correct. Helm is just another rendering.

use proptest::prelude::*;
use serde_json::{json, Value};

/// Configuration for a simulated Helm chart deployment.
#[derive(Debug, Clone)]
pub struct HelmChartConfig {
    /// Chart name — becomes the Deployment metadata name.
    pub chart_name: String,
    /// K8s namespace for the deployment.
    pub namespace: String,
    /// Number of pod replicas.
    pub replicas: u32,
    /// Container image registry/repository.
    pub image: String,
    /// Container image tag.
    pub image_tag: String,
    /// Service port exposed by the container.
    pub service_port: u16,
    /// Whether to generate a NetworkPolicy resource.
    pub enable_network_policy: bool,
    /// Whether to generate a PodDisruptionBudget resource.
    pub enable_pdb: bool,
    /// Whether to generate a HorizontalPodAutoscaler resource.
    pub enable_hpa: bool,
    /// Whether to generate a ServiceMonitor resource.
    pub enable_service_monitor: bool,
    /// CPU resource limit (e.g., "500m").
    pub resources_cpu_limit: String,
    /// Memory resource limit (e.g., "256Mi").
    pub resources_memory_limit: String,
    /// Whether the container must run as non-root.
    pub security_context_run_as_non_root: bool,
    /// Whether the root filesystem is read-only.
    pub security_context_read_only_root: bool,
    /// Whether to drop all Linux capabilities.
    pub security_context_drop_capabilities: bool,
    /// Labels applied to the Deployment metadata.
    pub labels: Vec<(String, String)>,
}

/// Convert a label vector to a JSON object.
fn labels_to_json(labels: &[(String, String)]) -> Value {
    let mut map = serde_json::Map::new();
    for (k, v) in labels {
        map.insert(k.clone(), json!(v));
    }
    Value::Object(map)
}

/// Simulate a Helm chart rendering as a K8s Deployment manifest JSON.
///
/// The output mirrors what `helm template` would produce — a valid K8s
/// Deployment resource with securityContext, resource limits, and labels.
#[must_use]
pub fn simulate(config: &HelmChartConfig) -> Value {
    let drop_list: Vec<&str> = if config.security_context_drop_capabilities {
        vec!["ALL"]
    } else {
        vec![]
    };

    let mut labels_map = labels_to_json(&config.labels);
    let labels_obj = labels_map.as_object_mut().unwrap();
    labels_obj.insert("app".to_string(), json!(config.chart_name));

    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": config.chart_name,
            "namespace": config.namespace,
            "labels": labels_map,
        },
        "spec": {
            "replicas": config.replicas,
            "selector": {
                "matchLabels": { "app": config.chart_name }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": config.chart_name,
                        "app.kubernetes.io/name": config.chart_name,
                        "app.kubernetes.io/managed-by": "pangea"
                    }
                },
                "spec": {
                    "securityContext": {
                        "runAsNonRoot": config.security_context_run_as_non_root,
                    },
                    "containers": [{
                        "name": config.chart_name,
                        "image": format!("{}:{}", config.image, config.image_tag),
                        "ports": [{ "containerPort": config.service_port }],
                        "resources": {
                            "limits": {
                                "cpu": config.resources_cpu_limit,
                                "memory": config.resources_memory_limit,
                            },
                        },
                        "securityContext": {
                            "runAsNonRoot": config.security_context_run_as_non_root,
                            "readOnlyRootFilesystem": config.security_context_read_only_root,
                            "allowPrivilegeEscalation": false,
                            "capabilities": {
                                "drop": drop_list,
                            },
                        },
                    }],
                },
            },
        },
    })
}

/// Proptest strategy for generating random `HelmChartConfig` values.
pub fn arb_helm_config() -> impl Strategy<Value = HelmChartConfig> {
    (
        "[a-z][a-z0-9-]{2,15}",
        prop::sample::select(vec![
            "default".to_string(),
            "production".to_string(),
            "staging".to_string(),
        ]),
        1..10u32,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
    )
        .prop_map(
            |(name, ns, replicas, np, pdb, hpa, sm, nonroot, readonly, drop_caps)| {
                HelmChartConfig {
                    chart_name: name,
                    namespace: ns,
                    replicas,
                    image: "ghcr.io/pleme-io/app".to_string(),
                    image_tag: "latest".to_string(),
                    service_port: 8080,
                    enable_network_policy: np,
                    enable_pdb: pdb,
                    enable_hpa: hpa,
                    enable_service_monitor: sm,
                    resources_cpu_limit: "500m".to_string(),
                    resources_memory_limit: "256Mi".to_string(),
                    security_context_run_as_non_root: nonroot,
                    security_context_read_only_root: readonly,
                    security_context_drop_capabilities: drop_caps,
                    labels: vec![
                        ("ManagedBy".to_string(), "pangea".to_string()),
                        ("Purpose".to_string(), "convergence".to_string()),
                    ],
                }
            },
        )
}

/// Proptest strategy for hardened configs — all security flags enabled.
///
/// Hardened means: `run_as_non_root`, `read_only_root`, `drop_capabilities` all true.
pub fn arb_hardened_helm_config() -> impl Strategy<Value = HelmChartConfig> {
    (
        "[a-z][a-z0-9-]{2,15}",
        prop::sample::select(vec![
            "default".to_string(),
            "production".to_string(),
            "staging".to_string(),
        ]),
        1..10u32,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
    )
        .prop_map(|(name, ns, replicas, np, pdb, hpa, sm)| HelmChartConfig {
            chart_name: name,
            namespace: ns,
            replicas,
            image: "ghcr.io/pleme-io/app".to_string(),
            image_tag: "latest".to_string(),
            service_port: 8080,
            enable_network_policy: np,
            enable_pdb: pdb,
            enable_hpa: hpa,
            enable_service_monitor: sm,
            resources_cpu_limit: "500m".to_string(),
            resources_memory_limit: "256Mi".to_string(),
            security_context_run_as_non_root: true,
            security_context_read_only_root: true,
            security_context_drop_capabilities: true,
            labels: vec![
                ("ManagedBy".to_string(), "pangea".to_string()),
                ("Purpose".to_string(), "convergence".to_string()),
            ],
        })
}
