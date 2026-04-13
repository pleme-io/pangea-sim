//! K8s manifest invariants — security properties for Helm chart output.
//!
//! These invariants check K8s Deployment/Pod manifests for security
//! properties, just as the Terraform invariants check infrastructure JSON.
//! Same trait, same simulation engine, different rendering target.
//!
//! K8s manifest structure (Deployment example):
//! ```json
//! {
//!   "apiVersion": "apps/v1",
//!   "kind": "Deployment",
//!   "metadata": { "name": "app", "labels": { ... } },
//!   "spec": {
//!     "template": {
//!       "metadata": { "labels": { ... } },
//!       "spec": {
//!         "containers": [{ "name": "app", "securityContext": { ... } }],
//!         "securityContext": { ... }
//!       }
//!     }
//!   }
//! }
//! ```

use super::{Invariant, Violation};
use serde_json::Value;

// ── Helpers ────────────────────────────────────────────────────

/// Extract all workload objects from a K8s manifest.
///
/// Handles both single-object manifests and lists (kind: List).
/// Finds Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet, and Pod.
fn extract_workloads(manifest: &Value) -> Vec<(&str, String, &Value)> {
    let mut workloads = Vec::new();

    let items: Vec<&Value> = if manifest.get("kind").and_then(Value::as_str) == Some("List") {
        manifest
            .get("items")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().collect())
            .unwrap_or_default()
    } else {
        vec![manifest]
    };

    for item in items {
        let kind = item.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = item
            .pointer("/metadata/name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        match kind {
            "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "Job" => {
                workloads.push((kind, name, item));
            }
            "CronJob" => {
                // CronJob wraps job template one level deeper
                workloads.push((kind, name, item));
            }
            "Pod" => {
                workloads.push((kind, name, item));
            }
            _ => {}
        }
    }

    workloads
}

/// Get the pod spec from a workload object.
///
/// For Deployment/StatefulSet/DaemonSet/ReplicaSet: spec.template.spec
/// For CronJob: spec.jobTemplate.spec.template.spec
/// For Pod: spec
fn pod_spec<'a>(kind: &str, workload: &'a Value) -> Option<&'a Value> {
    match kind {
        "Pod" => workload.get("spec"),
        "CronJob" => workload.pointer("/spec/jobTemplate/spec/template/spec"),
        _ => workload.pointer("/spec/template/spec"),
    }
}

/// Get the pod metadata from a workload object (for label checks).
fn pod_metadata<'a>(kind: &str, workload: &'a Value) -> Option<&'a Value> {
    match kind {
        "Pod" => workload.get("metadata"),
        "CronJob" => workload.pointer("/spec/jobTemplate/spec/template/metadata"),
        _ => workload.pointer("/spec/template/metadata"),
    }
}

/// Get all containers (containers + initContainers) from a pod spec.
fn all_containers(pod: &Value) -> Vec<(String, &Value)> {
    let mut result = Vec::new();
    for field in &["containers", "initContainers"] {
        if let Some(containers) = pod.get(*field).and_then(Value::as_array) {
            for c in containers {
                let name = c
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("unnamed")
                    .to_string();
                result.push((name, c));
            }
        }
    }
    result
}

// ── Invariant: NoRootContainers ────────────────────────────────

/// No container runs as root (runAsNonRoot: true).
///
/// Checks both pod-level securityContext and per-container securityContext.
/// The container-level setting takes precedence; if absent, the pod-level
/// setting is used. If neither is set, the container could run as root.
pub struct NoRootContainers;

impl Invariant for NoRootContainers {
    fn name(&self) -> &str {
        "no_root_containers"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            let pod_level = pod
                .pointer("/securityContext/runAsNonRoot")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            for (container_name, container) in all_containers(pod) {
                let container_level = container
                    .pointer("/securityContext/runAsNonRoot")
                    .and_then(Value::as_bool);

                let effective = container_level.unwrap_or(pod_level);

                if !effective {
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!(
                            "Container '{container_name}' does not set runAsNonRoot: true"
                        ),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: DropAllCapabilities ─────────────────────────────

/// All containers drop ALL Linux capabilities.
///
/// Checks that securityContext.capabilities.drop contains "ALL".
pub struct DropAllCapabilities;

impl Invariant for DropAllCapabilities {
    fn name(&self) -> &str {
        "drop_all_capabilities"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            for (container_name, container) in all_containers(pod) {
                let drops_all = container
                    .pointer("/securityContext/capabilities/drop")
                    .and_then(Value::as_array)
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some("ALL")))
                    .unwrap_or(false);

                if !drops_all {
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!(
                            "Container '{container_name}' does not drop ALL capabilities"
                        ),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: NoPrivilegeEscalation ───────────────────────────

/// No container allows privilege escalation (allowPrivilegeEscalation: false).
pub struct NoPrivilegeEscalation;

impl Invariant for NoPrivilegeEscalation {
    fn name(&self) -> &str {
        "no_privilege_escalation"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            for (container_name, container) in all_containers(pod) {
                let allow = container
                    .pointer("/securityContext/allowPrivilegeEscalation")
                    .and_then(Value::as_bool)
                    .unwrap_or(true); // K8s default is true

                if allow {
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!(
                            "Container '{container_name}' allows privilege escalation"
                        ),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: ResourceLimitsSet ───────────────────────────────

/// All containers have resource limits (cpu + memory).
pub struct ResourceLimitsSet;

impl Invariant for ResourceLimitsSet {
    fn name(&self) -> &str {
        "resource_limits_set"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            for (container_name, container) in all_containers(pod) {
                let limits = container.pointer("/resources/limits");
                let has_cpu = limits
                    .and_then(|l| l.get("cpu"))
                    .is_some();
                let has_memory = limits
                    .and_then(|l| l.get("memory"))
                    .is_some();

                if !has_cpu || !has_memory {
                    let mut missing = Vec::new();
                    if !has_cpu {
                        missing.push("cpu");
                    }
                    if !has_memory {
                        missing.push("memory");
                    }
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!(
                            "Container '{container_name}' missing resource limits: {}",
                            missing.join(", ")
                        ),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: ReadOnlyRootFs ──────────────────────────────────

/// Read-only root filesystem (readOnlyRootFilesystem: true).
pub struct ReadOnlyRootFs;

impl Invariant for ReadOnlyRootFs {
    fn name(&self) -> &str {
        "read_only_root_fs"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            for (container_name, container) in all_containers(pod) {
                let read_only = container
                    .pointer("/securityContext/readOnlyRootFilesystem")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if !read_only {
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!(
                            "Container '{container_name}' does not set readOnlyRootFilesystem: true"
                        ),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: RequiredLabels ──────────────────────────────────

/// All pods have required labels (app, app.kubernetes.io/managed-by).
pub struct RequiredLabels;

impl Invariant for RequiredLabels {
    fn name(&self) -> &str {
        "required_labels"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(meta) = pod_metadata(kind, workload) else {
                continue;
            };

            let labels = meta.get("labels").and_then(Value::as_object);
            let has_app = labels.and_then(|l| l.get("app")).is_some()
                || labels
                    .and_then(|l| l.get("app.kubernetes.io/name"))
                    .is_some();
            let has_managed_by = labels
                .and_then(|l| l.get("app.kubernetes.io/managed-by"))
                .is_some();

            if !has_app || !has_managed_by {
                let mut missing = Vec::new();
                if !has_app {
                    missing.push("app (or app.kubernetes.io/name)");
                }
                if !has_managed_by {
                    missing.push("app.kubernetes.io/managed-by");
                }
                violations.push(Violation {
                    invariant: self.name().into(),
                    resource_type: kind.into(),
                    resource_name: workload_name.clone(),
                    message: format!("Pod template missing required labels: {}", missing.join(", ")),
                });
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: NoHostNamespaces ────────────────────────────────

/// No hostNetwork, hostPID, or hostIPC.
pub struct NoHostNamespaces;

impl Invariant for NoHostNamespaces {
    fn name(&self) -> &str {
        "no_host_namespaces"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            let host_network = pod.get("hostNetwork").and_then(Value::as_bool).unwrap_or(false);
            let host_pid = pod.get("hostPID").and_then(Value::as_bool).unwrap_or(false);
            let host_ipc = pod.get("hostIPC").and_then(Value::as_bool).unwrap_or(false);

            let mut exposed = Vec::new();
            if host_network {
                exposed.push("hostNetwork");
            }
            if host_pid {
                exposed.push("hostPID");
            }
            if host_ipc {
                exposed.push("hostIPC");
            }

            if !exposed.is_empty() {
                violations.push(Violation {
                    invariant: self.name().into(),
                    resource_type: kind.into(),
                    resource_name: workload_name.clone(),
                    message: format!("Pod uses host namespaces: {}", exposed.join(", ")),
                });
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Invariant: NoPrivilegedContainers ──────────────────────────

/// No privileged containers (privileged: false or absent).
pub struct NoPrivilegedContainers;

impl Invariant for NoPrivilegedContainers {
    fn name(&self) -> &str {
        "no_privileged_containers"
    }

    fn check(&self, manifest: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for (kind, workload_name, workload) in extract_workloads(manifest) {
            let Some(pod) = pod_spec(kind, workload) else {
                continue;
            };

            for (container_name, container) in all_containers(pod) {
                let privileged = container
                    .pointer("/securityContext/privileged")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if privileged {
                    violations.push(Violation {
                        invariant: self.name().into(),
                        resource_type: kind.into(),
                        resource_name: workload_name.clone(),
                        message: format!("Container '{container_name}' is privileged"),
                    });
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

// ── Collection ─────────────────────────────────────────────────

/// All K8s manifest invariants bundled together.
pub fn all_k8s_invariants() -> Vec<Box<dyn Invariant>> {
    vec![
        Box::new(NoRootContainers),
        Box::new(DropAllCapabilities),
        Box::new(NoPrivilegeEscalation),
        Box::new(ResourceLimitsSet),
        Box::new(ReadOnlyRootFs),
        Box::new(RequiredLabels),
        Box::new(NoHostNamespaces),
        Box::new(NoPrivilegedContainers),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    /// Helper: a fully compliant Deployment manifest.
    fn compliant_deployment() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "web",
                "labels": { "app": "web" }
            },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "web",
                            "app.kubernetes.io/managed-by": "Helm"
                        }
                    },
                    "spec": {
                        "securityContext": {
                            "runAsNonRoot": true
                        },
                        "containers": [{
                            "name": "app",
                            "image": "myapp:1.0",
                            "securityContext": {
                                "runAsNonRoot": true,
                                "allowPrivilegeEscalation": false,
                                "privileged": false,
                                "readOnlyRootFilesystem": true,
                                "capabilities": {
                                    "drop": ["ALL"]
                                }
                            },
                            "resources": {
                                "limits": {
                                    "cpu": "500m",
                                    "memory": "256Mi"
                                },
                                "requests": {
                                    "cpu": "100m",
                                    "memory": "128Mi"
                                }
                            }
                        }]
                    }
                }
            }
        })
    }

    /// Helper: a non-compliant Deployment manifest (every invariant violated).
    fn non_compliant_deployment() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "insecure",
                "labels": { "app": "insecure" }
            },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": {}
                    },
                    "spec": {
                        "hostNetwork": true,
                        "hostPID": true,
                        "hostIPC": true,
                        "containers": [{
                            "name": "bad",
                            "image": "badapp:latest",
                            "securityContext": {
                                "privileged": true,
                                "allowPrivilegeEscalation": true
                            }
                        }]
                    }
                }
            }
        })
    }

    // ── Collection tests ───────────────────────────────────────

    #[test]
    fn all_k8s_invariants_returns_eight() {
        assert_eq!(all_k8s_invariants().len(), 8);
    }

    #[test]
    fn all_k8s_invariant_names_unique() {
        let invs = all_k8s_invariants();
        let names: HashSet<&str> = invs.iter().map(|i| i.name()).collect();
        assert_eq!(names.len(), invs.len(), "Invariant names must be unique");
    }

    #[test]
    fn all_k8s_invariants_pass_compliant_deployment() {
        let manifest = compliant_deployment();
        let invs = all_k8s_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        let result = super::super::check_all(&refs, &manifest);
        assert!(result.is_ok(), "All K8s invariants should pass on compliant deployment");
    }

    #[test]
    fn all_k8s_invariants_fail_non_compliant_deployment() {
        let manifest = non_compliant_deployment();
        let invs = all_k8s_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        let result = super::super::check_all(&refs, &manifest);
        assert!(result.is_err(), "K8s invariants should fail on non-compliant deployment");
        let violations = result.unwrap_err();
        // At minimum: no_root, no_drop_all, priv_escalation, no_limits, no_ro_fs,
        //             no_labels, host_namespaces, privileged = 8 sources
        assert!(violations.len() >= 8, "Expected at least 8 violations, got {}", violations.len());
    }

    #[test]
    fn empty_manifest_passes_all() {
        let manifest = json!({});
        let invs = all_k8s_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        assert!(super::super::check_all(&refs, &manifest).is_ok());
    }

    // ── NoRootContainers tests ─────────────────────────────────

    #[test]
    fn no_root_passes_with_run_as_non_root() {
        let manifest = compliant_deployment();
        assert!(NoRootContainers.check(&manifest).is_ok());
    }

    #[test]
    fn no_root_passes_with_pod_level_setting() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": { "runAsNonRoot": true },
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        assert!(NoRootContainers.check(&manifest).is_ok());
    }

    #[test]
    fn no_root_fails_without_setting() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = NoRootContainers.check(&manifest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn no_root_container_override_takes_precedence() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "securityContext": { "runAsNonRoot": true },
                        "containers": [{
                            "name": "overrider",
                            "image": "app:1",
                            "securityContext": { "runAsNonRoot": false }
                        }]
                    }
                }
            }
        });
        let result = NoRootContainers.check(&manifest);
        assert!(result.is_err());
    }

    // ── DropAllCapabilities tests ──────────────────────────────

    #[test]
    fn drop_all_passes_when_all_dropped() {
        let manifest = compliant_deployment();
        assert!(DropAllCapabilities.check(&manifest).is_ok());
    }

    #[test]
    fn drop_all_fails_without_drop() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = DropAllCapabilities.check(&manifest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn drop_all_fails_partial_drop() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1",
                            "securityContext": {
                                "capabilities": {
                                    "drop": ["NET_RAW"]
                                }
                            }
                        }]
                    }
                }
            }
        });
        let result = DropAllCapabilities.check(&manifest);
        assert!(result.is_err());
    }

    // ── NoPrivilegeEscalation tests ────────────────────────────

    #[test]
    fn no_priv_esc_passes_when_false() {
        let manifest = compliant_deployment();
        assert!(NoPrivilegeEscalation.check(&manifest).is_ok());
    }

    #[test]
    fn no_priv_esc_fails_when_unset() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = NoPrivilegeEscalation.check(&manifest);
        assert!(result.is_err(), "K8s default is true, so unset should fail");
    }

    #[test]
    fn no_priv_esc_fails_when_true() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1",
                            "securityContext": {
                                "allowPrivilegeEscalation": true
                            }
                        }]
                    }
                }
            }
        });
        let result = NoPrivilegeEscalation.check(&manifest);
        assert!(result.is_err());
    }

    // ── ResourceLimitsSet tests ────────────────────────────────

    #[test]
    fn resource_limits_passes_when_set() {
        let manifest = compliant_deployment();
        assert!(ResourceLimitsSet.check(&manifest).is_ok());
    }

    #[test]
    fn resource_limits_fails_missing_limits() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = ResourceLimitsSet.check(&manifest);
        assert!(result.is_err());
        let msg = &result.unwrap_err()[0].message;
        assert!(msg.contains("cpu"));
        assert!(msg.contains("memory"));
    }

    #[test]
    fn resource_limits_fails_missing_memory() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1",
                            "resources": {
                                "limits": { "cpu": "500m" }
                            }
                        }]
                    }
                }
            }
        });
        let result = ResourceLimitsSet.check(&manifest);
        assert!(result.is_err());
        let msg = &result.unwrap_err()[0].message;
        assert!(msg.contains("memory"));
        assert!(!msg.contains("cpu"));
    }

    // ── ReadOnlyRootFs tests ───────────────────────────────────

    #[test]
    fn read_only_root_fs_passes_when_true() {
        let manifest = compliant_deployment();
        assert!(ReadOnlyRootFs.check(&manifest).is_ok());
    }

    #[test]
    fn read_only_root_fs_fails_when_unset() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = ReadOnlyRootFs.check(&manifest);
        assert!(result.is_err());
    }

    #[test]
    fn read_only_root_fs_fails_when_false() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1",
                            "securityContext": {
                                "readOnlyRootFilesystem": false
                            }
                        }]
                    }
                }
            }
        });
        let result = ReadOnlyRootFs.check(&manifest);
        assert!(result.is_err());
    }

    // ── RequiredLabels tests ───────────────────────────────────

    #[test]
    fn required_labels_passes_with_all() {
        let manifest = compliant_deployment();
        assert!(RequiredLabels.check(&manifest).is_ok());
    }

    #[test]
    fn required_labels_passes_with_k8s_name_label() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": {
                            "app.kubernetes.io/name": "app",
                            "app.kubernetes.io/managed-by": "Helm"
                        }
                    },
                    "spec": {
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        assert!(RequiredLabels.check(&manifest).is_ok());
    }

    #[test]
    fn required_labels_fails_missing_all() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": {}
                    },
                    "spec": {
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        let result = RequiredLabels.check(&manifest);
        assert!(result.is_err());
        let msg = &result.unwrap_err()[0].message;
        assert!(msg.contains("app"));
        assert!(msg.contains("managed-by"));
    }

    #[test]
    fn required_labels_fails_missing_managed_by() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "metadata": {
                        "labels": { "app": "web" }
                    },
                    "spec": {
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        let result = RequiredLabels.check(&manifest);
        assert!(result.is_err());
        let msg = &result.unwrap_err()[0].message;
        assert!(msg.contains("managed-by"));
        assert!(!msg.contains("app (or"));
    }

    // ── NoHostNamespaces tests ─────────────────────────────────

    #[test]
    fn no_host_namespaces_passes_clean() {
        let manifest = compliant_deployment();
        assert!(NoHostNamespaces.check(&manifest).is_ok());
    }

    #[test]
    fn no_host_namespaces_fails_host_network() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": true,
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        let result = NoHostNamespaces.check(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].message.contains("hostNetwork"));
    }

    #[test]
    fn no_host_namespaces_fails_all_three() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": true,
                        "hostPID": true,
                        "hostIPC": true,
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        let result = NoHostNamespaces.check(&manifest);
        assert!(result.is_err());
        let msg = &result.unwrap_err()[0].message;
        assert!(msg.contains("hostNetwork"));
        assert!(msg.contains("hostPID"));
        assert!(msg.contains("hostIPC"));
    }

    #[test]
    fn no_host_namespaces_passes_false_values() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "hostNetwork": false,
                        "hostPID": false,
                        "hostIPC": false,
                        "containers": [{ "name": "app", "image": "app:1" }]
                    }
                }
            }
        });
        assert!(NoHostNamespaces.check(&manifest).is_ok());
    }

    // ── NoPrivilegedContainers tests ───────────────────────────

    #[test]
    fn no_privileged_passes_clean() {
        let manifest = compliant_deployment();
        assert!(NoPrivilegedContainers.check(&manifest).is_ok());
    }

    #[test]
    fn no_privileged_passes_unset() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        assert!(NoPrivilegedContainers.check(&manifest).is_ok());
    }

    #[test]
    fn no_privileged_fails_privileged_container() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "evil",
                            "image": "app:1",
                            "securityContext": { "privileged": true }
                        }]
                    }
                }
            }
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].message.contains("evil"));
    }

    #[test]
    fn no_privileged_passes_explicitly_false() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "safe",
                            "image": "app:1",
                            "securityContext": { "privileged": false }
                        }]
                    }
                }
            }
        });
        assert!(NoPrivilegedContainers.check(&manifest).is_ok());
    }

    // ── Multi-container tests ──────────────────────────────────

    #[test]
    fn checks_init_containers_too() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "initContainers": [{
                            "name": "init",
                            "image": "init:1",
                            "securityContext": { "privileged": true }
                        }],
                        "containers": [{
                            "name": "app",
                            "image": "app:1"
                        }]
                    }
                }
            }
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err()[0].message.contains("init"));
    }

    #[test]
    fn multiple_containers_multiple_violations() {
        let manifest = json!({
            "kind": "Deployment",
            "metadata": { "name": "app" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            { "name": "a", "image": "a:1" },
                            { "name": "b", "image": "b:1" }
                        ]
                    }
                }
            }
        });
        // NoRootContainers should catch both
        let result = NoRootContainers.check(&manifest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 2);
    }

    // ── Pod kind tests ─────────────────────────────────────────

    #[test]
    fn works_with_pod_kind() {
        let manifest = json!({
            "kind": "Pod",
            "metadata": { "name": "standalone" },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "app:1",
                    "securityContext": { "privileged": true }
                }]
            }
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
    }

    // ── StatefulSet kind tests ─────────────────────────────────

    #[test]
    fn works_with_statefulset() {
        let manifest = json!({
            "kind": "StatefulSet",
            "metadata": { "name": "db" },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "postgres",
                            "image": "pg:15",
                            "securityContext": { "privileged": true }
                        }]
                    }
                }
            }
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
    }

    // ── CronJob kind tests ─────────────────────────────────────

    #[test]
    fn works_with_cronjob() {
        let manifest = json!({
            "kind": "CronJob",
            "metadata": { "name": "cleanup" },
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "job",
                                    "image": "job:1",
                                    "securityContext": { "privileged": true }
                                }]
                            }
                        }
                    }
                }
            }
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
    }

    // ── List kind tests ────────────────────────────────────────

    #[test]
    fn works_with_list_of_workloads() {
        let manifest = json!({
            "kind": "List",
            "items": [
                {
                    "kind": "Deployment",
                    "metadata": { "name": "web" },
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "app",
                                    "image": "app:1",
                                    "securityContext": { "privileged": true }
                                }]
                            }
                        }
                    }
                },
                {
                    "kind": "Deployment",
                    "metadata": { "name": "api" },
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [{
                                    "name": "api",
                                    "image": "api:1",
                                    "securityContext": { "privileged": true }
                                }]
                            }
                        }
                    }
                }
            ]
        });
        let result = NoPrivilegedContainers.check(&manifest);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 2);
    }
}
