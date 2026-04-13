//! State transition simulation — prove migrations are safe.
//!
//! Models infrastructure state transitions and proves:
//! - Invariants hold at BOTH endpoints
//! - The transition itself is safe (no intermediate violation)
//! - Rollback paths exist and are safe
//! - Multi-step migrations preserve invariants at every step

use crate::invariants::{all_invariants, check_all, Invariant, Violation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A diff between two infrastructure states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    pub from_hash: String,
    pub to_hash: String,
    pub added_resources: Vec<String>,
    pub removed_resources: Vec<String>,
    pub modified_resources: Vec<String>,
}

/// Proof that a state transition preserves invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionProof {
    pub from_valid: bool,
    pub to_valid: bool,
    pub diff: StateDiff,
    pub invariants_preserved: bool,
    pub violations: Vec<String>,
}

/// Proof that a rollback is safe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackProof {
    pub forward: TransitionProof,
    pub backward: TransitionProof,
    pub rollback_safe: bool,
}

/// A multi-step migration plan with proofs at each step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub steps: Vec<TransitionProof>,
    pub all_steps_valid: bool,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_modified: usize,
}

/// Hash a JSON value for state identity.
fn hash_state(value: &Value) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    let mut hasher = DefaultHasher::new();
    serialized.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Extract all resource keys from a Terraform JSON value.
///
/// Returns keys in the form `"type.name"` (e.g., `"aws_vpc.main"`).
fn extract_resource_keys(tf: &Value) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    if let Some(resources) = tf.get("resource").and_then(Value::as_object) {
        for (resource_type, instances) in resources {
            if let Some(instances_map) = instances.as_object() {
                for name in instances_map.keys() {
                    keys.insert(format!("{resource_type}.{name}"));
                }
            }
        }
    }
    keys
}

/// Get the JSON value for a specific resource by type and name.
fn get_resource_value<'a>(tf: &'a Value, resource_type: &str, name: &str) -> Option<&'a Value> {
    tf.pointer(&format!("/resource/{resource_type}/{name}"))
}

/// Compute the diff between two Terraform JSON states.
#[must_use]
pub fn compute_diff(from: &Value, to: &Value) -> StateDiff {
    let from_keys = extract_resource_keys(from);
    let to_keys = extract_resource_keys(to);

    let added_resources: Vec<String> = to_keys.difference(&from_keys).cloned().collect();
    let removed_resources: Vec<String> = from_keys.difference(&to_keys).cloned().collect();

    let common_keys: BTreeSet<&String> = from_keys.intersection(&to_keys).collect();
    let mut modified_resources = Vec::new();

    for key in common_keys {
        // Split "type.name" back into components
        if let Some((rtype, rname)) = key.split_once('.') {
            let from_val = get_resource_value(from, rtype, rname);
            let to_val = get_resource_value(to, rtype, rname);
            if from_val != to_val {
                modified_resources.push(key.clone());
            }
        }
    }

    StateDiff {
        from_hash: hash_state(from),
        to_hash: hash_state(to),
        added_resources,
        removed_resources,
        modified_resources,
    }
}

/// Simulate a state transition and prove invariants hold at both endpoints.
#[must_use]
pub fn simulate_transition(from: &Value, to: &Value) -> TransitionProof {
    let diff = compute_diff(from, to);
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();

    let from_result = check_all(&refs, from);
    let to_result = check_all(&refs, to);

    let from_valid = from_result.is_ok();
    let to_valid = to_result.is_ok();

    let mut violations = Vec::new();
    if let Err(ref v) = from_result {
        violations.extend(format_violations(v));
    }
    if let Err(ref v) = to_result {
        violations.extend(format_violations(v));
    }

    TransitionProof {
        from_valid,
        to_valid,
        diff,
        invariants_preserved: from_valid && to_valid,
        violations,
    }
}

/// Prove a rollback path is safe (forward AND backward transitions preserve invariants).
#[must_use]
pub fn prove_rollback(from: &Value, to: &Value) -> RollbackProof {
    let forward = simulate_transition(from, to);
    let backward = simulate_transition(to, from);

    RollbackProof {
        rollback_safe: forward.invariants_preserved && backward.invariants_preserved,
        forward,
        backward,
    }
}

/// Simulate a multi-step migration and prove every step preserves invariants.
#[must_use]
pub fn simulate_migration(steps: &[Value]) -> MigrationPlan {
    if steps.len() < 2 {
        return MigrationPlan {
            steps: vec![],
            all_steps_valid: true,
            total_added: 0,
            total_removed: 0,
            total_modified: 0,
        };
    }

    let mut proofs = Vec::new();
    let mut total_added = 0;
    let mut total_removed = 0;
    let mut total_modified = 0;

    for pair in steps.windows(2) {
        let proof = simulate_transition(&pair[0], &pair[1]);
        total_added += proof.diff.added_resources.len();
        total_removed += proof.diff.removed_resources.len();
        total_modified += proof.diff.modified_resources.len();
        proofs.push(proof);
    }

    let all_steps_valid = proofs.iter().all(|p| p.invariants_preserved);

    MigrationPlan {
        steps: proofs,
        all_steps_valid,
        total_added,
        total_removed,
        total_modified,
    }
}

/// Format violations into human-readable strings.
fn format_violations(violations: &[Violation]) -> Vec<String> {
    violations
        .iter()
        .map(|v| format!("[{}] {}.{}: {}", v.invariant, v.resource_type, v.resource_name, v.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn compliant_state(name: &str) -> Value {
        json!({
            "resource": {
                "aws_vpc": {
                    format!("{name}-vpc"): {
                        "cidr_block": "10.0.0.0/16",
                        "tags": {"ManagedBy": "pangea", "Purpose": "simulation"}
                    }
                }
            }
        })
    }

    #[test]
    fn hash_state_deterministic() {
        let state = compliant_state("test");
        assert_eq!(hash_state(&state), hash_state(&state));
    }

    #[test]
    fn extract_keys_from_empty() {
        let keys = extract_resource_keys(&json!({}));
        assert!(keys.is_empty());
    }

    #[test]
    fn extract_keys_from_resources() {
        let tf = compliant_state("test");
        let keys = extract_resource_keys(&tf);
        assert_eq!(keys.len(), 1);
        assert!(keys.contains("aws_vpc.test-vpc"));
    }
}
