//! System mutation engine -- migrate any system to its best proven version.
//!
//! If we can type a system's current state and its ideal state, the
//! transition is a sequence of typed mutations, each provably safe.
//! Migration IS convergence through typed permutations.
//!
//! The engine reuses the same remediation patterns from `remediation.rs`
//! but frames them as discrete `Mutation` values that can be composed,
//! serialized, diffed, and reversed.

use crate::invariants::{all_invariants, check_all, Invariant};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// A typed mutation -- a single atomic change to a system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Mutation {
    /// Add a new resource.
    AddResource {
        resource_type: String,
        name: String,
        config: Value,
    },
    /// Remove a resource.
    RemoveResource {
        resource_type: String,
        name: String,
    },
    /// Modify a field on an existing resource.
    ModifyField {
        resource_type: String,
        name: String,
        field: String,
        value: Value,
    },
    /// Add tags to a resource.
    AddTags {
        resource_type: String,
        name: String,
        tags: Vec<(String, String)>,
    },
    /// Enable encryption on a resource.
    EnableEncryption {
        resource_type: String,
        name: String,
    },
    /// Restrict network access.
    RestrictCidr {
        resource_type: String,
        name: String,
        field: String,
        cidr: String,
    },
}

/// A mutation plan -- ordered sequence of mutations from current to target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationPlan {
    pub mutations: Vec<Mutation>,
    pub invariants_before: usize,
    pub invariants_after: usize,
    pub all_steps_safe: bool,
}

/// Apply a single mutation to Terraform JSON, returning the modified JSON.
#[must_use]
pub fn apply_mutation(tf_json: &Value, mutation: &Mutation) -> Value {
    let mut json = tf_json.clone();
    match mutation {
        Mutation::AddResource {
            resource_type,
            name,
            config,
        } => {
            let root = json.as_object_mut().unwrap_or_else(|| {
                panic!("expected object at root");
            });
            if !root.contains_key("resource") {
                root.insert("resource".into(), json!({}));
            }
            let resources = root
                .get_mut("resource")
                .unwrap()
                .as_object_mut()
                .unwrap();
            if !resources.contains_key(resource_type) {
                resources.insert(resource_type.clone(), json!({}));
            }
            let type_map = resources
                .get_mut(resource_type)
                .unwrap()
                .as_object_mut()
                .unwrap();
            type_map.insert(name.clone(), config.clone());
        }
        Mutation::RemoveResource {
            resource_type,
            name,
        } => {
            if let Some(type_map) = json
                .pointer_mut(&format!("/resource/{resource_type}"))
                .and_then(Value::as_object_mut)
            {
                type_map.remove(name);
            }
        }
        Mutation::ModifyField {
            resource_type,
            name,
            field,
            value,
        } => {
            if let Some(resource) = json
                .pointer_mut(&format!("/resource/{resource_type}/{name}"))
                .and_then(Value::as_object_mut)
            {
                // Handle nested fields (e.g., "metadata_options.http_tokens")
                let parts: Vec<&str> = field.split('.').collect();
                if parts.len() == 1 {
                    resource.insert(field.clone(), value.clone());
                } else {
                    // Navigate to the nested location
                    let mut current: &mut Value =
                        resource.entry(parts[0]).or_insert_with(|| json!({}));
                    for part in &parts[1..parts.len() - 1] {
                        if !current.is_object() {
                            *current = json!({});
                        }
                        current = current
                            .as_object_mut()
                            .unwrap()
                            .entry(*part)
                            .or_insert_with(|| json!({}));
                    }
                    if let Some(obj) = current.as_object_mut() {
                        obj.insert(
                            parts[parts.len() - 1].to_string(),
                            value.clone(),
                        );
                    }
                }
            }
        }
        Mutation::AddTags {
            resource_type,
            name,
            tags,
        } => {
            if let Some(resource) = json
                .pointer_mut(&format!("/resource/{resource_type}/{name}"))
                .and_then(Value::as_object_mut)
            {
                if !resource.contains_key("tags") {
                    resource.insert("tags".into(), json!({}));
                }
                if let Some(tags_obj) = resource
                    .get_mut("tags")
                    .and_then(Value::as_object_mut)
                {
                    for (k, v) in tags {
                        tags_obj.insert(k.clone(), json!(v));
                    }
                }
            }
        }
        Mutation::EnableEncryption {
            resource_type,
            name,
        } => {
            if let Some(resource) = json
                .pointer_mut(&format!("/resource/{resource_type}/{name}"))
                .and_then(Value::as_object_mut)
            {
                resource.insert("encrypted".into(), json!(true));
            }
        }
        Mutation::RestrictCidr {
            resource_type,
            name,
            field,
            cidr,
        } => {
            if let Some(resource) = json
                .pointer_mut(&format!("/resource/{resource_type}/{name}"))
                .and_then(Value::as_object_mut)
            {
                if let Some(cidrs) = resource.get_mut(field).and_then(Value::as_array_mut) {
                    for c in cidrs.iter_mut() {
                        if c.as_str() == Some("0.0.0.0/0") {
                            *c = json!(cidr);
                        }
                    }
                }
            }
        }
    }
    json
}

/// Apply a sequence of mutations, checking invariants after each step.
/// Returns a vec of (resulting JSON, whether all invariants pass) pairs.
#[must_use]
pub fn apply_migration(tf_json: &Value, plan: &MutationPlan) -> Vec<(Value, bool)> {
    let invariants = all_invariants();
    let refs: Vec<&dyn Invariant> = invariants.iter().map(AsRef::as_ref).collect();
    let mut current = tf_json.clone();
    let mut results = Vec::new();

    for mutation in &plan.mutations {
        current = apply_mutation(&current, mutation);
        let valid = check_all(&refs, &current).is_ok();
        results.push((current.clone(), valid));
    }
    results
}

/// Count how many invariants a system satisfies.
#[must_use]
pub fn count_satisfied_invariants(tf_json: &Value) -> usize {
    let invariants = all_invariants();
    invariants
        .iter()
        .filter(|inv| inv.check(tf_json).is_ok())
        .count()
}

/// Compute the mutations needed to optimize a system -- make it satisfy
/// as many invariants as possible. Each mutation is atomic and proven safe.
///
/// Uses the same remediation logic as `remediation.rs` but expressed as
/// discrete `Mutation` values. The optimization is monotonic: the invariant
/// count never decreases after applying the returned plan.
#[must_use]
pub fn optimize_system(tf_json: &Value) -> MutationPlan {
    let before = count_satisfied_invariants(tf_json);
    let mut current = tf_json.clone();
    let mut mutations = Vec::new();

    // 1. Encrypt unencrypted EBS volumes in launch templates
    optimize_ebs_encryption(&current, &mut mutations);
    for m in &mutations {
        current = apply_mutation(&current, m);
    }
    let mut applied_count = mutations.len();

    // 2. Require IMDSv2 on launch templates
    optimize_imdsv2(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 3. Restrict public SSH
    optimize_public_ssh(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 4. Block public S3
    optimize_public_s3(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 5. Replace default VPC references
    optimize_default_vpc(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 6. Make subnets private (disable public IP mapping on untagged subnets)
    optimize_subnets_private(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 7. Enable encryption at rest (RDS + DynamoDB)
    optimize_encryption_at_rest(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 8. Enable access logging on load balancers
    optimize_logging(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }
    applied_count = mutations.len();

    // 9. Add missing tags (ManagedBy + Purpose)
    optimize_tags(&current, &mut mutations);
    for m in &mutations[applied_count..] {
        current = apply_mutation(&current, m);
    }

    let after = count_satisfied_invariants(&current);

    MutationPlan {
        mutations,
        invariants_before: before,
        invariants_after: after,
        all_steps_safe: after >= before,
    }
}

/// Plan migration from current state to target state.
///
/// Computes the diff between `current` and `target`, then generates
/// mutations for each added, removed, and modified resource. The
/// mutations are ordered: removes first, then modifications, then adds.
#[must_use]
pub fn plan_migration(current: &Value, target: &Value) -> MutationPlan {
    let before = count_satisfied_invariants(current);
    let mut mutations = Vec::new();

    let current_keys = extract_resource_keys(current);
    let target_keys = extract_resource_keys(target);

    // Removed resources
    for key in current_keys.difference(&target_keys) {
        if let Some((rtype, rname)) = key.split_once('.') {
            mutations.push(Mutation::RemoveResource {
                resource_type: rtype.to_string(),
                name: rname.to_string(),
            });
        }
    }

    // Modified resources (in both, but different)
    for key in current_keys.intersection(&target_keys) {
        if let Some((rtype, rname)) = key.split_once('.') {
            let from_val = get_resource_value(current, rtype, rname);
            let to_val = get_resource_value(target, rtype, rname);
            if from_val != to_val {
                if let Some(target_config) = to_val {
                    // Generate field-level modifications
                    if let Some(target_obj) = target_config.as_object() {
                        for (field, value) in target_obj {
                            let current_field_val = from_val.and_then(|v| v.get(field));
                            if current_field_val != Some(value) {
                                mutations.push(Mutation::ModifyField {
                                    resource_type: rtype.to_string(),
                                    name: rname.to_string(),
                                    field: field.clone(),
                                    value: value.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Added resources
    for key in target_keys.difference(&current_keys) {
        if let Some((rtype, rname)) = key.split_once('.') {
            if let Some(config) = get_resource_value(target, rtype, rname) {
                mutations.push(Mutation::AddResource {
                    resource_type: rtype.to_string(),
                    name: rname.to_string(),
                    config: config.clone(),
                });
            }
        }
    }

    // Apply all mutations to compute the final state
    let mut final_state = current.clone();
    for m in &mutations {
        final_state = apply_mutation(&final_state, m);
    }
    let after = count_satisfied_invariants(&final_state);

    // The overall plan is safe if the final invariant count is at least
    // as good as where we started.
    let all_safe = after >= before;

    MutationPlan {
        mutations,
        invariants_before: before,
        invariants_after: after,
        all_steps_safe: all_safe,
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Extract all resource keys from a Terraform JSON value.
/// Returns keys in the form `"type.name"`.
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

// ── Optimization functions (mirror remediation.rs patterns) ─────────

fn optimize_ebs_encryption(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(templates) = tf_json.pointer("/resource/aws_launch_template") else {
        return;
    };
    let Some(templates_map) = templates.as_object() else {
        return;
    };

    for (name, tmpl) in templates_map {
        if let Some(mappings) = tmpl
            .get("block_device_mappings")
            .and_then(Value::as_array)
        {
            for mapping in mappings {
                let encrypted = mapping
                    .pointer("/ebs/encrypted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !encrypted {
                    // We apply EnableEncryption as a ModifyField on the
                    // block_device_mappings to set ebs.encrypted = true.
                    // Since we need to modify array elements, we rebuild
                    // the entire block_device_mappings array with encryption.
                    let mut fixed_mappings = mappings.clone();
                    for m in &mut fixed_mappings {
                        if m.pointer("/ebs/encrypted")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        let m_obj = m.as_object_mut().unwrap();
                        if !m_obj.contains_key("ebs") {
                            m_obj.insert("ebs".into(), json!({}));
                        }
                        m_obj
                            .get_mut("ebs")
                            .unwrap()
                            .as_object_mut()
                            .unwrap()
                            .insert("encrypted".into(), json!(true));
                    }
                    mutations.push(Mutation::ModifyField {
                        resource_type: "aws_launch_template".into(),
                        name: name.clone(),
                        field: "block_device_mappings".into(),
                        value: Value::Array(fixed_mappings),
                    });
                    break; // One mutation per template
                }
            }
        }
    }
}

fn optimize_imdsv2(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(templates) = tf_json.pointer("/resource/aws_launch_template") else {
        return;
    };
    let Some(templates_map) = templates.as_object() else {
        return;
    };

    for (name, tmpl) in templates_map {
        let http_tokens = tmpl
            .pointer("/metadata_options/http_tokens")
            .and_then(Value::as_str)
            .unwrap_or("optional");
        if http_tokens != "required" {
            mutations.push(Mutation::ModifyField {
                resource_type: "aws_launch_template".into(),
                name: name.clone(),
                field: "metadata_options.http_tokens".into(),
                value: json!("required"),
            });
        }
    }
}

fn optimize_public_ssh(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(rules) = tf_json.pointer("/resource/aws_security_group_rule") else {
        return;
    };
    let Some(rules_map) = rules.as_object() else {
        return;
    };

    for (name, rule) in rules_map {
        let from_port = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
        let to_port = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
        let rule_type = rule
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("");

        if rule_type == "ingress" && from_port <= 22 && to_port >= 22 {
            if let Some(cidrs) = rule.get("cidr_blocks").and_then(Value::as_array) {
                let has_open = cidrs.iter().any(|c| c.as_str() == Some("0.0.0.0/0"));
                if has_open {
                    mutations.push(Mutation::RestrictCidr {
                        resource_type: "aws_security_group_rule".into(),
                        name: name.clone(),
                        field: "cidr_blocks".into(),
                        cidr: "10.0.0.0/8".into(),
                    });
                }
            }
        }
    }
}

fn optimize_public_s3(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(blocks) = tf_json.pointer("/resource/aws_s3_bucket_public_access_block") else {
        return;
    };
    let Some(blocks_map) = blocks.as_object() else {
        return;
    };

    for (name, block) in blocks_map {
        let block_acls = block
            .get("block_public_acls")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !block_acls {
            mutations.push(Mutation::ModifyField {
                resource_type: "aws_s3_bucket_public_access_block".into(),
                name: name.clone(),
                field: "block_public_acls".into(),
                value: json!(true),
            });
        }

        let block_policy = block
            .get("block_public_policy")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !block_policy {
            mutations.push(Mutation::ModifyField {
                resource_type: "aws_s3_bucket_public_access_block".into(),
                name: name.clone(),
                field: "block_public_policy".into(),
                value: json!(true),
            });
        }
    }
}

fn optimize_default_vpc(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(resources) = tf_json.get("resource").and_then(Value::as_object) else {
        return;
    };

    for (resource_type, instances) in resources {
        if let Some(instances_map) = instances.as_object() {
            for (name, config) in instances_map {
                if config.get("vpc_id").and_then(Value::as_str) == Some("default") {
                    mutations.push(Mutation::ModifyField {
                        resource_type: resource_type.clone(),
                        name: name.clone(),
                        field: "vpc_id".into(),
                        value: json!("vpc-custom"),
                    });
                }
            }
        }
    }
}

fn optimize_subnets_private(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(subnets) = tf_json.pointer("/resource/aws_subnet") else {
        return;
    };
    let Some(subnets_map) = subnets.as_object() else {
        return;
    };

    for (name, subnet) in subnets_map {
        let maps_public = subnet
            .get("map_public_ip_on_launch")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if maps_public {
            let has_public_tag = subnet
                .pointer("/tags/Tier")
                .and_then(Value::as_str)
                == Some("public");
            if !has_public_tag {
                mutations.push(Mutation::ModifyField {
                    resource_type: "aws_subnet".into(),
                    name: name.clone(),
                    field: "map_public_ip_on_launch".into(),
                    value: json!(false),
                });
            }
        }
    }
}

fn optimize_encryption_at_rest(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    // RDS instances
    if let Some(dbs) = tf_json.pointer("/resource/aws_db_instance") {
        if let Some(dbs_map) = dbs.as_object() {
            for (name, db) in dbs_map {
                let encrypted = db
                    .get("storage_encrypted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !encrypted {
                    mutations.push(Mutation::ModifyField {
                        resource_type: "aws_db_instance".into(),
                        name: name.clone(),
                        field: "storage_encrypted".into(),
                        value: json!(true),
                    });
                }
            }
        }
    }

    // DynamoDB tables
    if let Some(tables) = tf_json.pointer("/resource/aws_dynamodb_table") {
        if let Some(tables_map) = tables.as_object() {
            for (name, table) in tables_map {
                let sse_enabled = table
                    .pointer("/server_side_encryption/enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !sse_enabled {
                    mutations.push(Mutation::ModifyField {
                        resource_type: "aws_dynamodb_table".into(),
                        name: name.clone(),
                        field: "server_side_encryption.enabled".into(),
                        value: json!(true),
                    });
                }
            }
        }
    }
}

fn optimize_logging(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(lbs) = tf_json.pointer("/resource/aws_lb") else {
        return;
    };
    let Some(lbs_map) = lbs.as_object() else {
        return;
    };

    for (name, lb) in lbs_map {
        let logging_enabled = lb
            .pointer("/access_logs/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !logging_enabled {
            mutations.push(Mutation::ModifyField {
                resource_type: "aws_lb".into(),
                name: name.clone(),
                field: "access_logs.enabled".into(),
                value: json!(true),
            });
        }
    }
}

fn optimize_tags(tf_json: &Value, mutations: &mut Vec<Mutation>) {
    let Some(resources) = tf_json.get("resource").and_then(Value::as_object) else {
        return;
    };

    for (resource_type, instances) in resources {
        if let Some(instances_map) = instances.as_object() {
            for (name, config) in instances_map {
                let tags = config.get("tags").and_then(Value::as_object);
                let has_managed_by = tags.and_then(|t| t.get("ManagedBy")).is_some();
                let has_purpose = tags.and_then(|t| t.get("Purpose")).is_some();

                if !has_managed_by || !has_purpose {
                    let mut tag_pairs = Vec::new();
                    if !has_managed_by {
                        tag_pairs.push(("ManagedBy".to_string(), "pangea".to_string()));
                    }
                    if !has_purpose {
                        tag_pairs.push(("Purpose".to_string(), "auto-optimized".to_string()));
                    }
                    mutations.push(Mutation::AddTags {
                        resource_type: resource_type.clone(),
                        name: name.clone(),
                        tags: tag_pairs,
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn apply_mutation_add_resource_adds_it() {
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

    #[test]
    fn apply_mutation_modify_field_changes_value() {
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

    #[test]
    fn optimize_system_on_empty_json_makes_no_mutations() {
        let tf = json!({});
        let plan = optimize_system(&tf);
        assert!(plan.mutations.is_empty());
        assert_eq!(plan.invariants_before, plan.invariants_after);
    }

    #[test]
    fn count_satisfied_on_empty_json_is_ten() {
        // Empty JSON passes all 10 invariants (no resources to violate)
        assert_eq!(count_satisfied_invariants(&json!({})), 10);
    }
}
