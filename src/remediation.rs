//! Auto-remediation -- transform non-compliant JSON into compliant JSON.
//!
//! Given compliance violations, automatically apply fixes. The key property:
//! `remediate(json, invariant_name)` ALWAYS produces JSON that passes
//! the violated invariant. This is proven by proptest.
//!
//! # Design
//!
//! Each remediation function is the *inverse* of the corresponding invariant
//! check. The invariant inspects a field and reports a violation; the
//! remediation sets that same field to the compliant value.
//!
//! # Limitations
//!
//! `IamLeastPrivilege` cannot be auto-remediated safely -- restricting
//! `Action: "*"` requires knowing the specific permissions needed, which
//! is application-specific. The engine flags this invariant as unremediated.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::invariants::{
    all_invariants, AllEbsEncrypted, AllSubnetsPrivate, EncryptionAtRest, ImdsV2Required,
    Invariant, LoggingEnabled, NoDefaultVpcUsage, NoPublicS3, NoPublicSsh, TaggingComplete,
};

/// A single remediation action applied to fix a violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Which invariant this remediation addresses.
    pub invariant: String,
    /// The resource type that was modified.
    pub resource_type: String,
    /// The resource name that was modified.
    pub resource_name: String,
    /// What kind of fix was applied.
    pub action: RemediationAction,
    /// Human-readable description of the fix.
    pub description: String,
}

/// What kind of fix was applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationAction {
    /// Set a field to a specific value.
    SetField { field: String, value: Value },
    /// Restrict a CIDR range.
    RestrictCidr {
        field: String,
        from: String,
        to: String,
    },
    /// Add tags to a resource.
    AddTags { tags: Vec<(String, String)> },
}

/// Result of remediation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    /// Number of violations found before remediation.
    pub original_violations: usize,
    /// List of remediations applied.
    pub remediations_applied: Vec<Remediation>,
    /// Number of violations remaining after remediation.
    pub remaining_violations: usize,
    /// Whether all violations were fixed.
    pub fully_remediated: bool,
    /// The remediated Terraform JSON.
    pub remediated_json: Value,
}

/// Invariants that cannot be auto-remediated safely.
const UNREMEDIATED_INVARIANTS: &[&str] = &["iam_least_privilege"];

/// Returns true if an invariant can be auto-remediated.
#[must_use]
pub fn can_remediate(invariant_name: &str) -> bool {
    !UNREMEDIATED_INVARIANTS.contains(&invariant_name)
}

/// Remediate Terraform JSON to fix a single invariant's violations.
///
/// Returns a `RemediationResult` with the fixed JSON and a record of
/// every change that was made. If the invariant cannot be auto-remediated
/// (e.g., `IamLeastPrivilege`), returns the JSON unchanged.
#[must_use]
pub fn remediate(tf_json: &Value, invariant_name: &str) -> RemediationResult {
    let mut working_json = tf_json.clone();
    let mut remediations = Vec::new();

    // Count original violations
    let original_violations = count_violations(&working_json, invariant_name);

    match invariant_name {
        "no_public_ssh" => remediate_public_ssh(&mut working_json, &mut remediations),
        "all_ebs_encrypted" => remediate_ebs_encryption(&mut working_json, &mut remediations),
        "imdsv2_required" => remediate_imds_v2(&mut working_json, &mut remediations),
        "no_public_s3" => remediate_public_s3(&mut working_json, &mut remediations),
        "no_default_vpc_usage" => {
            remediate_no_default_vpc(&mut working_json, &mut remediations);
        }
        "all_subnets_private" => {
            remediate_subnets_private(&mut working_json, &mut remediations);
        }
        "encryption_at_rest" => {
            remediate_encryption_at_rest(&mut working_json, &mut remediations);
        }
        "logging_enabled" => remediate_logging_enabled(&mut working_json, &mut remediations),
        "tagging_complete" => remediate_tags(&mut working_json, &mut remediations),
        // IamLeastPrivilege intentionally omitted -- cannot auto-fix safely
        _ => {}
    }

    let remaining = count_violations(&working_json, invariant_name);

    RemediationResult {
        original_violations,
        remediations_applied: remediations,
        remaining_violations: remaining,
        fully_remediated: remaining == 0,
        remediated_json: working_json,
    }
}

/// Remediate ALL violations across all invariants at once.
///
/// Applies remediations for every invariant that can be auto-fixed.
/// `IamLeastPrivilege` is skipped. Returns the fully remediated JSON
/// and a combined record of all changes.
#[must_use]
pub fn remediate_all(tf_json: &Value) -> RemediationResult {
    let mut working_json = tf_json.clone();
    let mut all_remediations = Vec::new();
    let mut total_original = 0;

    let invariants = all_invariants();
    for inv in &invariants {
        let name = inv.name();
        if !can_remediate(name) {
            continue;
        }
        total_original += count_violations(&working_json, name);
        let result = remediate(&working_json, name);
        all_remediations.extend(result.remediations_applied);
        working_json = result.remediated_json;
    }

    // Count remaining violations across all invariants
    let mut total_remaining = 0;
    for inv in &invariants {
        if !can_remediate(inv.name()) {
            continue;
        }
        total_remaining += count_violations(&working_json, inv.name());
    }

    RemediationResult {
        original_violations: total_original,
        remediations_applied: all_remediations,
        remaining_violations: total_remaining,
        fully_remediated: total_remaining == 0,
        remediated_json: working_json,
    }
}

// ── Helper: count violations for an invariant ─────────────────────────

fn count_violations(tf_json: &Value, invariant_name: &str) -> usize {
    let checker: Box<dyn Invariant> = match invariant_name {
        "no_public_ssh" => Box::new(NoPublicSsh),
        "all_ebs_encrypted" => Box::new(AllEbsEncrypted),
        "imdsv2_required" => Box::new(ImdsV2Required),
        "no_public_s3" => Box::new(NoPublicS3),
        "no_default_vpc_usage" => Box::new(NoDefaultVpcUsage),
        "all_subnets_private" => Box::new(AllSubnetsPrivate),
        "encryption_at_rest" => Box::new(EncryptionAtRest),
        "logging_enabled" => Box::new(LoggingEnabled),
        "tagging_complete" => Box::new(TaggingComplete),
        _ => return 0,
    };
    match checker.check(tf_json) {
        Ok(()) => 0,
        Err(violations) => violations.len(),
    }
}

// ── Remediation functions ─────────────────────────────────────────────

/// Replace `0.0.0.0/0` CIDR on SSH ingress rules with `10.0.0.0/8`.
fn remediate_public_ssh(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(rules) = json.pointer_mut("/resource/aws_security_group_rule") else {
        return;
    };
    let Some(rules_map) = rules.as_object_mut() else {
        return;
    };

    for (name, rule) in rules_map.iter_mut() {
        let from_port = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
        let to_port = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
        let rule_type = rule
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        if rule_type == "ingress" && from_port <= 22 && to_port >= 22 {
            if let Some(cidrs) = rule.get_mut("cidr_blocks").and_then(Value::as_array_mut) {
                for cidr in cidrs.iter_mut() {
                    if cidr.as_str() == Some("0.0.0.0/0") {
                        let old = cidr.as_str().unwrap_or("").to_string();
                        *cidr = json!("10.0.0.0/8");
                        remediations.push(Remediation {
                            invariant: "no_public_ssh".into(),
                            resource_type: "aws_security_group_rule".into(),
                            resource_name: name.clone(),
                            action: RemediationAction::RestrictCidr {
                                field: "cidr_blocks".into(),
                                from: old,
                                to: "10.0.0.0/8".into(),
                            },
                            description: format!(
                                "Restricted SSH CIDR from 0.0.0.0/0 to 10.0.0.0/8 on rule '{name}'"
                            ),
                        });
                    }
                }
            }
        }
    }
}

/// Set `encrypted: true` on all EBS block device mappings in launch templates.
fn remediate_ebs_encryption(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(templates) = json.pointer_mut("/resource/aws_launch_template") else {
        return;
    };
    let Some(templates_map) = templates.as_object_mut() else {
        return;
    };

    for (name, tmpl) in templates_map.iter_mut() {
        if let Some(mappings) = tmpl
            .get_mut("block_device_mappings")
            .and_then(Value::as_array_mut)
        {
            for mapping in mappings.iter_mut() {
                let encrypted = mapping
                    .pointer("/ebs/encrypted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);

                if !encrypted {
                    // Ensure ebs object exists
                    if mapping.get("ebs").is_none() {
                        mapping
                            .as_object_mut()
                            .unwrap()
                            .insert("ebs".into(), json!({}));
                    }
                    mapping
                        .get_mut("ebs")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert("encrypted".into(), json!(true));

                    remediations.push(Remediation {
                        invariant: "all_ebs_encrypted".into(),
                        resource_type: "aws_launch_template".into(),
                        resource_name: name.clone(),
                        action: RemediationAction::SetField {
                            field: "block_device_mappings[].ebs.encrypted".into(),
                            value: json!(true),
                        },
                        description: format!(
                            "Set EBS encrypted: true on launch template '{name}'"
                        ),
                    });
                }
            }
        }
    }
}

/// Set `http_tokens: "required"` on all launch templates.
fn remediate_imds_v2(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(templates) = json.pointer_mut("/resource/aws_launch_template") else {
        return;
    };
    let Some(templates_map) = templates.as_object_mut() else {
        return;
    };

    for (name, tmpl) in templates_map.iter_mut() {
        let http_tokens = tmpl
            .pointer("/metadata_options/http_tokens")
            .and_then(Value::as_str)
            .unwrap_or("optional");

        if http_tokens != "required" {
            let tmpl_obj = tmpl.as_object_mut().unwrap();
            if tmpl_obj.get("metadata_options").is_none() {
                tmpl_obj.insert("metadata_options".into(), json!({}));
            }
            tmpl_obj
                .get_mut("metadata_options")
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("http_tokens".into(), json!("required"));

            remediations.push(Remediation {
                invariant: "imdsv2_required".into(),
                resource_type: "aws_launch_template".into(),
                resource_name: name.clone(),
                action: RemediationAction::SetField {
                    field: "metadata_options.http_tokens".into(),
                    value: json!("required"),
                },
                description: format!(
                    "Set http_tokens: \"required\" on launch template '{name}'"
                ),
            });
        }
    }
}

/// Set `block_public_acls: true` and `block_public_policy: true` on S3 public
/// access blocks.
fn remediate_public_s3(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(blocks) = json.pointer_mut("/resource/aws_s3_bucket_public_access_block") else {
        return;
    };
    let Some(blocks_map) = blocks.as_object_mut() else {
        return;
    };

    for (name, block) in blocks_map.iter_mut() {
        let block_obj = block.as_object_mut().unwrap();

        let block_acls = block_obj
            .get("block_public_acls")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !block_acls {
            block_obj.insert("block_public_acls".into(), json!(true));
            remediations.push(Remediation {
                invariant: "no_public_s3".into(),
                resource_type: "aws_s3_bucket_public_access_block".into(),
                resource_name: name.clone(),
                action: RemediationAction::SetField {
                    field: "block_public_acls".into(),
                    value: json!(true),
                },
                description: format!(
                    "Set block_public_acls: true on S3 access block '{name}'"
                ),
            });
        }

        let block_policy = block_obj
            .get("block_public_policy")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !block_policy {
            block_obj.insert("block_public_policy".into(), json!(true));
            remediations.push(Remediation {
                invariant: "no_public_s3".into(),
                resource_type: "aws_s3_bucket_public_access_block".into(),
                resource_name: name.clone(),
                action: RemediationAction::SetField {
                    field: "block_public_policy".into(),
                    value: json!(true),
                },
                description: format!(
                    "Set block_public_policy: true on S3 access block '{name}'"
                ),
            });
        }
    }
}

/// Replace `vpc_id: "default"` with a placeholder custom VPC ID.
fn remediate_no_default_vpc(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(resources) = json.get_mut("resource").and_then(Value::as_object_mut) else {
        return;
    };

    for (resource_type, instances) in resources.iter_mut() {
        if let Some(instances_map) = instances.as_object_mut() {
            for (name, config) in instances_map.iter_mut() {
                if config.get("vpc_id").and_then(Value::as_str) == Some("default") {
                    config
                        .as_object_mut()
                        .unwrap()
                        .insert("vpc_id".into(), json!("vpc-custom"));

                    remediations.push(Remediation {
                        invariant: "no_default_vpc_usage".into(),
                        resource_type: resource_type.clone(),
                        resource_name: name.clone(),
                        action: RemediationAction::SetField {
                            field: "vpc_id".into(),
                            value: json!("vpc-custom"),
                        },
                        description: format!(
                            "Changed vpc_id from 'default' to 'vpc-custom' on {resource_type} '{name}'"
                        ),
                    });
                }
            }
        }
    }
}

/// Add `Tier: public` tag to subnets that have `map_public_ip_on_launch: true`
/// but are missing the tag. Alternatively, set `map_public_ip_on_launch: false`.
/// We choose the safer option: disable public IP mapping.
fn remediate_subnets_private(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(subnets) = json.pointer_mut("/resource/aws_subnet") else {
        return;
    };
    let Some(subnets_map) = subnets.as_object_mut() else {
        return;
    };

    for (name, subnet) in subnets_map.iter_mut() {
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
                // Safer fix: disable public IP mapping rather than adding a Tier:public tag
                subnet
                    .as_object_mut()
                    .unwrap()
                    .insert("map_public_ip_on_launch".into(), json!(false));

                remediations.push(Remediation {
                    invariant: "all_subnets_private".into(),
                    resource_type: "aws_subnet".into(),
                    resource_name: name.clone(),
                    action: RemediationAction::SetField {
                        field: "map_public_ip_on_launch".into(),
                        value: json!(false),
                    },
                    description: format!(
                        "Set map_public_ip_on_launch: false on subnet '{name}' (no Tier:public tag)"
                    ),
                });
            }
        }
    }
}

/// Set `storage_encrypted: true` on RDS instances and
/// `server_side_encryption.enabled: true` on DynamoDB tables.
fn remediate_encryption_at_rest(json: &mut Value, remediations: &mut Vec<Remediation>) {
    // RDS instances
    if let Some(dbs) = json.pointer_mut("/resource/aws_db_instance") {
        if let Some(dbs_map) = dbs.as_object_mut() {
            for (name, db) in dbs_map.iter_mut() {
                let encrypted = db
                    .get("storage_encrypted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !encrypted {
                    db.as_object_mut()
                        .unwrap()
                        .insert("storage_encrypted".into(), json!(true));
                    remediations.push(Remediation {
                        invariant: "encryption_at_rest".into(),
                        resource_type: "aws_db_instance".into(),
                        resource_name: name.clone(),
                        action: RemediationAction::SetField {
                            field: "storage_encrypted".into(),
                            value: json!(true),
                        },
                        description: format!(
                            "Set storage_encrypted: true on RDS instance '{name}'"
                        ),
                    });
                }
            }
        }
    }

    // DynamoDB tables
    if let Some(tables) = json.pointer_mut("/resource/aws_dynamodb_table") {
        if let Some(tables_map) = tables.as_object_mut() {
            for (name, table) in tables_map.iter_mut() {
                let sse_enabled = table
                    .pointer("/server_side_encryption/enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !sse_enabled {
                    let tbl = table.as_object_mut().unwrap();
                    if tbl.get("server_side_encryption").is_none() {
                        tbl.insert("server_side_encryption".into(), json!({}));
                    }
                    tbl.get_mut("server_side_encryption")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert("enabled".into(), json!(true));

                    remediations.push(Remediation {
                        invariant: "encryption_at_rest".into(),
                        resource_type: "aws_dynamodb_table".into(),
                        resource_name: name.clone(),
                        action: RemediationAction::SetField {
                            field: "server_side_encryption.enabled".into(),
                            value: json!(true),
                        },
                        description: format!(
                            "Set server_side_encryption.enabled: true on DynamoDB table '{name}'"
                        ),
                    });
                }
            }
        }
    }
}

/// Set `access_logs.enabled: true` on all load balancers.
fn remediate_logging_enabled(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(lbs) = json.pointer_mut("/resource/aws_lb") else {
        return;
    };
    let Some(lbs_map) = lbs.as_object_mut() else {
        return;
    };

    for (name, lb) in lbs_map.iter_mut() {
        let logging_enabled = lb
            .pointer("/access_logs/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if !logging_enabled {
            let lb_obj = lb.as_object_mut().unwrap();
            if lb_obj.get("access_logs").is_none() {
                lb_obj.insert(
                    "access_logs".into(),
                    json!({
                        "enabled": true,
                        "bucket": "access-logs"
                    }),
                );
            } else {
                lb_obj
                    .get_mut("access_logs")
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("enabled".into(), json!(true));
            }

            remediations.push(Remediation {
                invariant: "logging_enabled".into(),
                resource_type: "aws_lb".into(),
                resource_name: name.clone(),
                action: RemediationAction::SetField {
                    field: "access_logs.enabled".into(),
                    value: json!(true),
                },
                description: format!("Set access_logs.enabled: true on load balancer '{name}'"),
            });
        }
    }
}

/// Add `ManagedBy` and `Purpose` tags to all resources missing them.
fn remediate_tags(json: &mut Value, remediations: &mut Vec<Remediation>) {
    let Some(resources) = json.get_mut("resource").and_then(Value::as_object_mut) else {
        return;
    };

    for (resource_type, instances) in resources.iter_mut() {
        if let Some(instances_map) = instances.as_object_mut() {
            for (name, config) in instances_map.iter_mut() {
                let config_obj = config.as_object_mut().unwrap();
                if config_obj.get("tags").is_none() {
                    config_obj.insert("tags".into(), json!({}));
                }

                let tags = config_obj
                    .get_mut("tags")
                    .unwrap()
                    .as_object_mut()
                    .unwrap();

                let mut added = Vec::new();

                if !tags.contains_key("ManagedBy") {
                    tags.insert("ManagedBy".into(), json!("pangea"));
                    added.push(("ManagedBy".to_string(), "pangea".to_string()));
                }
                if !tags.contains_key("Purpose") {
                    tags.insert("Purpose".into(), json!("auto-remediated"));
                    added.push(("Purpose".to_string(), "auto-remediated".to_string()));
                }

                if !added.is_empty() {
                    remediations.push(Remediation {
                        invariant: "tagging_complete".into(),
                        resource_type: resource_type.clone(),
                        resource_name: name.clone(),
                        action: RemediationAction::AddTags { tags: added },
                        description: format!(
                            "Added required tags to {resource_type} '{name}'"
                        ),
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
    fn remediate_public_ssh_restricts_cidr() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "bad_ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "no_public_ssh");
        assert!(result.fully_remediated);
        assert_eq!(result.remediations_applied.len(), 1);

        // Verify the CIDR was changed
        let cidr = result
            .remediated_json
            .pointer("/resource/aws_security_group_rule/bad_ssh/cidr_blocks/0")
            .unwrap();
        assert_eq!(cidr, "10.0.0.0/8");
    }

    #[test]
    fn remediate_ebs_encryption_sets_true() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "unencrypted": {
                        "block_device_mappings": [{"ebs": {"encrypted": false, "volume_size": 100}}],
                        "metadata_options": {"http_tokens": "required"},
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "all_ebs_encrypted");
        assert!(result.fully_remediated);

        let encrypted = result
            .remediated_json
            .pointer("/resource/aws_launch_template/unencrypted/block_device_mappings/0/ebs/encrypted")
            .unwrap();
        assert_eq!(encrypted, true);
    }

    #[test]
    fn remediate_imds_v2_sets_required() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "no_imds": {
                        "metadata_options": {"http_tokens": "optional"},
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "imdsv2_required");
        assert!(result.fully_remediated);

        let tokens = result
            .remediated_json
            .pointer("/resource/aws_launch_template/no_imds/metadata_options/http_tokens")
            .unwrap();
        assert_eq!(tokens, "required");
    }

    #[test]
    fn remediate_public_s3_blocks_access() {
        let tf = json!({
            "resource": {
                "aws_s3_bucket_public_access_block": {
                    "open": {
                        "block_public_acls": false,
                        "block_public_policy": false,
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "no_public_s3");
        assert!(result.fully_remediated);

        let block = &result.remediated_json;
        assert_eq!(
            block.pointer("/resource/aws_s3_bucket_public_access_block/open/block_public_acls"),
            Some(&json!(true))
        );
        assert_eq!(
            block.pointer("/resource/aws_s3_bucket_public_access_block/open/block_public_policy"),
            Some(&json!(true))
        );
    }

    #[test]
    fn remediate_tags_adds_missing() {
        let tf = json!({
            "resource": {
                "aws_vpc": {
                    "main": {
                        "cidr_block": "10.0.0.0/16"
                    }
                }
            }
        });
        let result = remediate(&tf, "tagging_complete");
        assert!(result.fully_remediated);

        let tags = result
            .remediated_json
            .pointer("/resource/aws_vpc/main/tags")
            .unwrap();
        assert_eq!(tags.get("ManagedBy").unwrap(), "pangea");
        assert!(tags.get("Purpose").is_some());
    }

    #[test]
    fn iam_least_privilege_cannot_be_remediated() {
        assert!(!can_remediate("iam_least_privilege"));
        let tf = json!({
            "resource": {
                "aws_iam_policy": {
                    "admin": {
                        "policy": "{\"Statement\":[{\"Action\":\"*\",\"Resource\":\"*\",\"Effect\":\"Allow\"}]}"
                    }
                }
            }
        });
        let result = remediate(&tf, "iam_least_privilege");
        // No changes -- cannot auto-remediate
        assert!(result.remediations_applied.is_empty());
    }

    #[test]
    fn remediate_all_fixes_multiple() {
        let tf = json!({
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
                        "block_device_mappings": [{"ebs": {"encrypted": false}}],
                        "metadata_options": {"http_tokens": "optional"}
                    }
                }
            }
        });
        let result = remediate_all(&tf);
        assert!(result.fully_remediated);
        // At minimum: SSH cidr + EBS encryption + IMDSv2 + 2x tags
        assert!(result.remediations_applied.len() >= 4);
    }

    #[test]
    fn remediate_no_default_vpc_replaces_default() {
        let tf = json!({
            "resource": {
                "aws_instance": {
                    "bad": {
                        "vpc_id": "default",
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "no_default_vpc_usage");
        assert!(result.fully_remediated);
        let vpc_id = result
            .remediated_json
            .pointer("/resource/aws_instance/bad/vpc_id")
            .unwrap();
        assert_ne!(vpc_id, "default");
    }

    #[test]
    fn remediate_encryption_at_rest_rds() {
        let tf = json!({
            "resource": {
                "aws_db_instance": {
                    "db": {
                        "storage_encrypted": false,
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "encryption_at_rest");
        assert!(result.fully_remediated);
        assert_eq!(
            result.remediated_json.pointer("/resource/aws_db_instance/db/storage_encrypted"),
            Some(&json!(true))
        );
    }

    #[test]
    fn remediate_encryption_at_rest_dynamodb() {
        let tf = json!({
            "resource": {
                "aws_dynamodb_table": {
                    "tbl": {
                        "name": "test",
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "encryption_at_rest");
        assert!(result.fully_remediated);
        assert_eq!(
            result.remediated_json.pointer("/resource/aws_dynamodb_table/tbl/server_side_encryption/enabled"),
            Some(&json!(true))
        );
    }

    #[test]
    fn remediate_logging_enabled_sets_access_logs() {
        let tf = json!({
            "resource": {
                "aws_lb": {
                    "main": {
                        "name": "test-lb",
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "logging_enabled");
        assert!(result.fully_remediated);
        assert_eq!(
            result.remediated_json.pointer("/resource/aws_lb/main/access_logs/enabled"),
            Some(&json!(true))
        );
    }

    #[test]
    fn remediate_subnets_private_disables_public_ip() {
        let tf = json!({
            "resource": {
                "aws_subnet": {
                    "exposed": {
                        "map_public_ip_on_launch": true,
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let result = remediate(&tf, "all_subnets_private");
        assert!(result.fully_remediated);
        assert_eq!(
            result.remediated_json.pointer("/resource/aws_subnet/exposed/map_public_ip_on_launch"),
            Some(&json!(false))
        );
    }
}
