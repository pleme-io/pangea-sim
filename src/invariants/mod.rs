//! Invariant proof engine — verify security properties hold for ALL configurations.
//!
//! Each invariant is a function from Terraform JSON → Result. If it returns Ok,
//! the property holds. If it returns Err, the violations are listed.
//!
//! Combined with proptest, this proves invariants across random configurations:
//! "Checked 10,000 configs. 0 violations. Property proven."

pub mod k8s;

use serde_json::Value;

/// A violation of a security invariant.
#[derive(Debug, Clone)]
pub struct Violation {
    /// Which invariant was violated.
    pub invariant: String,
    /// The resource type (e.g., "aws_security_group_rule").
    pub resource_type: String,
    /// The resource name.
    pub resource_name: String,
    /// Human-readable description.
    pub message: String,
}

/// A security invariant that can be checked against Terraform JSON.
pub trait Invariant: Send + Sync {
    /// Name of this invariant (e.g., "no_public_ssh").
    fn name(&self) -> &str;

    /// Check the invariant against synthesized Terraform JSON.
    /// Returns Ok(()) if the invariant holds, Err(violations) if not.
    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>>;
}

/// Check all invariants against a Terraform JSON value.
///
/// Returns Ok(()) if all pass, Err with all violations if any fail.
pub fn check_all(invariants: &[&dyn Invariant], tf_json: &Value) -> Result<(), Vec<Violation>> {
    let mut all_violations = Vec::new();
    for inv in invariants {
        if let Err(violations) = inv.check(tf_json) {
            all_violations.extend(violations);
        }
    }
    if all_violations.is_empty() {
        Ok(())
    } else {
        Err(all_violations)
    }
}

// ── Built-in invariants ─────────────────────────────────────────

/// No security group rule allows SSH (port 22) from 0.0.0.0/0.
pub struct NoPublicSsh;

impl Invariant for NoPublicSsh {
    fn name(&self) -> &str { "no_public_ssh" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(rules) = tf_json.pointer("/resource/aws_security_group_rule") {
            if let Some(rules_map) = rules.as_object() {
                for (name, rule) in rules_map {
                    let from_port = rule.get("from_port").and_then(Value::as_i64).unwrap_or(0);
                    let to_port = rule.get("to_port").and_then(Value::as_i64).unwrap_or(0);
                    let rule_type = rule.get("type").and_then(Value::as_str).unwrap_or("");

                    if rule_type == "ingress" && from_port <= 22 && to_port >= 22 {
                        if let Some(cidrs) = rule.get("cidr_blocks").and_then(Value::as_array) {
                            for cidr in cidrs {
                                if cidr.as_str() == Some("0.0.0.0/0") {
                                    violations.push(Violation {
                                        invariant: self.name().into(),
                                        resource_type: "aws_security_group_rule".into(),
                                        resource_name: name.clone(),
                                        message: "SSH (port 22) open to 0.0.0.0/0".into(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All EBS volumes and launch template block devices must be encrypted.
pub struct AllEbsEncrypted;

impl Invariant for AllEbsEncrypted {
    fn name(&self) -> &str { "all_ebs_encrypted" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        // Check launch templates
        if let Some(templates) = tf_json.pointer("/resource/aws_launch_template") {
            if let Some(templates_map) = templates.as_object() {
                for (name, tmpl) in templates_map {
                    if let Some(mappings) = tmpl.get("block_device_mappings").and_then(Value::as_array) {
                        for mapping in mappings {
                            let encrypted = mapping
                                .pointer("/ebs/encrypted")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            if !encrypted {
                                violations.push(Violation {
                                    invariant: self.name().into(),
                                    resource_type: "aws_launch_template".into(),
                                    resource_name: name.clone(),
                                    message: "EBS volume not encrypted".into(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All launch templates must require IMDSv2 (http_tokens: "required").
pub struct ImdsV2Required;

impl Invariant for ImdsV2Required {
    fn name(&self) -> &str { "imdsv2_required" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(templates) = tf_json.pointer("/resource/aws_launch_template") {
            if let Some(templates_map) = templates.as_object() {
                for (name, tmpl) in templates_map {
                    let http_tokens = tmpl
                        .pointer("/metadata_options/http_tokens")
                        .and_then(Value::as_str)
                        .unwrap_or("optional");
                    if http_tokens != "required" {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_launch_template".into(),
                            resource_name: name.clone(),
                            message: format!("IMDSv2 not required (http_tokens: \"{http_tokens}\")"),
                        });
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// No S3 bucket allows public access.
///
/// Checks that every `aws_s3_bucket_public_access_block` has both
/// `block_public_acls` and `block_public_policy` set to `true`.
pub struct NoPublicS3;

impl Invariant for NoPublicS3 {
    fn name(&self) -> &str { "no_public_s3" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(blocks) = tf_json.pointer("/resource/aws_s3_bucket_public_access_block") {
            if let Some(blocks_map) = blocks.as_object() {
                for (name, block) in blocks_map {
                    let block_acls = block.get("block_public_acls")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let block_policy = block.get("block_public_policy")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    if !block_acls {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_s3_bucket_public_access_block".into(),
                            resource_name: name.clone(),
                            message: "block_public_acls is not true".into(),
                        });
                    }
                    if !block_policy {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_s3_bucket_public_access_block".into(),
                            resource_name: name.clone(),
                            message: "block_public_policy is not true".into(),
                        });
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// No IAM policy has `Action: "*"` AND `Resource: "*"` (overly permissive).
///
/// Checks `aws_iam_policy` and `aws_iam_role_policy` resources, parsing
/// the `policy` field as JSON to inspect statements.
pub struct IamLeastPrivilege;

impl Invariant for IamLeastPrivilege {
    fn name(&self) -> &str { "iam_least_privilege" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        for resource_type in &["aws_iam_policy", "aws_iam_role_policy"] {
            let pointer = format!("/resource/{resource_type}");
            if let Some(policies) = tf_json.pointer(&pointer) {
                if let Some(policies_map) = policies.as_object() {
                    for (name, policy_resource) in policies_map {
                        Self::check_policy_document(
                            &mut violations,
                            self.name(),
                            resource_type,
                            name,
                            policy_resource,
                        );
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

impl IamLeastPrivilege {
    fn check_policy_document(
        violations: &mut Vec<Violation>,
        invariant_name: &str,
        resource_type: &str,
        resource_name: &str,
        resource: &Value,
    ) {
        let policy_str = resource.get("policy").and_then(Value::as_str).unwrap_or("");
        let policy_json: Result<Value, _> = serde_json::from_str(policy_str);

        if let Ok(doc) = policy_json {
            let statements = match doc.get("Statement") {
                Some(Value::Array(arr)) => arr.clone(),
                Some(stmt) => vec![stmt.clone()],
                None => vec![],
            };

            for stmt in &statements {
                let has_star_action = Self::value_contains_star(stmt.get("Action"));
                let has_star_resource = Self::value_contains_star(stmt.get("Resource"));

                if has_star_action && has_star_resource {
                    violations.push(Violation {
                        invariant: invariant_name.into(),
                        resource_type: resource_type.into(),
                        resource_name: resource_name.into(),
                        message: "IAM policy has Action: \"*\" and Resource: \"*\"".into(),
                    });
                }
            }
        }
    }

    fn value_contains_star(val: Option<&Value>) -> bool {
        match val {
            Some(Value::String(s)) => s == "*",
            Some(Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some("*")),
            _ => false,
        }
    }
}

/// No resource references the default VPC.
///
/// Checks that no resource has `vpc_id` set to `"default"`.
pub struct NoDefaultVpcUsage;

impl Invariant for NoDefaultVpcUsage {
    fn name(&self) -> &str { "no_default_vpc_usage" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(resources) = tf_json.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in resources {
                if let Some(instances_map) = instances.as_object() {
                    for (name, config) in instances_map {
                        if config.get("vpc_id").and_then(Value::as_str) == Some("default") {
                            violations.push(Violation {
                                invariant: self.name().into(),
                                resource_type: resource_type.clone(),
                                resource_name: name.clone(),
                                message: "Resource uses the default VPC (vpc_id: \"default\")".into(),
                            });
                        }
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All subnets are private unless explicitly tagged as public.
///
/// Checks that no `aws_subnet` has `map_public_ip_on_launch: true`
/// unless it has a tag `Tier: public`.
pub struct AllSubnetsPrivate;

impl Invariant for AllSubnetsPrivate {
    fn name(&self) -> &str { "all_subnets_private" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(subnets) = tf_json.pointer("/resource/aws_subnet") {
            if let Some(subnets_map) = subnets.as_object() {
                for (name, subnet) in subnets_map {
                    let maps_public = subnet.get("map_public_ip_on_launch")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);

                    if maps_public {
                        let has_public_tag = subnet
                            .pointer("/tags/Tier")
                            .and_then(Value::as_str)
                            == Some("public");

                        if !has_public_tag {
                            violations.push(Violation {
                                invariant: self.name().into(),
                                resource_type: "aws_subnet".into(),
                                resource_name: name.clone(),
                                message: "Subnet maps public IPs without Tier: public tag".into(),
                            });
                        }
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All databases and DynamoDB tables have encryption at rest enabled.
///
/// Checks:
/// - `aws_db_instance` has `storage_encrypted: true`
/// - `aws_dynamodb_table` has `server_side_encryption.enabled: true`
pub struct EncryptionAtRest;

impl Invariant for EncryptionAtRest {
    fn name(&self) -> &str { "encryption_at_rest" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        // Check RDS instances
        if let Some(dbs) = tf_json.pointer("/resource/aws_db_instance") {
            if let Some(dbs_map) = dbs.as_object() {
                for (name, db) in dbs_map {
                    let encrypted = db.get("storage_encrypted")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !encrypted {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_db_instance".into(),
                            resource_name: name.clone(),
                            message: "RDS instance does not have storage_encrypted: true".into(),
                        });
                    }
                }
            }
        }

        // Check DynamoDB tables
        if let Some(tables) = tf_json.pointer("/resource/aws_dynamodb_table") {
            if let Some(tables_map) = tables.as_object() {
                for (name, table) in tables_map {
                    let sse_enabled = table
                        .pointer("/server_side_encryption/enabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !sse_enabled {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_dynamodb_table".into(),
                            resource_name: name.clone(),
                            message: "DynamoDB table does not have server_side_encryption enabled".into(),
                        });
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All load balancers have access logging enabled.
///
/// Checks that every `aws_lb` has an `access_logs` block with `enabled: true`.
pub struct LoggingEnabled;

impl Invariant for LoggingEnabled {
    fn name(&self) -> &str { "logging_enabled" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(lbs) = tf_json.pointer("/resource/aws_lb") {
            if let Some(lbs_map) = lbs.as_object() {
                for (name, lb) in lbs_map {
                    let logging_enabled = lb
                        .pointer("/access_logs/enabled")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !logging_enabled {
                        violations.push(Violation {
                            invariant: self.name().into(),
                            resource_type: "aws_lb".into(),
                            resource_name: name.clone(),
                            message: "Load balancer does not have access_logs enabled".into(),
                        });
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All resources have required tags: `ManagedBy` and `Purpose`.
///
/// Checks every resource across all types for the presence of both tag keys.
pub struct TaggingComplete;

impl Invariant for TaggingComplete {
    fn name(&self) -> &str { "tagging_complete" }

    fn check(&self, tf_json: &Value) -> Result<(), Vec<Violation>> {
        let mut violations = Vec::new();

        if let Some(resources) = tf_json.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in resources {
                if let Some(instances_map) = instances.as_object() {
                    for (name, config) in instances_map {
                        let tags = config.get("tags").and_then(Value::as_object);
                        let has_managed_by = tags
                            .and_then(|t| t.get("ManagedBy"))
                            .is_some();
                        let has_purpose = tags
                            .and_then(|t| t.get("Purpose"))
                            .is_some();

                        if !has_managed_by || !has_purpose {
                            let mut missing = Vec::new();
                            if !has_managed_by { missing.push("ManagedBy"); }
                            if !has_purpose { missing.push("Purpose"); }
                            violations.push(Violation {
                                invariant: self.name().into(),
                                resource_type: resource_type.clone(),
                                resource_name: name.clone(),
                                message: format!("Missing required tags: {}", missing.join(", ")),
                            });
                        }
                    }
                }
            }
        }

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }
}

/// All invariants bundled together.
pub fn all_invariants() -> Vec<Box<dyn Invariant>> {
    vec![
        Box::new(NoPublicSsh),
        Box::new(AllEbsEncrypted),
        Box::new(ImdsV2Required),
        Box::new(NoPublicS3),
        Box::new(IamLeastPrivilege),
        Box::new(NoDefaultVpcUsage),
        Box::new(AllSubnetsPrivate),
        Box::new(EncryptionAtRest),
        Box::new(LoggingEnabled),
        Box::new(TaggingComplete),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_public_ssh_passes_on_restricted_rule() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["10.0.0.0/8"]
                    }
                }
            }
        });
        assert!(NoPublicSsh.check(&tf).is_ok());
    }

    #[test]
    fn no_public_ssh_fails_on_open_rule() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "bad_ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        });
        let result = NoPublicSsh.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn no_public_ssh_ignores_egress() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "egress": {
                        "type": "egress",
                        "from_port": 0,
                        "to_port": 65535,
                        "protocol": "-1",
                        "cidr_blocks": ["0.0.0.0/0"]
                    }
                }
            }
        });
        assert!(NoPublicSsh.check(&tf).is_ok());
    }

    #[test]
    fn ebs_encrypted_passes() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "builder": {
                        "block_device_mappings": [{
                            "ebs": { "encrypted": true, "volume_size": 100 }
                        }]
                    }
                }
            }
        });
        assert!(AllEbsEncrypted.check(&tf).is_ok());
    }

    #[test]
    fn ebs_encrypted_fails_unencrypted() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "bad": {
                        "block_device_mappings": [{
                            "ebs": { "encrypted": false, "volume_size": 100 }
                        }]
                    }
                }
            }
        });
        assert!(AllEbsEncrypted.check(&tf).is_err());
    }

    #[test]
    fn imdsv2_required_passes() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "good": {
                        "metadata_options": { "http_tokens": "required" }
                    }
                }
            }
        });
        assert!(ImdsV2Required.check(&tf).is_ok());
    }

    #[test]
    fn imdsv2_required_fails_optional() {
        let tf = json!({
            "resource": {
                "aws_launch_template": {
                    "bad": {
                        "metadata_options": { "http_tokens": "optional" }
                    }
                }
            }
        });
        assert!(ImdsV2Required.check(&tf).is_err());
    }

    #[test]
    fn check_all_passes_clean_config() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"],
                        "tags": { "ManagedBy": "pangea", "Purpose": "access" }
                    }
                },
                "aws_launch_template": {
                    "lt": {
                        "metadata_options": { "http_tokens": "required" },
                        "block_device_mappings": [{ "ebs": { "encrypted": true } }],
                        "tags": { "ManagedBy": "pangea", "Purpose": "compute" }
                    }
                }
            }
        });
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        assert!(check_all(&inv_refs, &tf).is_ok());
    }

    #[test]
    fn check_all_catches_multiple_violations() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "bad_ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["0.0.0.0/0"],
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                },
                "aws_launch_template": {
                    "bad_lt": {
                        "metadata_options": { "http_tokens": "optional" },
                        "block_device_mappings": [{ "ebs": { "encrypted": false } }],
                        "tags": { "ManagedBy": "pangea", "Purpose": "test" }
                    }
                }
            }
        });
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        let result = check_all(&inv_refs, &tf);
        assert!(result.is_err());
        // SSH + EBS + IMDSv2 = 3 violations
        // (TaggingComplete passes because both resources have required tags)
        assert_eq!(result.unwrap_err().len(), 3);
    }

    #[test]
    fn empty_terraform_json_passes_all() {
        let tf = json!({});
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        assert!(check_all(&inv_refs, &tf).is_ok());
    }

    // ── NoPublicS3 tests ────────────────────────────────────────

    #[test]
    fn no_public_s3_passes_when_blocked() {
        let tf = json!({
            "resource": {
                "aws_s3_bucket_public_access_block": {
                    "bucket": {
                        "block_public_acls": true,
                        "block_public_policy": true
                    }
                }
            }
        });
        assert!(NoPublicS3.check(&tf).is_ok());
    }

    #[test]
    fn no_public_s3_fails_when_acls_unblocked() {
        let tf = json!({
            "resource": {
                "aws_s3_bucket_public_access_block": {
                    "bad_bucket": {
                        "block_public_acls": false,
                        "block_public_policy": true
                    }
                }
            }
        });
        let result = NoPublicS3.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn no_public_s3_fails_when_both_unblocked() {
        let tf = json!({
            "resource": {
                "aws_s3_bucket_public_access_block": {
                    "wide_open": {
                        "block_public_acls": false,
                        "block_public_policy": false
                    }
                }
            }
        });
        let result = NoPublicS3.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 2);
    }

    // ── IamLeastPrivilege tests ─────────────────────────────────

    #[test]
    fn iam_least_privilege_passes_scoped_policy() {
        let tf = json!({
            "resource": {
                "aws_iam_policy": {
                    "good": {
                        "policy": "{\"Statement\":[{\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::my-bucket/*\"}]}"
                    }
                }
            }
        });
        assert!(IamLeastPrivilege.check(&tf).is_ok());
    }

    #[test]
    fn iam_least_privilege_fails_star_star() {
        let tf = json!({
            "resource": {
                "aws_iam_policy": {
                    "admin": {
                        "policy": "{\"Statement\":[{\"Action\":\"*\",\"Resource\":\"*\"}]}"
                    }
                }
            }
        });
        let result = IamLeastPrivilege.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn iam_least_privilege_fails_star_in_array() {
        let tf = json!({
            "resource": {
                "aws_iam_role_policy": {
                    "bad_role": {
                        "policy": "{\"Statement\":[{\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}"
                    }
                }
            }
        });
        let result = IamLeastPrivilege.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    // ── NoDefaultVpcUsage tests ─────────────────────────────────

    #[test]
    fn no_default_vpc_passes_custom_vpc() {
        let tf = json!({
            "resource": {
                "aws_instance": {
                    "server": {
                        "vpc_id": "vpc-123abc"
                    }
                }
            }
        });
        assert!(NoDefaultVpcUsage.check(&tf).is_ok());
    }

    #[test]
    fn no_default_vpc_fails_default_reference() {
        let tf = json!({
            "resource": {
                "aws_instance": {
                    "bad_server": {
                        "vpc_id": "default"
                    }
                }
            }
        });
        let result = NoDefaultVpcUsage.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    // ── AllSubnetsPrivate tests ─────────────────────────────────

    #[test]
    fn all_subnets_private_passes_private_subnet() {
        let tf = json!({
            "resource": {
                "aws_subnet": {
                    "private": {
                        "map_public_ip_on_launch": false
                    }
                }
            }
        });
        assert!(AllSubnetsPrivate.check(&tf).is_ok());
    }

    #[test]
    fn all_subnets_private_passes_public_with_tag() {
        let tf = json!({
            "resource": {
                "aws_subnet": {
                    "public_tagged": {
                        "map_public_ip_on_launch": true,
                        "tags": { "Tier": "public" }
                    }
                }
            }
        });
        assert!(AllSubnetsPrivate.check(&tf).is_ok());
    }

    #[test]
    fn all_subnets_private_fails_public_without_tag() {
        let tf = json!({
            "resource": {
                "aws_subnet": {
                    "bad_subnet": {
                        "map_public_ip_on_launch": true
                    }
                }
            }
        });
        let result = AllSubnetsPrivate.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    // ── EncryptionAtRest tests ──────────────────────────────────

    #[test]
    fn encryption_at_rest_passes_encrypted_rds() {
        let tf = json!({
            "resource": {
                "aws_db_instance": {
                    "db": {
                        "storage_encrypted": true
                    }
                }
            }
        });
        assert!(EncryptionAtRest.check(&tf).is_ok());
    }

    #[test]
    fn encryption_at_rest_fails_unencrypted_rds() {
        let tf = json!({
            "resource": {
                "aws_db_instance": {
                    "bad_db": {
                        "storage_encrypted": false
                    }
                }
            }
        });
        let result = EncryptionAtRest.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn encryption_at_rest_passes_encrypted_dynamodb() {
        let tf = json!({
            "resource": {
                "aws_dynamodb_table": {
                    "table": {
                        "server_side_encryption": { "enabled": true }
                    }
                }
            }
        });
        assert!(EncryptionAtRest.check(&tf).is_ok());
    }

    #[test]
    fn encryption_at_rest_fails_unencrypted_dynamodb() {
        let tf = json!({
            "resource": {
                "aws_dynamodb_table": {
                    "bad_table": {
                        "server_side_encryption": { "enabled": false }
                    }
                }
            }
        });
        let result = EncryptionAtRest.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    // ── LoggingEnabled tests ────────────────────────────────────

    #[test]
    fn logging_enabled_passes_with_access_logs() {
        let tf = json!({
            "resource": {
                "aws_lb": {
                    "nlb": {
                        "access_logs": { "enabled": true, "bucket": "logs-bucket" }
                    }
                }
            }
        });
        assert!(LoggingEnabled.check(&tf).is_ok());
    }

    #[test]
    fn logging_enabled_fails_without_access_logs() {
        let tf = json!({
            "resource": {
                "aws_lb": {
                    "bad_lb": {
                        "name": "my-lb"
                    }
                }
            }
        });
        let result = LoggingEnabled.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    #[test]
    fn logging_enabled_fails_disabled_access_logs() {
        let tf = json!({
            "resource": {
                "aws_lb": {
                    "bad_lb": {
                        "access_logs": { "enabled": false }
                    }
                }
            }
        });
        let result = LoggingEnabled.check(&tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 1);
    }

    // ── TaggingComplete tests ───────────────────────────────────

    #[test]
    fn tagging_complete_passes_fully_tagged() {
        let tf = json!({
            "resource": {
                "aws_vpc": {
                    "main": {
                        "cidr_block": "10.0.0.0/16",
                        "tags": { "ManagedBy": "pangea", "Purpose": "network" }
                    }
                }
            }
        });
        assert!(TaggingComplete.check(&tf).is_ok());
    }

    #[test]
    fn tagging_complete_fails_missing_managed_by() {
        let tf = json!({
            "resource": {
                "aws_vpc": {
                    "bad": {
                        "cidr_block": "10.0.0.0/16",
                        "tags": { "Purpose": "network" }
                    }
                }
            }
        });
        let result = TaggingComplete.check(&tf);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("ManagedBy"));
    }

    #[test]
    fn tagging_complete_fails_no_tags() {
        let tf = json!({
            "resource": {
                "aws_vpc": {
                    "untagged": {
                        "cidr_block": "10.0.0.0/16"
                    }
                }
            }
        });
        let result = TaggingComplete.check(&tf);
        assert!(result.is_err());
        let violations = result.unwrap_err();
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("ManagedBy"));
        assert!(violations[0].message.contains("Purpose"));
    }

    // ── Integration: all 10 invariants catch violations ─────────

    #[test]
    fn all_ten_invariants_registered() {
        let invs = all_invariants();
        assert_eq!(invs.len(), 10);
    }

    #[test]
    fn check_all_passes_fully_compliant_config() {
        let tf = json!({
            "resource": {
                "aws_security_group_rule": {
                    "ssh": {
                        "type": "ingress",
                        "from_port": 22,
                        "to_port": 22,
                        "cidr_blocks": ["10.0.0.0/8"],
                        "tags": { "ManagedBy": "pangea", "Purpose": "access" }
                    }
                },
                "aws_launch_template": {
                    "lt": {
                        "metadata_options": { "http_tokens": "required" },
                        "block_device_mappings": [{ "ebs": { "encrypted": true } }],
                        "tags": { "ManagedBy": "pangea", "Purpose": "compute" }
                    }
                },
                "aws_s3_bucket_public_access_block": {
                    "bucket": {
                        "block_public_acls": true,
                        "block_public_policy": true,
                        "tags": { "ManagedBy": "pangea", "Purpose": "storage" }
                    }
                },
                "aws_subnet": {
                    "private": {
                        "map_public_ip_on_launch": false,
                        "tags": { "ManagedBy": "pangea", "Purpose": "network" }
                    }
                },
                "aws_db_instance": {
                    "db": {
                        "storage_encrypted": true,
                        "tags": { "ManagedBy": "pangea", "Purpose": "data" }
                    }
                },
                "aws_dynamodb_table": {
                    "table": {
                        "server_side_encryption": { "enabled": true },
                        "tags": { "ManagedBy": "pangea", "Purpose": "data" }
                    }
                },
                "aws_lb": {
                    "nlb": {
                        "access_logs": { "enabled": true, "bucket": "logs" },
                        "tags": { "ManagedBy": "pangea", "Purpose": "routing" }
                    }
                }
            }
        });
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        assert!(check_all(&inv_refs, &tf).is_ok());
    }
}
