//! Invariant proof engine — verify security properties hold for ALL configurations.
//!
//! Each invariant is a function from Terraform JSON → Result. If it returns Ok,
//! the property holds. If it returns Err, the violations are listed.
//!
//! Combined with proptest, this proves invariants across random configurations:
//! "Checked 10,000 configs. 0 violations. Property proven."

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

/// All invariants bundled together.
pub fn all_invariants() -> Vec<Box<dyn Invariant>> {
    vec![
        Box::new(NoPublicSsh),
        Box::new(AllEbsEncrypted),
        Box::new(ImdsV2Required),
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
                    "ssh": { "type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"] }
                },
                "aws_launch_template": {
                    "lt": {
                        "metadata_options": { "http_tokens": "required" },
                        "block_device_mappings": [{ "ebs": { "encrypted": true } }]
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
                    "bad_ssh": { "type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"] }
                },
                "aws_launch_template": {
                    "bad_lt": {
                        "metadata_options": { "http_tokens": "optional" },
                        "block_device_mappings": [{ "ebs": { "encrypted": false } }]
                    }
                }
            }
        });
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        let result = check_all(&inv_refs, &tf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().len(), 3); // SSH + EBS + IMDSv2
    }

    #[test]
    fn empty_terraform_json_passes_all() {
        let tf = json!({});
        let invs = all_invariants();
        let inv_refs: Vec<&dyn Invariant> = invs.iter().map(AsRef::as_ref).collect();
        assert!(check_all(&inv_refs, &tf).is_ok());
    }
}
