//! AWS Config recorder simulation — configuration compliance recording.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for AWS Config recorder.
#[derive(Debug, Clone)]
pub struct ConfigRecorderConfig {
    pub name: String,
    pub all_resources: bool,
}

/// Proptest strategy for `ConfigRecorderConfig`.
pub fn arb_config() -> impl Strategy<Value = ConfigRecorderConfig> {
    (arb_name(), any::<bool>()).prop_map(|(name, all_resources)| ConfigRecorderConfig {
        name,
        all_resources,
    })
}

/// Simulate AWS Config recorder and return Terraform JSON.
#[must_use]
pub fn simulate(c: &ConfigRecorderConfig) -> Value {
    let tags = required_tags();
    let role_name = format!("{}-config-role", c.name);

    let assume_role_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    });

    let config_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "config:Put*",
                "config:Get*",
                "config:List*",
                "config:Describe*",
                "s3:PutObject",
                "s3:GetBucketAcl"
            ],
            "Resource": format!("arn:aws:s3:::{}-config-bucket/*", c.name)
        }]
    });

    json!({
        "resource": {
            "aws_config_configuration_recorder": {
                format!("{}-recorder", c.name): {
                    "name": format!("{}-recorder", c.name),
                    "role_arn": format!("${{aws_iam_role.{role_name}.arn}}"),
                    "recording_group": {
                        "all_supported": c.all_resources
                    },
                    "tags": tags
                }
            },
            "aws_config_delivery_channel": {
                format!("{}-channel", c.name): {
                    "name": format!("{}-channel", c.name),
                    "s3_bucket_name": format!("${{aws_s3_bucket.{}-config-bucket.id}}", c.name),
                    "tags": tags
                }
            },
            "aws_iam_role": {
                &role_name: {
                    "name": &role_name,
                    "assume_role_policy": serde_json::to_string(&assume_role_policy).unwrap(),
                    "tags": tags
                }
            },
            "aws_iam_role_policy": {
                format!("{}-config-policy", c.name): {
                    "name": format!("{}-config-policy", c.name),
                    "role": format!("${{aws_iam_role.{role_name}.id}}"),
                    "policy": serde_json::to_string(&config_policy).unwrap(),
                    "tags": tags
                }
            }
        }
    })
}
