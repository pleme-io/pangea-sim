//! CloudTrail simulation — audit trail with S3 + KMS encryption.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for CloudTrail.
#[derive(Debug, Clone)]
pub struct CloudTrailConfig {
    pub name: String,
    pub multi_region: bool,
    pub enable_log_validation: bool,
}

/// Proptest strategy for `CloudTrailConfig`.
pub fn arb_config() -> impl Strategy<Value = CloudTrailConfig> {
    (arb_name(), any::<bool>(), any::<bool>()).prop_map(
        |(name, multi_region, enable_log_validation)| CloudTrailConfig {
            name,
            multi_region,
            enable_log_validation,
        },
    )
}

/// Simulate CloudTrail and return Terraform JSON.
#[must_use]
pub fn simulate(c: &CloudTrailConfig) -> Value {
    let tags = required_tags();

    json!({
        "resource": {
            "aws_cloudtrail": {
                format!("{}-trail", c.name): {
                    "name": format!("{}-trail", c.name),
                    "s3_bucket_name": format!("${{aws_s3_bucket.{}-trail-bucket.id}}", c.name),
                    "is_multi_region_trail": c.multi_region,
                    "enable_log_file_validation": c.enable_log_validation,
                    "kms_key_id": format!("${{aws_kms_key.{}-kms.arn}}", c.name),
                    "tags": tags
                }
            },
            "aws_s3_bucket": {
                format!("{}-trail-bucket", c.name): {
                    "bucket": format!("{}-cloudtrail-logs", c.name),
                    "tags": tags
                }
            },
            "aws_s3_bucket_public_access_block": {
                format!("{}-trail-pab", c.name): {
                    "bucket": format!("${{aws_s3_bucket.{}-trail-bucket.id}}", c.name),
                    "block_public_acls": true,
                    "block_public_policy": true,
                    "ignore_public_acls": true,
                    "restrict_public_buckets": true,
                    "tags": tags
                }
            }
        }
    })
}
