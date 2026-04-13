//! Encrypted storage simulation — KMS key + alias + S3 bucket with encryption.
//!
//! Produces KMS + S3 resources with encryption-at-rest and public access blocked.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for encrypted storage.
#[derive(Debug, Clone)]
pub struct EncryptedStorageConfig {
    pub name: String,
    pub profile: Profile,
    pub key_rotation: bool,
    pub bucket_versioning: bool,
}

/// Proptest strategy for `EncryptedStorageConfig`.
pub fn arb_config() -> impl Strategy<Value = EncryptedStorageConfig> {
    (arb_name(), arb_profile(), any::<bool>(), any::<bool>()).prop_map(
        |(name, profile, key_rotation, bucket_versioning)| EncryptedStorageConfig {
            name,
            profile,
            key_rotation,
            bucket_versioning,
        },
    )
}

/// Simulate encrypted storage and return Terraform JSON.
#[must_use]
pub fn simulate(c: &EncryptedStorageConfig) -> Value {
    let tags = required_tags();
    let kms_key_name = format!("{}-kms", c.name);

    json!({
        "resource": {
            "aws_kms_key": {
                &kms_key_name: {
                    "description": format!("Encryption key for {}", c.name),
                    "enable_key_rotation": c.key_rotation,
                    "deletion_window_in_days": 30,
                    "tags": tags
                }
            },
            "aws_kms_alias": {
                format!("{}-kms-alias", c.name): {
                    "name": format!("alias/{}", c.name),
                    "target_key_id": format!("${{aws_kms_key.{kms_key_name}.key_id}}"),
                    "tags": tags
                }
            },
            "aws_s3_bucket": {
                format!("{}-bucket", c.name): {
                    "bucket": format!("{}-storage", c.name),
                    "tags": tags
                }
            },
            "aws_s3_bucket_server_side_encryption_configuration": {
                format!("{}-bucket-enc", c.name): {
                    "bucket": format!("${{aws_s3_bucket.{}-bucket.id}}", c.name),
                    "rule": {
                        "apply_server_side_encryption_by_default": {
                            "sse_algorithm": "aws:kms",
                            "kms_master_key_id": format!("${{aws_kms_key.{kms_key_name}.arn}}")
                        }
                    },
                    "tags": tags
                }
            },
            "aws_s3_bucket_public_access_block": {
                format!("{}-bucket-pab", c.name): {
                    "bucket": format!("${{aws_s3_bucket.{}-bucket.id}}", c.name),
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
