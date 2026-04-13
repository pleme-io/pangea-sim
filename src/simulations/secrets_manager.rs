//! Secrets Manager simulation — encrypted secrets with KMS + rotation.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for Secrets Manager resources.
#[derive(Debug, Clone)]
pub struct SecretsManagerConfig {
    pub name: String,
    pub secret_count: usize,
    pub enable_rotation: bool,
}

/// Proptest strategy for `SecretsManagerConfig`.
pub fn arb_config() -> impl Strategy<Value = SecretsManagerConfig> {
    (arb_name(), 1..=5_usize, any::<bool>()).prop_map(|(name, secret_count, enable_rotation)| {
        SecretsManagerConfig {
            name,
            secret_count,
            enable_rotation,
        }
    })
}

/// Simulate Secrets Manager resources and return Terraform JSON.
#[must_use]
pub fn simulate(c: &SecretsManagerConfig) -> Value {
    let tags = required_tags();
    let mut secrets = serde_json::Map::new();

    for i in 0..c.secret_count {
        let secret_key = format!("{}-secret-{i}", c.name);
        secrets.insert(
            secret_key.clone(),
            json!({
                "name": format!("{}/{i}", c.name),
                "kms_key_id": format!("${{aws_kms_key.{}-kms.arn}}", c.name),
                "tags": tags
            }),
        );
    }

    let mut resources = json!({
        "aws_secretsmanager_secret": secrets
    });

    if c.enable_rotation {
        let mut rotations = serde_json::Map::new();
        for i in 0..c.secret_count {
            rotations.insert(
                format!("{}-rotation-{i}", c.name),
                json!({
                    "secret_id": format!("${{aws_secretsmanager_secret.{}-secret-{i}.id}}", c.name),
                    "rotation_lambda_arn": format!("${{aws_lambda_function.{}-rotator.arn}}", c.name),
                    "rotation_rules": {
                        "automatically_after_days": 30
                    },
                    "tags": tags
                }),
            );
        }
        resources.as_object_mut().unwrap().insert(
            "aws_secretsmanager_secret_rotation".to_string(),
            Value::Object(rotations),
        );
    }

    json!({ "resource": resources })
}
