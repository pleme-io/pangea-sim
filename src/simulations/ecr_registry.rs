//! ECR registry simulation — container registry with scanning + lifecycle.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for ECR registries.
#[derive(Debug, Clone)]
pub struct EcrRegistryConfig {
    pub name: String,
    pub repo_count: usize,
    pub scan_on_push: bool,
}

/// Proptest strategy for `EcrRegistryConfig`.
pub fn arb_config() -> impl Strategy<Value = EcrRegistryConfig> {
    (arb_name(), 1..=5_usize, any::<bool>()).prop_map(|(name, repo_count, scan_on_push)| {
        EcrRegistryConfig {
            name,
            repo_count,
            scan_on_push,
        }
    })
}

/// Simulate ECR registries and return Terraform JSON.
#[must_use]
pub fn simulate(c: &EcrRegistryConfig) -> Value {
    let tags = required_tags();
    let mut repos = serde_json::Map::new();
    let mut policies = serde_json::Map::new();

    for i in 0..c.repo_count {
        let repo_key = format!("{}-repo-{i}", c.name);
        repos.insert(
            repo_key.clone(),
            json!({
                "name": format!("{}/service-{i}", c.name),
                "image_scanning_configuration": {
                    "scan_on_push": c.scan_on_push
                },
                "encryption_configuration": {
                    "encryption_type": "KMS"
                },
                "image_tag_mutability": "IMMUTABLE",
                "tags": tags
            }),
        );

        policies.insert(
            format!("{}-lifecycle-{i}", c.name),
            json!({
                "repository": format!("${{aws_ecr_repository.{repo_key}.name}}"),
                "policy": serde_json::to_string(&json!({
                    "rules": [{
                        "rulePriority": 1,
                        "description": "Keep last 30 images",
                        "selection": {
                            "tagStatus": "any",
                            "countType": "imageCountMoreThan",
                            "countNumber": 30
                        },
                        "action": {
                            "type": "expire"
                        }
                    }]
                })).unwrap(),
                "tags": tags
            }),
        );
    }

    json!({
        "resource": {
            "aws_ecr_repository": repos,
            "aws_ecr_lifecycle_policy": policies
        }
    })
}
