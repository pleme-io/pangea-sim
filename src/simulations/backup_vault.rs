//! Backup vault simulation — AWS Backup vault + plan + selection.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a backup vault.
#[derive(Debug, Clone)]
pub struct BackupVaultConfig {
    pub name: String,
    pub retention_days: i64,
    pub schedule: String,
}

/// Proptest strategy for `BackupVaultConfig`.
pub fn arb_config() -> impl Strategy<Value = BackupVaultConfig> {
    (
        arb_name(),
        prop_oneof![Just(7_i64), Just(14), Just(30), Just(90)],
        prop_oneof![
            Just("cron(0 12 * * ? *)".into()),
            Just("cron(0 0 * * ? *)".into()),
        ],
    )
        .prop_map(|(name, retention_days, schedule)| BackupVaultConfig {
            name,
            retention_days,
            schedule,
        })
}

/// Simulate a backup vault and return Terraform JSON.
#[must_use]
pub fn simulate(c: &BackupVaultConfig) -> Value {
    let tags = required_tags();
    let vault_key = format!("{}-vault", c.name);

    json!({
        "resource": {
            "aws_backup_vault": {
                &vault_key: {
                    "name": &vault_key,
                    "tags": tags
                }
            },
            "aws_backup_plan": {
                format!("{}-plan", c.name): {
                    "name": format!("{}-plan", c.name),
                    "rule": {
                        "rule_name": format!("{}-daily", c.name),
                        "target_vault_name": format!("${{aws_backup_vault.{vault_key}.name}}"),
                        "schedule": c.schedule.clone(),
                        "lifecycle": {
                            "delete_after": c.retention_days
                        }
                    },
                    "tags": tags
                }
            }
        }
    })
}
