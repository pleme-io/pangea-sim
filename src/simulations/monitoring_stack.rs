//! Monitoring stack simulation — CloudWatch log groups + alarms + SNS topics.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a monitoring stack.
#[derive(Debug, Clone)]
pub struct MonitoringStackConfig {
    pub name: String,
    pub retention_days: i64,
    pub enable_alarms: bool,
}

/// Proptest strategy for `MonitoringStackConfig`.

pub fn arb_config() -> impl Strategy<Value = MonitoringStackConfig> {
    (
        arb_name(),
        prop_oneof![Just(7_i64), Just(14), Just(30), Just(90), Just(365)],
        any::<bool>(),
    )
        .prop_map(|(name, retention_days, enable_alarms)| MonitoringStackConfig {
            name,
            retention_days,
            enable_alarms,
        })
}

/// Simulate a monitoring stack and return Terraform JSON.
#[must_use]
pub fn simulate(c: &MonitoringStackConfig) -> Value {
    let tags = required_tags();

    let mut resources = json!({
        "aws_cloudwatch_log_group": {
            format!("{}-logs", c.name): {
                "name": format!("/app/{}", c.name),
                "retention_in_days": c.retention_days,
                "tags": tags
            }
        },
        "aws_sns_topic": {
            format!("{}-alerts", c.name): {
                "name": format!("{}-alerts", c.name),
                "tags": tags
            }
        }
    });

    if c.enable_alarms {
        let res = resources.as_object_mut().unwrap();
        res.insert(
            "aws_cloudwatch_metric_alarm".to_string(),
            json!({
                format!("{}-cpu-alarm", c.name): {
                    "alarm_name": format!("{}-high-cpu", c.name),
                    "comparison_operator": "GreaterThanThreshold",
                    "evaluation_periods": 2,
                    "metric_name": "CPUUtilization",
                    "namespace": "AWS/EC2",
                    "period": 300,
                    "statistic": "Average",
                    "threshold": 80,
                    "alarm_actions": [format!("${{aws_sns_topic.{}-alerts.arn}}", c.name)],
                    "tags": tags
                }
            }),
        );
    }

    json!({ "resource": resources })
}
