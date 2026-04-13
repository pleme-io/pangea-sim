//! WAF shield simulation — WAFv2 web ACL with managed rule groups.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a WAF shield.
#[derive(Debug, Clone)]
pub struct WafShieldConfig {
    pub name: String,
    pub rate_limit: i64,
}

/// Proptest strategy for `WafShieldConfig`.
pub fn arb_config() -> impl Strategy<Value = WafShieldConfig> {
    (arb_name(), prop_oneof![Just(100_i64), Just(500), Just(1000), Just(2000)]).prop_map(
        |(name, rate_limit)| WafShieldConfig { name, rate_limit },
    )
}

/// Simulate a WAF shield and return Terraform JSON.
#[must_use]
pub fn simulate(c: &WafShieldConfig) -> Value {
    let tags = required_tags();

    json!({
        "resource": {
            "aws_wafv2_web_acl": {
                format!("{}-waf", c.name): {
                    "name": format!("{}-waf", c.name),
                    "scope": "REGIONAL",
                    "default_action": { "allow": {} },
                    "rule": [{
                        "name": "rate-limit",
                        "priority": 1,
                        "action": { "block": {} },
                        "statement": {
                            "rate_based_statement": {
                                "limit": c.rate_limit,
                                "aggregate_key_type": "IP"
                            }
                        },
                        "visibility_config": {
                            "sampled_requests_enabled": true,
                            "cloudwatch_metrics_enabled": true,
                            "metric_name": format!("{}-rate-limit", c.name)
                        }
                    }],
                    "visibility_config": {
                        "sampled_requests_enabled": true,
                        "cloudwatch_metrics_enabled": true,
                        "metric_name": format!("{}-waf", c.name)
                    },
                    "tags": tags
                }
            }
        }
    })
}
