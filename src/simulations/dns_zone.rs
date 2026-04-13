//! DNS zone simulation — Route53 hosted zone + records.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a DNS zone.
#[derive(Debug, Clone)]
pub struct DnsZoneConfig {
    pub name: String,
    pub domain: String,
    pub private_zone: bool,
}

/// Proptest strategy for `DnsZoneConfig`.
pub fn arb_config() -> impl Strategy<Value = DnsZoneConfig> {
    (arb_name(), arb_domain(), any::<bool>()).prop_map(|(name, domain, private_zone)| {
        DnsZoneConfig {
            name,
            domain,
            private_zone,
        }
    })
}

/// Simulate a DNS zone and return Terraform JSON.
#[must_use]
pub fn simulate(c: &DnsZoneConfig) -> Value {
    let tags = required_tags();
    let zone_key = format!("{}-zone", c.name);

    json!({
        "resource": {
            "aws_route53_zone": {
                &zone_key: {
                    "name": c.domain.clone(),
                    "tags": tags
                }
            },
            "aws_route53_record": {
                format!("{}-ns", c.name): {
                    "zone_id": format!("${{aws_route53_zone.{zone_key}.zone_id}}"),
                    "name": c.domain.clone(),
                    "type": "NS",
                    "ttl": 300,
                    "tags": tags
                }
            }
        }
    })
}
