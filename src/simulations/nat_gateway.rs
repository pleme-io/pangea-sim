//! NAT gateway simulation — EIP + NAT gateway per AZ for private subnet egress.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for NAT gateways.
#[derive(Debug, Clone)]
pub struct NatGatewayConfig {
    pub name: String,
    pub azs: Vec<String>,
    pub single_nat: bool,
}

/// Proptest strategy for `NatGatewayConfig`.
pub fn arb_config() -> impl Strategy<Value = NatGatewayConfig> {
    (arb_name(), arb_azs(), any::<bool>()).prop_map(|(name, azs, single_nat)| NatGatewayConfig {
        name,
        azs,
        single_nat,
    })
}

/// Simulate NAT gateways and return Terraform JSON.
#[must_use]
pub fn simulate(c: &NatGatewayConfig) -> Value {
    let tags = required_tags();
    let mut eips = serde_json::Map::new();
    let mut nats = serde_json::Map::new();

    let nat_count = if c.single_nat { 1 } else { c.azs.len() };

    for i in 0..nat_count {
        let eip_key = format!("{}-eip-{i}", c.name);
        let nat_key = format!("{}-nat-{i}", c.name);

        eips.insert(
            eip_key.clone(),
            json!({
                "domain": "vpc",
                "tags": tags
            }),
        );

        nats.insert(
            nat_key,
            json!({
                "allocation_id": format!("${{aws_eip.{eip_key}.id}}"),
                "subnet_id": format!("${{aws_subnet.{}-public-{i}.id}}", c.name),
                "tags": tags
            }),
        );
    }

    json!({
        "resource": {
            "aws_eip": eips,
            "aws_nat_gateway": nats
        }
    })
}
