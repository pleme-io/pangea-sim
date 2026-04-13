//! Tiered subnets simulation — public/private/data subnet tiers across AZs.
//!
//! Creates subnets tagged by tier. Public subnets get map_public_ip_on_launch
//! with the required Tier: public tag. Private and data subnets never map public IPs.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for tiered subnets.
#[derive(Debug, Clone)]
pub struct TieredSubnetsConfig {
    pub name: String,
    pub cidr: String,
    pub azs: Vec<String>,
    pub include_data_tier: bool,
}

/// Proptest strategy for `TieredSubnetsConfig`.
pub fn arb_config() -> impl Strategy<Value = TieredSubnetsConfig> {
    (arb_name(), arb_cidr(), arb_azs(), any::<bool>()).prop_map(
        |(name, cidr, azs, include_data_tier)| TieredSubnetsConfig {
            name,
            cidr,
            azs,
            include_data_tier,
        },
    )
}

/// Simulate tiered subnets and return Terraform JSON.
#[must_use]
pub fn simulate(c: &TieredSubnetsConfig) -> Value {
    let tags = required_tags();
    let vpc_ref = format!("${{aws_vpc.{}-vpc.id}}", c.name);

    let mut subnets = serde_json::Map::new();
    let mut route_tables = serde_json::Map::new();

    for (i, az) in c.azs.iter().enumerate() {
        let pub_tags = tags_with(&[("Tier", "public"), ("AZ", az)]);
        subnets.insert(
            format!("{}-public-{i}", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "cidr_block": format!("10.0.{}.0/24", i),
                "availability_zone": az,
                "map_public_ip_on_launch": true,
                "tags": pub_tags
            }),
        );

        let priv_tags = tags_with(&[("Tier", "private"), ("AZ", az)]);
        subnets.insert(
            format!("{}-private-{i}", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "cidr_block": format!("10.0.{}.0/24", 10 + i),
                "availability_zone": az,
                "map_public_ip_on_launch": false,
                "tags": priv_tags
            }),
        );

        route_tables.insert(
            format!("{}-private-rt-{i}", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "tags": tags
            }),
        );

        if c.include_data_tier {
            let data_tags = tags_with(&[("Tier", "data"), ("AZ", az)]);
            subnets.insert(
                format!("{}-data-{i}", c.name),
                json!({
                    "vpc_id": &vpc_ref,
                    "cidr_block": format!("10.0.{}.0/24", 20 + i),
                    "availability_zone": az,
                    "map_public_ip_on_launch": false,
                    "tags": data_tags
                }),
            );
        }
    }

    json!({
        "resource": {
            "aws_subnet": subnets,
            "aws_route_table": route_tables
        }
    })
}
