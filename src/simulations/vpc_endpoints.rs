//! VPC endpoints simulation — interface and gateway endpoints for AWS services.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for VPC endpoints.
#[derive(Debug, Clone)]
pub struct VpcEndpointsConfig {
    pub name: String,
    pub enable_s3_gateway: bool,
    pub enable_ssm: bool,
    pub enable_ecr: bool,
}

/// Proptest strategy for `VpcEndpointsConfig`.
pub fn arb_config() -> impl Strategy<Value = VpcEndpointsConfig> {
    (arb_name(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
        |(name, enable_s3_gateway, enable_ssm, enable_ecr)| VpcEndpointsConfig {
            name,
            enable_s3_gateway,
            enable_ssm,
            enable_ecr,
        },
    )
}

/// Simulate VPC endpoints and return Terraform JSON.
#[must_use]
pub fn simulate(c: &VpcEndpointsConfig) -> Value {
    let tags = required_tags();
    let vpc_ref = format!("${{aws_vpc.{}-vpc.id}}", c.name);
    let mut endpoints = serde_json::Map::new();

    if c.enable_s3_gateway {
        endpoints.insert(
            format!("{}-s3-gw", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "service_name": "com.amazonaws.us-east-1.s3",
                "vpc_endpoint_type": "Gateway",
                "tags": tags
            }),
        );
    }

    if c.enable_ssm {
        endpoints.insert(
            format!("{}-ssm", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "service_name": "com.amazonaws.us-east-1.ssm",
                "vpc_endpoint_type": "Interface",
                "private_dns_enabled": true,
                "tags": tags
            }),
        );
    }

    if c.enable_ecr {
        endpoints.insert(
            format!("{}-ecr-api", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "service_name": "com.amazonaws.us-east-1.ecr.api",
                "vpc_endpoint_type": "Interface",
                "private_dns_enabled": true,
                "tags": tags
            }),
        );
        endpoints.insert(
            format!("{}-ecr-dkr", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "service_name": "com.amazonaws.us-east-1.ecr.dkr",
                "vpc_endpoint_type": "Interface",
                "private_dns_enabled": true,
                "tags": tags
            }),
        );
    }

    // Ensure at least one endpoint exists
    if endpoints.is_empty() {
        endpoints.insert(
            format!("{}-s3-gw", c.name),
            json!({
                "vpc_id": &vpc_ref,
                "service_name": "com.amazonaws.us-east-1.s3",
                "vpc_endpoint_type": "Gateway",
                "tags": tags
            }),
        );
    }

    json!({
        "resource": {
            "aws_vpc_endpoint": endpoints
        }
    })
}
