//! Secure VPC simulation — VPC + IGW + SG + SG rules + default SG lockdown.
//!
//! Produces 5+ resource types with zero-trust defaults:
//! - VPC with DNS support
//! - Default security group stripped of all rules
//! - Internet gateway
//! - Custom security group
//! - SSH rule restricted to VPC CIDR only (never 0.0.0.0/0)

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a secure VPC simulation.
#[derive(Debug, Clone)]
pub struct SecureVpcConfig {
    pub name: String,
    pub cidr: String,
    pub azs: Vec<String>,
    pub profile: Profile,
    pub flow_logs: bool,
}

/// Proptest strategy for `SecureVpcConfig`.
pub fn arb_config() -> impl Strategy<Value = SecureVpcConfig> {
    (arb_name(), arb_cidr(), arb_azs(), arb_profile(), any::<bool>()).prop_map(
        |(name, cidr, azs, profile, flow_logs)| SecureVpcConfig {
            name,
            cidr,
            azs,
            profile,
            flow_logs,
        },
    )
}

/// Simulate a secure VPC and return Terraform JSON.
#[must_use]
pub fn simulate(c: &SecureVpcConfig) -> Value {
    let tags = required_tags();
    let vpc_key = format!("{}-vpc", c.name);
    let vpc_ref = format!("${{aws_vpc.{vpc_key}.id}}");

    let mut resources = json!({
        "aws_vpc": {
            &vpc_key: {
                "cidr_block": c.cidr,
                "enable_dns_support": true,
                "enable_dns_hostnames": true,
                "tags": tags
            }
        },
        "aws_default_security_group": {
            format!("{}-default-sg", c.name): {
                "vpc_id": &vpc_ref,
                "tags": tags
            }
        },
        "aws_internet_gateway": {
            format!("{}-igw", c.name): {
                "vpc_id": &vpc_ref,
                "tags": tags
            }
        },
        "aws_security_group": {
            format!("{}-sg", c.name): {
                "name": format!("{}-sg", c.name),
                "vpc_id": &vpc_ref,
                "tags": tags
            }
        },
        "aws_security_group_rule": {
            format!("{}-ssh-in", c.name): {
                "security_group_id": format!("${{aws_security_group.{}-sg.id}}", c.name),
                "type": "ingress",
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": [c.cidr.clone()],
                "tags": tags
            }
        }
    });

    if c.flow_logs {
        let res = resources.as_object_mut().unwrap();
        res.insert(
            "aws_flow_log".to_string(),
            json!({
                format!("{}-flow-log", c.name): {
                    "vpc_id": &vpc_ref,
                    "traffic_type": "ALL",
                    "log_destination_type": "cloud-watch-logs",
                    "tags": tags
                }
            }),
        );
        res.insert(
            "aws_cloudwatch_log_group".to_string(),
            json!({
                format!("{}-flow-log-group", c.name): {
                    "name": format!("/aws/vpc/{}/flow-logs", c.name),
                    "retention_in_days": 90,
                    "tags": tags
                }
            }),
        );
    }

    json!({ "resource": resources })
}
