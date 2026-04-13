//! WireGuard VPN simulation — VPN endpoint with encrypted launch template.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a WireGuard VPN endpoint.
#[derive(Debug, Clone)]
pub struct WireguardVpnConfig {
    pub name: String,
    pub cidr: String,
    pub instance_type: String,
    pub ami_id: String,
    pub wg_port: u16,
}

/// Proptest strategy for `WireguardVpnConfig`.
pub fn arb_config() -> impl Strategy<Value = WireguardVpnConfig> {
    (
        arb_name(),
        arb_cidr(),
        arb_instance_type(),
        arb_ami_id(),
        Just(51822u16),
    )
        .prop_map(
            |(name, cidr, instance_type, ami_id, wg_port)| WireguardVpnConfig {
                name,
                cidr,
                instance_type,
                ami_id,
                wg_port,
            },
        )
}

/// Simulate a WireGuard VPN and return Terraform JSON.
#[must_use]
pub fn simulate(c: &WireguardVpnConfig) -> Value {
    let tags = required_tags();
    let sg_key = format!("{}-wg-sg", c.name);
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");

    json!({
        "resource": {
            "aws_security_group": {
                &sg_key: {
                    "name": &sg_key,
                    "vpc_id": format!("${{aws_vpc.{}-vpc.id}}", c.name),
                    "tags": tags
                }
            },
            "aws_security_group_rule": {
                format!("{}-wg-in", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": c.wg_port,
                    "to_port": c.wg_port,
                    "protocol": "udp",
                    "cidr_blocks": [c.cidr.clone()],
                    "tags": tags
                }
            },
            "aws_launch_template": {
                format!("{}-wg-lt", c.name): {
                    "name": format!("{}-wg-lt", c.name),
                    "image_id": c.ami_id.clone(),
                    "instance_type": c.instance_type.clone(),
                    "vpc_security_group_ids": [&sg_ref],
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": {
                            "encrypted": true,
                            "volume_size": 20,
                            "volume_type": "gp3"
                        }
                    }],
                    "metadata_options": {
                        "http_tokens": "required",
                        "http_endpoint": "enabled"
                    },
                    "tags": tags
                }
            },
            "aws_eip": {
                format!("{}-wg-eip", c.name): {
                    "domain": "vpc",
                    "tags": tags
                }
            }
        }
    })
}
