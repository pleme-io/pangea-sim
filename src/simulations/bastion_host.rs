//! Bastion host simulation — hardened jump box with encrypted EBS + IMDSv2.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a bastion host.
#[derive(Debug, Clone)]
pub struct BastionHostConfig {
    pub name: String,
    pub cidr: String,
    pub instance_type: String,
    pub ami_id: String,
}

/// Proptest strategy for `BastionHostConfig`.
pub fn arb_config() -> impl Strategy<Value = BastionHostConfig> {
    (arb_name(), arb_cidr(), arb_instance_type(), arb_ami_id()).prop_map(
        |(name, cidr, instance_type, ami_id)| BastionHostConfig {
            name,
            cidr,
            instance_type,
            ami_id,
        },
    )
}

/// Simulate a bastion host and return Terraform JSON.
#[must_use]
pub fn simulate(c: &BastionHostConfig) -> Value {
    let tags = required_tags();
    let sg_key = format!("{}-bastion-sg", c.name);
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
                format!("{}-bastion-ssh", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": [c.cidr.clone()],
                    "tags": tags
                }
            },
            "aws_launch_template": {
                format!("{}-bastion-lt", c.name): {
                    "name": format!("{}-bastion-lt", c.name),
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
            }
        }
    })
}
