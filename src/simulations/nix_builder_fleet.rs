//! Nix builder fleet simulation — composes VPC + launch template + ASG + NLB + SG.
//!
//! Fleet of Nix build nodes behind a network load balancer with encrypted EBS
//! and IMDSv2 required.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a Nix builder fleet.
#[derive(Debug, Clone)]
pub struct NixBuilderFleetConfig {
    pub name: String,
    pub cidr: String,
    pub azs: Vec<String>,
    pub profile: Profile,
    pub instance_type: String,
    pub ami_id: String,
    pub volume_size: i64,
    pub fleet_size_min: i64,
    pub fleet_size_max: i64,
    pub nix_port: u16,
}

/// Proptest strategy for `NixBuilderFleetConfig`.
pub fn arb_config() -> impl Strategy<Value = NixBuilderFleetConfig> {
    (
        arb_name(),
        arb_cidr(),
        arb_azs(),
        arb_profile(),
        arb_instance_type(),
        arb_ami_id(),
        arb_volume_size(),
        1..=2_i64,
        2..=8_i64,
        prop_oneof![Just(22u16), Just(8080)],
    )
        .prop_map(
            |(name, cidr, azs, profile, instance_type, ami_id, volume_size, min, max, nix_port)| {
                NixBuilderFleetConfig {
                    name,
                    cidr,
                    azs,
                    profile,
                    instance_type,
                    ami_id,
                    volume_size,
                    fleet_size_min: min,
                    fleet_size_max: max.max(min),
                    nix_port,
                }
            },
        )
}

/// Simulate a Nix builder fleet and return Terraform JSON.
#[must_use]
pub fn simulate(c: &NixBuilderFleetConfig) -> Value {
    let tags = required_tags();
    let vpc_key = format!("{}-vpc", c.name);
    let vpc_ref = format!("${{aws_vpc.{vpc_key}.id}}");
    let sg_key = format!("{}-sg", c.name);
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");
    let lt_key = format!("{}-lt", c.name);
    let nlb_key = format!("{}-nlb", c.name);
    let tg_key = format!("{}-tg", c.name);

    json!({
        "resource": {
            "aws_vpc": {
                &vpc_key: {
                    "cidr_block": c.cidr,
                    "enable_dns_support": true,
                    "enable_dns_hostnames": true,
                    "tags": tags
                }
            },
            "aws_security_group": {
                &sg_key: {
                    "name": &sg_key,
                    "vpc_id": &vpc_ref,
                    "tags": tags
                }
            },
            "aws_security_group_rule": {
                format!("{}-nix-in", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": c.nix_port,
                    "to_port": c.nix_port,
                    "protocol": "tcp",
                    "cidr_blocks": [c.cidr.clone()],
                    "tags": tags
                },
                format!("{}-ssh-in", c.name): {
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
                &lt_key: {
                    "name": &lt_key,
                    "image_id": c.ami_id.clone(),
                    "instance_type": c.instance_type.clone(),
                    "vpc_security_group_ids": [&sg_ref],
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": {
                            "encrypted": true,
                            "volume_size": c.volume_size,
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
            "aws_autoscaling_group": {
                format!("{}-asg", c.name): {
                    "name": format!("{}-asg", c.name),
                    "min_size": c.fleet_size_min,
                    "max_size": c.fleet_size_max,
                    "desired_capacity": c.fleet_size_min,
                    "launch_template": {
                        "id": format!("${{aws_launch_template.{lt_key}.id}}"),
                        "version": "$Latest"
                    },
                    "target_group_arns": [format!("${{aws_lb_target_group.{tg_key}.arn}}")],
                    "tags": tags
                }
            },
            "aws_lb": {
                &nlb_key: {
                    "name": &nlb_key,
                    "internal": true,
                    "load_balancer_type": "network",
                    "access_logs": {
                        "enabled": true,
                        "bucket": format!("{}-nlb-logs", c.name)
                    },
                    "tags": tags
                }
            },
            "aws_lb_target_group": {
                &tg_key: {
                    "name": &tg_key,
                    "port": c.nix_port,
                    "protocol": "TCP",
                    "vpc_id": &vpc_ref,
                    "health_check": {
                        "port": c.nix_port,
                        "protocol": "TCP"
                    },
                    "tags": tags
                }
            },
            "aws_lb_listener": {
                format!("{}-listener", c.name): {
                    "load_balancer_arn": format!("${{aws_lb.{nlb_key}.arn}}"),
                    "port": c.nix_port,
                    "protocol": "TCP",
                    "default_action": {
                        "type": "forward",
                        "target_group_arn": format!("${{aws_lb_target_group.{tg_key}.arn}}")
                    },
                    "tags": tags
                }
            }
        }
    })
}
