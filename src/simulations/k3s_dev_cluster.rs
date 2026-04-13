//! K3s dev cluster simulation — composes VPC + launch template + ASG + SG + IAM.
//!
//! Full cluster simulation with encrypted EBS, IMDSv2, and VPC-only SSH.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for a K3s dev cluster.
#[derive(Debug, Clone)]
pub struct K3sDevClusterConfig {
    pub name: String,
    pub cidr: String,
    pub azs: Vec<String>,
    pub profile: Profile,
    pub instance_type: String,
    pub ami_id: String,
    pub volume_size: i64,
    pub node_count_min: i64,
    pub node_count_max: i64,
}

/// Proptest strategy for `K3sDevClusterConfig`.
pub fn arb_config() -> impl Strategy<Value = K3sDevClusterConfig> {
    (
        arb_name(),
        arb_cidr(),
        arb_azs(),
        arb_profile(),
        arb_instance_type(),
        arb_ami_id(),
        arb_volume_size(),
        1..=3_i64,
        3..=10_i64,
    )
        .prop_map(
            |(name, cidr, azs, profile, instance_type, ami_id, volume_size, min, max)| {
                K3sDevClusterConfig {
                    name,
                    cidr,
                    azs,
                    profile,
                    instance_type,
                    ami_id,
                    volume_size,
                    node_count_min: min,
                    node_count_max: max.max(min),
                }
            },
        )
}

/// Simulate a K3s dev cluster and return Terraform JSON.
#[must_use]
pub fn simulate(c: &K3sDevClusterConfig) -> Value {
    let tags = required_tags();
    let vpc_key = format!("{}-vpc", c.name);
    let vpc_ref = format!("${{aws_vpc.{vpc_key}.id}}");
    let sg_key = format!("{}-sg", c.name);
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");
    let lt_key = format!("{}-lt", c.name);
    let role_name = format!("{}-k3s-role", c.name);

    let assume_role_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    });

    let node_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVolumes",
                "ec2:CreateTags",
                "ec2:DescribeVpcs"
            ],
            "Resource": format!("arn:aws:ec2:*:*:instance/{}-*", c.name)
        }]
    });

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
                format!("{}-ssh-in", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": [c.cidr.clone()],
                    "tags": tags
                },
                format!("{}-k3s-api", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": 6443,
                    "to_port": 6443,
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
                    "iam_instance_profile": {
                        "name": format!("${{aws_iam_instance_profile.{}-profile.name}}", c.name)
                    },
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
                    "min_size": c.node_count_min,
                    "max_size": c.node_count_max,
                    "desired_capacity": c.node_count_min,
                    "launch_template": {
                        "id": format!("${{aws_launch_template.{lt_key}.id}}"),
                        "version": "$Latest"
                    },
                    "vpc_zone_identifier": c.azs.iter().enumerate().map(|(i, _)| {
                        format!("${{aws_subnet.{}-private-{i}.id}}", c.name)
                    }).collect::<Vec<_>>(),
                    "tags": tags
                }
            },
            "aws_iam_role": {
                &role_name: {
                    "name": &role_name,
                    "assume_role_policy": serde_json::to_string(&assume_role_policy).unwrap(),
                    "tags": tags
                }
            },
            "aws_iam_instance_profile": {
                format!("{}-profile", c.name): {
                    "name": format!("{}-profile", c.name),
                    "role": format!("${{aws_iam_role.{role_name}.name}}"),
                    "tags": tags
                }
            },
            "aws_iam_role_policy": {
                format!("{}-policy", c.name): {
                    "name": format!("{}-policy", c.name),
                    "role": format!("${{aws_iam_role.{role_name}.id}}"),
                    "policy": serde_json::to_string(&node_policy).unwrap(),
                    "tags": tags
                }
            }
        }
    })
}
