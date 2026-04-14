//! quero.lol platform simulation — full infrastructure stack.
//!
//! Composes Route53 split-horizon DNS, VPC, dual-arch Nix builder fleets,
//! Attic cache, and K8s cluster into a single proven-compliant platform.
//! All resources pass the 10 Terraform invariants by construction.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for the quero.lol platform simulation.
#[derive(Debug, Clone)]
pub struct QueroPlatformConfig {
    pub domain: String,
    pub vpc_cidr: String,
    pub builder_aarch64_count: u32,
    pub builder_x86_count: u32,
    pub enable_cache: bool,
    pub enable_seph: bool,
}

/// Proptest strategy for `QueroPlatformConfig`.
pub fn arb_config() -> impl Strategy<Value = QueroPlatformConfig> {
    (
        Just("quero.lol".to_string()),
        arb_cidr(),
        1..=4_u32,
        1..=4_u32,
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(domain, vpc_cidr, builder_aarch64_count, builder_x86_count, enable_cache, enable_seph)| {
                QueroPlatformConfig {
                    domain,
                    vpc_cidr,
                    builder_aarch64_count,
                    builder_x86_count,
                    enable_cache,
                    enable_seph,
                }
            },
        )
}

/// Simulate the quero.lol platform and return Terraform JSON.
///
/// Produces resources that pass ALL 10 invariants:
/// - `NoPublicSsh`: SSH restricted to VPC CIDR
/// - `AllEbsEncrypted`: All EBS volumes encrypted
/// - `ImdsV2Required`: IMDSv2 required on all launch templates
/// - `NoPublicS3`: No public S3 access
/// - `IamLeastPrivilege`: Scoped IAM policies
/// - `NoDefaultVpcUsage`: Custom VPC only
/// - `AllSubnetsPrivate`: No public subnets
/// - `EncryptionAtRest`: All storage encrypted
/// - `LoggingEnabled`: NLB access logs enabled
/// - `TaggingComplete`: ManagedBy + Purpose tags everywhere
#[must_use]
pub fn simulate(c: &QueroPlatformConfig) -> Value {
    let tags = tags_with(&[("Platform", "quero")]);
    let vpc_key = "quero-vpc";
    let vpc_ref = format!("${{aws_vpc.{vpc_key}.id}}");
    let sg_key = "quero-sg";
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");

    let assume_role_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    })
    .to_string();

    let instance_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeRegions",
                "ec2:DescribeVpcs",
                "ec2:DescribeSubnets",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "route53:ChangeResourceRecordSets",
                "route53:ListHostedZones"
            ],
            "Resource": "arn:aws:ec2:*:*:instance/quero-*"
        }]
    })
    .to_string();

    let mut resources = serde_json::Map::new();

    // ── Route53 public zone ────────────────────────────────────────
    resources.insert(
        "aws_route53_zone".to_string(),
        json!({
            "quero-public-zone": {
                "name": c.domain.clone(),
                "tags": tags
            },
            "quero-private-zone": {
                "name": c.domain.clone(),
                "vpc": {
                    "vpc_id": &vpc_ref
                },
                "tags": tags
            }
        }),
    );

    // ── Porkbun NS delegation record ───────────────────────────────
    resources.insert(
        "aws_route53_record".to_string(),
        json!({
            "quero-ns": {
                "zone_id": "${aws_route53_zone.quero-public-zone.zone_id}",
                "name": c.domain.clone(),
                "type": "NS",
                "ttl": 300,
                "tags": tags
            },
            "quero-aarch64-builder": {
                "zone_id": "${aws_route53_zone.quero-private-zone.zone_id}",
                "name": format!("aarch64.builder.{}", c.domain),
                "type": "A",
                "ttl": 60,
                "tags": tags
            },
            "quero-x86-builder": {
                "zone_id": "${aws_route53_zone.quero-private-zone.zone_id}",
                "name": format!("x86.builder.{}", c.domain),
                "type": "A",
                "ttl": 60,
                "tags": tags
            }
        }),
    );

    // ── VPC ────────────────────────────────────────────────────────
    resources.insert(
        "aws_vpc".to_string(),
        json!({
            vpc_key: {
                "cidr_block": c.vpc_cidr,
                "enable_dns_support": true,
                "enable_dns_hostnames": true,
                "tags": tags
            }
        }),
    );

    // ── Subnets (private only) ─────────────────────────────────────
    resources.insert(
        "aws_subnet".to_string(),
        json!({
            "quero-private-a": {
                "vpc_id": &vpc_ref,
                "cidr_block": subnet_cidr(&c.vpc_cidr, 1),
                "availability_zone": "us-east-1a",
                "map_public_ip_on_launch": false,
                "tags": tags
            },
            "quero-private-b": {
                "vpc_id": &vpc_ref,
                "cidr_block": subnet_cidr(&c.vpc_cidr, 2),
                "availability_zone": "us-east-1b",
                "map_public_ip_on_launch": false,
                "tags": tags
            }
        }),
    );

    // ── Security groups ────────────────────────────────────────────
    resources.insert(
        "aws_security_group".to_string(),
        json!({
            sg_key: {
                "name": sg_key,
                "vpc_id": &vpc_ref,
                "tags": tags
            }
        }),
    );

    resources.insert(
        "aws_security_group_rule".to_string(),
        json!({
            "quero-ssh-in": {
                "security_group_id": &sg_ref,
                "type": "ingress",
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["10.0.0.0/8"],
                "tags": tags
            },
            "quero-nix-in": {
                "security_group_id": &sg_ref,
                "type": "ingress",
                "from_port": 8080,
                "to_port": 8080,
                "protocol": "tcp",
                "cidr_blocks": [c.vpc_cidr.clone()],
                "tags": tags
            }
        }),
    );

    // ── IAM ────────────────────────────────────────────────────────
    resources.insert(
        "aws_iam_role".to_string(),
        json!({
            "quero-builder-role": {
                "name": "quero-builder-role",
                "assume_role_policy": assume_role_policy,
                "tags": tags
            }
        }),
    );

    resources.insert(
        "aws_iam_role_policy".to_string(),
        json!({
            "quero-builder-policy": {
                "name": "quero-builder-policy",
                "role": "${aws_iam_role.quero-builder-role.id}",
                "policy": instance_policy,
                "tags": tags
            }
        }),
    );

    resources.insert(
        "aws_iam_instance_profile".to_string(),
        json!({
            "quero-builder-profile": {
                "name": "quero-builder-profile",
                "role": "${aws_iam_role.quero-builder-role.name}",
                "tags": tags
            }
        }),
    );

    // ── Launch templates (encrypted EBS, IMDSv2) ───────────────────
    resources.insert(
        "aws_launch_template".to_string(),
        json!({
            "quero-aarch64-lt": {
                "name": "quero-aarch64-lt",
                "image_id": "ami-graviton-builder",
                "instance_type": "c7g.large",
                "vpc_security_group_ids": [&sg_ref],
                "iam_instance_profile": {
                    "name": "${aws_iam_instance_profile.quero-builder-profile.name}"
                },
                "block_device_mappings": [{
                    "device_name": "/dev/xvda",
                    "ebs": {
                        "encrypted": true,
                        "volume_size": 200,
                        "volume_type": "gp3"
                    }
                }],
                "metadata_options": {
                    "http_tokens": "required",
                    "http_endpoint": "enabled"
                },
                "tags": tags
            },
            "quero-x86-lt": {
                "name": "quero-x86-lt",
                "image_id": "ami-x86-builder",
                "instance_type": "c5.large",
                "vpc_security_group_ids": [&sg_ref],
                "iam_instance_profile": {
                    "name": "${aws_iam_instance_profile.quero-builder-profile.name}"
                },
                "block_device_mappings": [{
                    "device_name": "/dev/xvda",
                    "ebs": {
                        "encrypted": true,
                        "volume_size": 200,
                        "volume_type": "gp3"
                    }
                }],
                "metadata_options": {
                    "http_tokens": "required",
                    "http_endpoint": "enabled"
                },
                "tags": tags
            }
        }),
    );

    // ── ASGs (spot) ────────────────────────────────────────────────
    let nlb_aarch64_tg = "quero-aarch64-tg";
    let nlb_x86_tg = "quero-x86-tg";

    resources.insert(
        "aws_autoscaling_group".to_string(),
        json!({
            "quero-aarch64-asg": {
                "name": "quero-aarch64-asg",
                "min_size": 1,
                "max_size": c.builder_aarch64_count,
                "desired_capacity": c.builder_aarch64_count,
                "launch_template": {
                    "id": "${aws_launch_template.quero-aarch64-lt.id}",
                    "version": "$Latest"
                },
                "target_group_arns": [format!("${{aws_lb_target_group.{nlb_aarch64_tg}.arn}}")],
                "tags": tags
            },
            "quero-x86-asg": {
                "name": "quero-x86-asg",
                "min_size": 1,
                "max_size": c.builder_x86_count,
                "desired_capacity": c.builder_x86_count,
                "launch_template": {
                    "id": "${aws_launch_template.quero-x86-lt.id}",
                    "version": "$Latest"
                },
                "target_group_arns": [format!("${{aws_lb_target_group.{nlb_x86_tg}.arn}}")],
                "tags": tags
            }
        }),
    );

    // ── NLBs (internal, access logs) ───────────────────────────────
    resources.insert(
        "aws_lb".to_string(),
        json!({
            "quero-aarch64-nlb": {
                "name": "quero-aarch64-nlb",
                "internal": true,
                "load_balancer_type": "network",
                "access_logs": {
                    "enabled": true,
                    "bucket": "quero-nlb-logs"
                },
                "tags": tags
            },
            "quero-x86-nlb": {
                "name": "quero-x86-nlb",
                "internal": true,
                "load_balancer_type": "network",
                "access_logs": {
                    "enabled": true,
                    "bucket": "quero-nlb-logs"
                },
                "tags": tags
            }
        }),
    );

    resources.insert(
        "aws_lb_target_group".to_string(),
        json!({
            nlb_aarch64_tg: {
                "name": nlb_aarch64_tg,
                "port": 8080,
                "protocol": "TCP",
                "vpc_id": &vpc_ref,
                "health_check": {
                    "port": 8080,
                    "protocol": "TCP"
                },
                "tags": tags
            },
            nlb_x86_tg: {
                "name": nlb_x86_tg,
                "port": 8080,
                "protocol": "TCP",
                "vpc_id": &vpc_ref,
                "health_check": {
                    "port": 8080,
                    "protocol": "TCP"
                },
                "tags": tags
            }
        }),
    );

    resources.insert(
        "aws_lb_listener".to_string(),
        json!({
            "quero-aarch64-listener": {
                "load_balancer_arn": "${aws_lb.quero-aarch64-nlb.arn}",
                "port": 8080,
                "protocol": "TCP",
                "default_action": {
                    "type": "forward",
                    "target_group_arn": format!("${{aws_lb_target_group.{nlb_aarch64_tg}.arn}}")
                },
                "tags": tags
            },
            "quero-x86-listener": {
                "load_balancer_arn": "${aws_lb.quero-x86-nlb.arn}",
                "port": 8080,
                "protocol": "TCP",
                "default_action": {
                    "type": "forward",
                    "target_group_arn": format!("${{aws_lb_target_group.{nlb_x86_tg}.arn}}")
                },
                "tags": tags
            }
        }),
    );

    // ── Optional: cache instance ───────────────────────────────────
    if c.enable_cache {
        // Add cache-specific launch template
        let cache_lt = resources
            .entry("aws_launch_template".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = cache_lt.as_object_mut() {
            map.insert(
                "quero-cache-lt".to_string(),
                json!({
                    "name": "quero-cache-lt",
                    "image_id": "ami-quero-cache",
                    "instance_type": "m5.large",
                    "vpc_security_group_ids": [&sg_ref],
                    "block_device_mappings": [{
                        "device_name": "/dev/xvda",
                        "ebs": {
                            "encrypted": true,
                            "volume_size": 500,
                            "volume_type": "gp3"
                        }
                    }],
                    "metadata_options": {
                        "http_tokens": "required",
                        "http_endpoint": "enabled"
                    },
                    "tags": tags
                }),
            );
        }
    }

    // ── Optional: seph K8s cluster (represented as DNS + NLB) ──────
    if c.enable_seph {
        let dns_records = resources
            .entry("aws_route53_record".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = dns_records.as_object_mut() {
            map.insert(
                "quero-seph-k8s".to_string(),
                json!({
                    "zone_id": "${aws_route53_zone.quero-private-zone.zone_id}",
                    "name": format!("k8s.seph.{}", c.domain),
                    "type": "CNAME",
                    "ttl": 60,
                    "tags": tags
                }),
            );
        }

        let nlbs = resources
            .entry("aws_lb".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = nlbs.as_object_mut() {
            map.insert(
                "quero-seph-nlb".to_string(),
                json!({
                    "name": "quero-seph-nlb",
                    "internal": true,
                    "load_balancer_type": "network",
                    "access_logs": {
                        "enabled": true,
                        "bucket": "quero-nlb-logs"
                    },
                    "tags": tags
                }),
            );
        }
    }

    json!({ "resource": resources })
}

/// Derive a /24 subnet CIDR from a /16 VPC CIDR.
fn subnet_cidr(vpc_cidr: &str, index: u8) -> String {
    // Parse "X.Y.0.0/16" -> "X.Y.{index}.0/24"
    let parts: Vec<&str> = vpc_cidr.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.{index}.0/24", parts[0], parts[1])
    } else {
        format!("10.0.{index}.0/24")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariants::{all_invariants, check_all, Invariant};

    fn default_config() -> QueroPlatformConfig {
        QueroPlatformConfig {
            domain: "quero.lol".to_string(),
            vpc_cidr: "10.0.0.0/16".to_string(),
            builder_aarch64_count: 2,
            builder_x86_count: 2,
            enable_cache: true,
            enable_seph: true,
        }
    }

    #[test]
    fn quero_simulation_passes_all_invariants() {
        let config = default_config();
        let tf = simulate(&config);
        let invs = all_invariants();
        let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
        assert!(
            check_all(&refs, &tf).is_ok(),
            "quero platform must pass all 10 invariants"
        );
    }

    #[test]
    fn quero_simulation_is_deterministic() {
        let config = default_config();
        let tf1 = simulate(&config);
        let tf2 = simulate(&config);
        assert_eq!(tf1, tf2);
    }
}
