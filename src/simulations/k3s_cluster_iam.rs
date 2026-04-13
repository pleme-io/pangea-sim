//! K3s cluster IAM simulation — IAM roles + instance profiles + policies.
//!
//! Produces IAM resources with least-privilege policies (never Action: * + Resource: *).

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for K3s IAM resources.
#[derive(Debug, Clone)]
pub struct K3sClusterIamConfig {
    pub name: String,
    pub profile: Profile,
    pub enable_ssm: bool,
    pub enable_ecr: bool,
}

/// Proptest strategy for `K3sClusterIamConfig`.
pub fn arb_config() -> impl Strategy<Value = K3sClusterIamConfig> {
    (arb_name(), arb_profile(), any::<bool>(), any::<bool>()).prop_map(
        |(name, profile, enable_ssm, enable_ecr)| K3sClusterIamConfig {
            name,
            profile,
            enable_ssm,
            enable_ecr,
        },
    )
}

/// Simulate K3s IAM and return Terraform JSON.
#[must_use]
pub fn simulate(c: &K3sClusterIamConfig) -> Value {
    let tags = required_tags();
    let role_name = format!("{}-k3s-role", c.name);

    let assume_role_policy = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    });

    let mut policy_statements = vec![
        json!({
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
        }),
        json!({
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeListeners"
            ],
            "Resource": format!("arn:aws:elasticloadbalancing:*:*:loadbalancer/{}-*", c.name)
        }),
    ];

    if c.enable_ssm {
        policy_statements.push(json!({
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeAssociation",
                "ssm:GetDeployablePatchSnapshotForInstance",
                "ssm:GetDocument",
                "ssm:DescribeDocument",
                "ssm:GetManifest",
                "ssm:ListAssociations",
                "ssm:ListInstanceAssociations",
                "ssm:PutInventory",
                "ssm:UpdateAssociationStatus",
                "ssm:UpdateInstanceAssociationStatus",
                "ssm:UpdateInstanceInformation"
            ],
            "Resource": format!("arn:aws:ssm:*:*:document/{}-*", c.name)
        }));
    }

    if c.enable_ecr {
        policy_statements.push(json!({
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            "Resource": format!("arn:aws:ecr:*:*:repository/{}-*", c.name)
        }));
    }

    let node_policy = json!({
        "Version": "2012-10-17",
        "Statement": policy_statements
    });

    json!({
        "resource": {
            "aws_iam_role": {
                &role_name: {
                    "name": &role_name,
                    "assume_role_policy": serde_json::to_string(&assume_role_policy).unwrap(),
                    "tags": tags
                }
            },
            "aws_iam_instance_profile": {
                format!("{}-k3s-profile", c.name): {
                    "name": format!("{}-k3s-profile", c.name),
                    "role": format!("${{aws_iam_role.{role_name}.name}}"),
                    "tags": tags
                }
            },
            "aws_iam_role_policy": {
                format!("{}-k3s-policy", c.name): {
                    "name": format!("{}-k3s-policy", c.name),
                    "role": format!("${{aws_iam_role.{role_name}.id}}"),
                    "policy": serde_json::to_string(&node_policy).unwrap(),
                    "tags": tags
                }
            }
        }
    })
}
