//! Ingress ALB simulation — ALB + security group + ACM certificate + listeners.
//!
//! Application load balancer with HTTPS, access logging, and VPC-only security rules.

use proptest::prelude::*;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for an ingress ALB.
#[derive(Debug, Clone)]
pub struct IngressAlbConfig {
    pub name: String,
    pub cidr: String,
    pub domain: String,
    pub profile: Profile,
    pub enable_waf: bool,
}

/// Proptest strategy for `IngressAlbConfig`.
pub fn arb_config() -> impl Strategy<Value = IngressAlbConfig> {
    (arb_name(), arb_cidr(), arb_domain(), arb_profile(), any::<bool>()).prop_map(
        |(name, cidr, domain, profile, enable_waf)| IngressAlbConfig {
            name,
            cidr,
            domain,
            profile,
            enable_waf,
        },
    )
}

/// Simulate an ingress ALB and return Terraform JSON.
#[must_use]
pub fn simulate(c: &IngressAlbConfig) -> Value {
    let tags = required_tags();
    let alb_key = format!("{}-alb", c.name);
    let sg_key = format!("{}-alb-sg", c.name);
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");
    let alb_ref = format!("${{aws_lb.{alb_key}.arn}}");
    let cert_key = format!("{}-cert", c.name);
    let tg_key = format!("{}-tg", c.name);

    let mut resources = json!({
        "aws_security_group": {
            &sg_key: {
                "name": &sg_key,
                "vpc_id": format!("${{aws_vpc.{}-vpc.id}}", c.name),
                "tags": tags
            }
        },
        "aws_security_group_rule": {
            format!("{}-https-in", c.name): {
                "security_group_id": &sg_ref,
                "type": "ingress",
                "from_port": 443,
                "to_port": 443,
                "protocol": "tcp",
                "cidr_blocks": [c.cidr.clone()],
                "tags": tags
            },
            format!("{}-http-in", c.name): {
                "security_group_id": &sg_ref,
                "type": "ingress",
                "from_port": 80,
                "to_port": 80,
                "protocol": "tcp",
                "cidr_blocks": [c.cidr.clone()],
                "tags": tags
            }
        },
        "aws_acm_certificate": {
            &cert_key: {
                "domain_name": c.domain.clone(),
                "validation_method": "DNS",
                "tags": tags
            }
        },
        "aws_lb": {
            &alb_key: {
                "name": &alb_key,
                "internal": false,
                "load_balancer_type": "application",
                "security_groups": [&sg_ref],
                "access_logs": {
                    "enabled": true,
                    "bucket": format!("{}-alb-logs", c.name)
                },
                "tags": tags
            }
        },
        "aws_lb_target_group": {
            &tg_key: {
                "name": &tg_key,
                "port": 80,
                "protocol": "HTTP",
                "vpc_id": format!("${{aws_vpc.{}-vpc.id}}", c.name),
                "health_check": {
                    "path": "/health",
                    "protocol": "HTTP"
                },
                "tags": tags
            }
        },
        "aws_lb_listener": {
            format!("{}-https-listener", c.name): {
                "load_balancer_arn": &alb_ref,
                "port": 443,
                "protocol": "HTTPS",
                "certificate_arn": format!("${{aws_acm_certificate.{cert_key}.arn}}"),
                "default_action": {
                    "type": "forward",
                    "target_group_arn": format!("${{aws_lb_target_group.{tg_key}.arn}}")
                },
                "tags": tags
            },
            format!("{}-http-redirect", c.name): {
                "load_balancer_arn": &alb_ref,
                "port": 80,
                "protocol": "HTTP",
                "default_action": {
                    "type": "redirect",
                    "redirect": {
                        "port": "443",
                        "protocol": "HTTPS",
                        "status_code": "HTTP_301"
                    }
                },
                "tags": tags
            }
        }
    });

    if c.enable_waf {
        let res = resources.as_object_mut().unwrap();
        res.insert(
            "aws_wafv2_web_acl_association".to_string(),
            json!({
                format!("{}-waf-assoc", c.name): {
                    "resource_arn": &alb_ref,
                    "web_acl_arn": format!("${{aws_wafv2_web_acl.{}-waf.arn}}", c.name),
                    "tags": tags
                }
            }),
        );
    }

    json!({ "resource": resources })
}
