//! RDS cluster simulation — encrypted RDS instance + subnet group + parameter group.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;

/// Configuration for an RDS cluster.
#[derive(Debug, Clone)]
pub struct RdsClusterConfig {
    pub name: String,
    pub cidr: String,
    pub engine: String,
    pub instance_class: String,
    pub storage_size: i64,
    pub multi_az: bool,
}

/// Proptest strategy for `RdsClusterConfig`.
pub fn arb_config() -> impl Strategy<Value = RdsClusterConfig> {
    (
        arb_name(),
        arb_cidr(),
        prop_oneof![Just("postgres".into()), Just("mysql".into())],
        prop_oneof![Just("db.t3.medium".into()), Just("db.r5.large".into())],
        20..=500_i64,
        any::<bool>(),
    )
        .prop_map(
            |(name, cidr, engine, instance_class, storage_size, multi_az)| RdsClusterConfig {
                name,
                cidr,
                engine,
                instance_class,
                storage_size,
                multi_az,
            },
        )
}

/// Simulate an RDS cluster and return Terraform JSON.
#[must_use]
pub fn simulate(c: &RdsClusterConfig) -> Value {
    let tags = required_tags();
    let sg_key = format!("{}-rds-sg", c.name);
    let sg_ref = format!("${{aws_security_group.{sg_key}.id}}");

    let db_port: u16 = if c.engine == "postgres" { 5432 } else { 3306 };

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
                format!("{}-rds-in", c.name): {
                    "security_group_id": &sg_ref,
                    "type": "ingress",
                    "from_port": db_port,
                    "to_port": db_port,
                    "protocol": "tcp",
                    "cidr_blocks": [c.cidr.clone()],
                    "tags": tags
                }
            },
            "aws_db_subnet_group": {
                format!("{}-rds-subnets", c.name): {
                    "name": format!("{}-rds-subnets", c.name),
                    "subnet_ids": [
                        format!("${{aws_subnet.{}-data-0.id}}", c.name),
                        format!("${{aws_subnet.{}-data-1.id}}", c.name)
                    ],
                    "tags": tags
                }
            },
            "aws_db_instance": {
                format!("{}-rds", c.name): {
                    "identifier": format!("{}-rds", c.name),
                    "engine": c.engine.clone(),
                    "instance_class": c.instance_class.clone(),
                    "allocated_storage": c.storage_size,
                    "storage_encrypted": true,
                    "kms_key_id": format!("${{aws_kms_key.{}-kms.arn}}", c.name),
                    "multi_az": c.multi_az,
                    "db_subnet_group_name": format!("${{aws_db_subnet_group.{}-rds-subnets.name}}", c.name),
                    "vpc_security_group_ids": [&sg_ref],
                    "tags": tags
                }
            }
        }
    })
}
