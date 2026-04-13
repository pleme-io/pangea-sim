//! Architecture simulation modules.
//!
//! Each module defines a config struct, a proptest strategy, and a `simulate()`
//! function that produces compliant Terraform JSON. Every simulation guarantees:
//!
//! - All resources have `ManagedBy` + `Purpose` tags (`TaggingComplete`)
//! - No SG rule uses `0.0.0.0/0` on SSH (`NoPublicSsh`)
//! - All launch templates use encrypted EBS + IMDSv2 (`AllEbsEncrypted`, `ImdsV2Required`)
//! - No IAM policy has `Action: *` + `Resource: *` (`IamLeastPrivilege`)
//! - All S3 public access blocks are enabled (`NoPublicS3`)
//! - All RDS instances have `storage_encrypted: true` (`EncryptionAtRest`)
//! - All load balancers have access logging enabled (`LoggingEnabled`)

pub mod config;

pub mod secure_vpc;
pub mod tiered_subnets;
pub mod nat_gateway;
pub mod dns_zone;
pub mod bastion_host;
pub mod k3s_dev_cluster;
pub mod k3s_cluster_iam;
pub mod nix_builder_fleet;
pub mod ingress_alb;
pub mod encrypted_storage;
pub mod monitoring_stack;
pub mod waf_shield;
pub mod backup_vault;
pub mod vpc_endpoints;
pub mod secrets_manager;
pub mod cloudtrail;
pub mod rds_cluster;
pub mod wireguard_vpn;
pub mod ecr_registry;
pub mod config_recorder;
pub mod composed;
pub mod helm_chart;
