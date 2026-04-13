//! Composed system simulations — real-world multi-architecture stacks.
//!
//! These simulate COMPLETE infrastructure environments by composing
//! multiple architecture simulations. They prove that composition
//! preserves invariants — the whole is as secure as its parts.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

use super::config::*;
use super::{secure_vpc, k3s_dev_cluster, nix_builder_fleet, ingress_alb, encrypted_storage, monitoring_stack, dns_zone, backup_vault, rds_cluster, wireguard_vpn};

// ── System 1: Production K8s Platform ────────────────────────────
// VPC + K3s cluster + ALB + monitoring + backups + encryption + DNS

/// A complete production Kubernetes platform.
#[derive(Debug, Clone)]
pub struct ProductionK8sPlatform {
    pub name: String,
    pub vpc: secure_vpc::SecureVpcConfig,
    pub cluster: k3s_dev_cluster::K3sDevClusterConfig,
    pub alb: ingress_alb::IngressAlbConfig,
    pub monitoring: monitoring_stack::MonitoringStackConfig,
    pub backup: backup_vault::BackupVaultConfig,
    pub encryption: encrypted_storage::EncryptedStorageConfig,
    pub dns: dns_zone::DnsZoneConfig,
}

pub fn arb_production_k8s() -> impl Strategy<Value = ProductionK8sPlatform> {
    (
        arb_name(),
        secure_vpc::arb_config(),
        k3s_dev_cluster::arb_config(),
        ingress_alb::arb_config(),
        monitoring_stack::arb_config(),
        backup_vault::arb_config(),
        encrypted_storage::arb_config(),
        dns_zone::arb_config(),
    ).prop_map(|(name, vpc, cluster, alb, monitoring, backup, encryption, dns)| {
        ProductionK8sPlatform { name, vpc, cluster, alb, monitoring, backup, encryption, dns }
    })
}

pub fn simulate_production_k8s(p: &ProductionK8sPlatform) -> Value {
    let mut resources = serde_json::Map::new();

    // Merge all component JSONs
    for component_json in [
        secure_vpc::simulate(&p.vpc),
        k3s_dev_cluster::simulate(&p.cluster),
        ingress_alb::simulate(&p.alb),
        monitoring_stack::simulate(&p.monitoring),
        backup_vault::simulate(&p.backup),
        encrypted_storage::simulate(&p.encryption),
        dns_zone::simulate(&p.dns),
    ] {
        if let Some(res) = component_json.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in res {
                let entry = resources.entry(resource_type.clone())
                    .or_insert_with(|| json!({}));
                if let (Some(existing), Some(new)) = (entry.as_object_mut(), instances.as_object()) {
                    for (k, v) in new {
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    json!({ "resource": resources })
}

// ── System 2: Builder Fleet + VPN ────────────────────────────────
// VPC + Nix builders + WireGuard VPN + DNS + encryption

/// Cloud builder infrastructure with VPN access.
#[derive(Debug, Clone)]
pub struct BuilderInfra {
    pub name: String,
    pub vpc: secure_vpc::SecureVpcConfig,
    pub builders: nix_builder_fleet::NixBuilderFleetConfig,
    pub vpn: wireguard_vpn::WireguardVpnConfig,
    pub dns: dns_zone::DnsZoneConfig,
    pub encryption: encrypted_storage::EncryptedStorageConfig,
}

pub fn arb_builder_infra() -> impl Strategy<Value = BuilderInfra> {
    (
        arb_name(),
        secure_vpc::arb_config(),
        nix_builder_fleet::arb_config(),
        wireguard_vpn::arb_config(),
        dns_zone::arb_config(),
        encrypted_storage::arb_config(),
    ).prop_map(|(name, vpc, builders, vpn, dns, encryption)| {
        BuilderInfra { name, vpc, builders, vpn, dns, encryption }
    })
}

pub fn simulate_builder_infra(b: &BuilderInfra) -> Value {
    let mut resources = serde_json::Map::new();

    for component_json in [
        secure_vpc::simulate(&b.vpc),
        nix_builder_fleet::simulate(&b.builders),
        wireguard_vpn::simulate(&b.vpn),
        dns_zone::simulate(&b.dns),
        encrypted_storage::simulate(&b.encryption),
    ] {
        if let Some(res) = component_json.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in res {
                let entry = resources.entry(resource_type.clone())
                    .or_insert_with(|| json!({}));
                if let (Some(existing), Some(new)) = (entry.as_object_mut(), instances.as_object()) {
                    for (k, v) in new {
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    json!({ "resource": resources })
}

// ── System 3: Data Platform ──────────────────────────────────────
// VPC + RDS + encryption + monitoring + backups + VPN

/// Complete data platform with database, encryption, and observability.
#[derive(Debug, Clone)]
pub struct DataPlatform {
    pub name: String,
    pub vpc: secure_vpc::SecureVpcConfig,
    pub database: rds_cluster::RdsClusterConfig,
    pub encryption: encrypted_storage::EncryptedStorageConfig,
    pub monitoring: monitoring_stack::MonitoringStackConfig,
    pub backup: backup_vault::BackupVaultConfig,
    pub vpn: wireguard_vpn::WireguardVpnConfig,
}

pub fn arb_data_platform() -> impl Strategy<Value = DataPlatform> {
    (
        arb_name(),
        secure_vpc::arb_config(),
        rds_cluster::arb_config(),
        encrypted_storage::arb_config(),
        monitoring_stack::arb_config(),
        backup_vault::arb_config(),
        wireguard_vpn::arb_config(),
    ).prop_map(|(name, vpc, database, encryption, monitoring, backup, vpn)| {
        DataPlatform { name, vpc, database, encryption, monitoring, backup, vpn }
    })
}

pub fn simulate_data_platform(d: &DataPlatform) -> Value {
    let mut resources = serde_json::Map::new();

    for component_json in [
        secure_vpc::simulate(&d.vpc),
        rds_cluster::simulate(&d.database),
        encrypted_storage::simulate(&d.encryption),
        monitoring_stack::simulate(&d.monitoring),
        backup_vault::simulate(&d.backup),
        wireguard_vpn::simulate(&d.vpn),
    ] {
        if let Some(res) = component_json.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in res {
                let entry = resources.entry(resource_type.clone())
                    .or_insert_with(|| json!({}));
                if let (Some(existing), Some(new)) = (entry.as_object_mut(), instances.as_object()) {
                    for (k, v) in new {
                        existing.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    json!({ "resource": resources })
}
