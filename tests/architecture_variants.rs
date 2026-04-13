//! Architecture variant proofs — all valid configs produce valid simulations.

use proptest::prelude::*;
use pangea_sim::analysis::ArchitectureAnalysis;

macro_rules! prove_variants {
    ($proof_mod:ident, $sim_mod:path, $min:expr) => {
        mod $proof_mod {
            use super::*;
            use $sim_mod as sim;
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(500))]
                #[test]
                fn produces_resources(config in sim::arb_config()) {
                    let tf = sim::simulate(&config);
                    let a = ArchitectureAnalysis::from_terraform_json(&tf);
                    prop_assert!(a.resource_count >= $min);
                }
                #[test]
                fn deterministic(config in sim::arb_config()) {
                    prop_assert_eq!(sim::simulate(&config), sim::simulate(&config));
                }
            }
        }
    };
}

prove_variants!(secure_vpc, pangea_sim::simulations::secure_vpc, 3);
prove_variants!(tiered_subnets, pangea_sim::simulations::tiered_subnets, 1);
prove_variants!(dns_zone, pangea_sim::simulations::dns_zone, 1);
prove_variants!(ingress_alb, pangea_sim::simulations::ingress_alb, 2);
prove_variants!(waf_shield, pangea_sim::simulations::waf_shield, 1);
prove_variants!(encrypted_storage, pangea_sim::simulations::encrypted_storage, 1);
prove_variants!(backup_vault, pangea_sim::simulations::backup_vault, 1);
prove_variants!(monitoring_stack, pangea_sim::simulations::monitoring_stack, 1);
prove_variants!(k3s_cluster_iam, pangea_sim::simulations::k3s_cluster_iam, 2);
prove_variants!(k3s_dev_cluster, pangea_sim::simulations::k3s_dev_cluster, 5);
prove_variants!(nix_builder_fleet, pangea_sim::simulations::nix_builder_fleet, 4);
prove_variants!(nat_gateway, pangea_sim::simulations::nat_gateway, 1);
prove_variants!(bastion_host, pangea_sim::simulations::bastion_host, 2);
prove_variants!(vpc_endpoints, pangea_sim::simulations::vpc_endpoints, 1);
prove_variants!(secrets_manager, pangea_sim::simulations::secrets_manager, 1);
prove_variants!(cloudtrail, pangea_sim::simulations::cloudtrail, 2);
prove_variants!(rds_cluster, pangea_sim::simulations::rds_cluster, 3);
prove_variants!(wireguard_vpn, pangea_sim::simulations::wireguard_vpn, 3);
prove_variants!(ecr_registry, pangea_sim::simulations::ecr_registry, 1);
prove_variants!(config_recorder, pangea_sim::simulations::config_recorder, 3);
