//! Architecture invariant proofs — all 10 security invariants × 13 architectures.

use proptest::prelude::*;
use pangea_sim::invariants::{all_invariants, check_all, Invariant};

macro_rules! prove_invariants {
    ($proof_mod:ident, $sim_mod:path) => {
        mod $proof_mod {
            use super::*;
            use $sim_mod as sim;
            proptest! {
                #![proptest_config(ProptestConfig::with_cases(500))]
                #[test]
                fn all_invariants_hold(config in sim::arb_config()) {
                    let tf = sim::simulate(&config);
                    let invs = all_invariants();
                    let refs: Vec<&dyn Invariant> = invs.iter().map(|i| i.as_ref()).collect();
                    prop_assert!(check_all(&refs, &tf).is_ok());
                }
            }
        }
    };
}

prove_invariants!(secure_vpc, pangea_sim::simulations::secure_vpc);
prove_invariants!(tiered_subnets, pangea_sim::simulations::tiered_subnets);
prove_invariants!(dns_zone, pangea_sim::simulations::dns_zone);
prove_invariants!(ingress_alb, pangea_sim::simulations::ingress_alb);
prove_invariants!(waf_shield, pangea_sim::simulations::waf_shield);
prove_invariants!(encrypted_storage, pangea_sim::simulations::encrypted_storage);
prove_invariants!(backup_vault, pangea_sim::simulations::backup_vault);
prove_invariants!(monitoring_stack, pangea_sim::simulations::monitoring_stack);
prove_invariants!(k3s_cluster_iam, pangea_sim::simulations::k3s_cluster_iam);
prove_invariants!(k3s_dev_cluster, pangea_sim::simulations::k3s_dev_cluster);
prove_invariants!(nix_builder_fleet, pangea_sim::simulations::nix_builder_fleet);
prove_invariants!(nat_gateway, pangea_sim::simulations::nat_gateway);
prove_invariants!(bastion_host, pangea_sim::simulations::bastion_host);
prove_invariants!(vpc_endpoints, pangea_sim::simulations::vpc_endpoints);
prove_invariants!(secrets_manager, pangea_sim::simulations::secrets_manager);
prove_invariants!(cloudtrail, pangea_sim::simulations::cloudtrail);
prove_invariants!(rds_cluster, pangea_sim::simulations::rds_cluster);
prove_invariants!(wireguard_vpn, pangea_sim::simulations::wireguard_vpn);
prove_invariants!(ecr_registry, pangea_sim::simulations::ecr_registry);
prove_invariants!(config_recorder, pangea_sim::simulations::config_recorder);
