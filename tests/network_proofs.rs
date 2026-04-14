//! Network topology proofs — prove connectivity, fault tolerance,
//! and routing correctness through types.
//!
//! 15+ proofs that network invariants hold across topologies, that
//! redundancy is correctly detected, and that real-world network
//! layouts (pleme-io VPC + subnets + NLB) satisfy all checks.

use proptest::prelude::*;
use std::collections::BTreeMap;

use pangea_sim::network::*;

// ── Helpers ────────────────────────────────────────────────────────

fn node(id: &str, node_type: NodeType, region: &str, cidr: Option<&str>) -> (NodeId, NetworkNode) {
    (
        NodeId(id.to_string()),
        NetworkNode {
            id: NodeId(id.to_string()),
            node_type,
            region: region.to_string(),
            cidr: cidr.map(String::from),
        },
    )
}

fn link(from: &str, to: &str, link_type: LinkType, bandwidth: Option<u32>) -> NetworkLink {
    NetworkLink {
        from: NodeId(from.to_string()),
        to: NodeId(to.to_string()),
        link_type,
        bandwidth_mbps: bandwidth,
    }
}

/// Build a fully connected (mesh) topology with N nodes.
fn fully_connected_topology(n: usize) -> NetworkTopology {
    let mut nodes = BTreeMap::new();
    let mut links = Vec::new();

    for i in 0..n {
        let id = format!("node_{i}");
        nodes.insert(
            NodeId(id.clone()),
            NetworkNode {
                id: NodeId(id.clone()),
                node_type: NodeType::Instance,
                region: "us-east-1".to_string(),
                cidr: Some(format!("10.{i}.0.0/16")),
            },
        );
    }

    for i in 0..n {
        for j in (i + 1)..n {
            links.push(link(
                &format!("node_{i}"),
                &format!("node_{j}"),
                LinkType::Direct,
                Some(1000),
            ));
        }
    }

    NetworkTopology { nodes, links }
}

/// Build a star (hub-and-spoke) topology with center + N spokes.
fn star_topology(n_spokes: usize) -> NetworkTopology {
    let mut nodes = BTreeMap::new();
    let mut links = Vec::new();

    let (hub_id, hub_node) = node("hub", NodeType::LoadBalancer, "us-east-1", None);
    nodes.insert(hub_id, hub_node);

    for i in 0..n_spokes {
        let id = format!("spoke_{i}");
        let (spoke_id, spoke_node) = node(&id, NodeType::Instance, "us-east-1", Some(&format!("10.{i}.0.0/24")));
        nodes.insert(spoke_id, spoke_node);
        links.push(link("hub", &id, LinkType::Direct, Some(1000)));
    }

    NetworkTopology { nodes, links }
}

/// Build a ring topology with N nodes.
fn ring_topology(n: usize) -> NetworkTopology {
    let mut nodes = BTreeMap::new();
    let mut links = Vec::new();

    for i in 0..n {
        let id = format!("node_{i}");
        nodes.insert(
            NodeId(id.clone()),
            NetworkNode {
                id: NodeId(id.clone()),
                node_type: NodeType::Instance,
                region: "us-east-1".to_string(),
                cidr: Some(format!("10.{i}.0.0/24")),
            },
        );
    }

    for i in 0..n {
        let next = (i + 1) % n;
        links.push(link(
            &format!("node_{i}"),
            &format!("node_{next}"),
            LinkType::Direct,
            Some(1000),
        ));
    }

    NetworkTopology { nodes, links }
}

/// Build a pleme-io style network: VPC -> subnets -> NLB -> instances.
fn pleme_io_network() -> NetworkTopology {
    let mut nodes = BTreeMap::new();

    // VPC — no CIDR on the container node itself; subnets carry the CIDRs
    let (vpc_id, vpc_node) = node("vpc-main", NodeType::Vpc, "us-east-1", None);
    nodes.insert(vpc_id, vpc_node);

    // Subnets
    let (pub1_id, pub1) = node("subnet-pub-1a", NodeType::Subnet, "us-east-1a", Some("10.0.1.0/24"));
    let (pub2_id, pub2) = node("subnet-pub-1b", NodeType::Subnet, "us-east-1b", Some("10.0.2.0/24"));
    let (priv1_id, priv1) = node("subnet-priv-1a", NodeType::Subnet, "us-east-1a", Some("10.0.10.0/24"));
    let (priv2_id, priv2) = node("subnet-priv-1b", NodeType::Subnet, "us-east-1b", Some("10.0.11.0/24"));
    nodes.insert(pub1_id, pub1);
    nodes.insert(pub2_id, pub2);
    nodes.insert(priv1_id, priv1);
    nodes.insert(priv2_id, priv2);

    // NLB
    let (nlb_id, nlb_node) = node("nlb-main", NodeType::LoadBalancer, "us-east-1", None);
    nodes.insert(nlb_id, nlb_node);

    // Gateway
    let (gw_id, gw_node) = node("igw-main", NodeType::Gateway, "us-east-1", None);
    nodes.insert(gw_id, gw_node);

    // Instances
    let (inst1_id, inst1) = node("instance-1a", NodeType::Instance, "us-east-1a", None);
    let (inst2_id, inst2) = node("instance-1b", NodeType::Instance, "us-east-1b", None);
    nodes.insert(inst1_id, inst1);
    nodes.insert(inst2_id, inst2);

    let links = vec![
        // VPC -> subnets
        link("vpc-main", "subnet-pub-1a", LinkType::Direct, Some(10000)),
        link("vpc-main", "subnet-pub-1b", LinkType::Direct, Some(10000)),
        link("vpc-main", "subnet-priv-1a", LinkType::Direct, Some(10000)),
        link("vpc-main", "subnet-priv-1b", LinkType::Direct, Some(10000)),
        // Gateway -> VPC
        link("igw-main", "vpc-main", LinkType::Direct, Some(10000)),
        // NLB -> public subnets
        link("nlb-main", "subnet-pub-1a", LinkType::Direct, Some(10000)),
        link("nlb-main", "subnet-pub-1b", LinkType::Direct, Some(10000)),
        // Instances -> private subnets
        link("instance-1a", "subnet-priv-1a", LinkType::Direct, Some(10000)),
        link("instance-1b", "subnet-priv-1b", LinkType::Direct, Some(10000)),
        // Cross-AZ links for redundancy
        link("subnet-pub-1a", "subnet-priv-1a", LinkType::Direct, Some(10000)),
        link("subnet-pub-1b", "subnet-priv-1b", LinkType::Direct, Some(10000)),
        // Cross-AZ subnet links
        link("subnet-pub-1a", "subnet-pub-1b", LinkType::Peering, Some(10000)),
        link("subnet-priv-1a", "subnet-priv-1b", LinkType::Peering, Some(10000)),
    ];

    NetworkTopology { nodes, links }
}

// ── Proptest strategies ────────────────────────────────────────────

fn arb_unique_cidr(index: usize) -> String {
    // Generate non-overlapping CIDRs by using different second octets
    format!("10.{index}.0.0/24")
}

fn arb_connected_topology() -> impl Strategy<Value = NetworkTopology> {
    (3..=8usize).prop_map(|n| {
        let mut nodes = BTreeMap::new();
        let mut links = Vec::new();

        for i in 0..n {
            let id = format!("n{i}");
            nodes.insert(
                NodeId(id.clone()),
                NetworkNode {
                    id: NodeId(id),
                    node_type: NodeType::Instance,
                    region: "us-east-1".to_string(),
                    cidr: Some(arb_unique_cidr(i)),
                },
            );
        }

        // Create a spanning tree (linear chain) to guarantee connectivity
        for i in 0..(n - 1) {
            links.push(NetworkLink {
                from: NodeId(format!("n{i}")),
                to: NodeId(format!("n{}", i + 1)),
                link_type: LinkType::Direct,
                bandwidth_mbps: Some(1000),
            });
        }

        NetworkTopology { nodes, links }
    })
}

// ── Proofs ─────────────────────────────────────────────────────────

/// Proof 1: Fully connected topology passes connectivity check.
#[test]
fn fully_connected_passes_connectivity() {
    let topo = fully_connected_topology(5);
    assert!(
        check_connectivity(&topo).is_ok(),
        "Fully connected topology should pass connectivity"
    );
}

/// Proof 2: Disconnected topology fails connectivity check.
#[test]
fn disconnected_fails_connectivity() {
    let mut nodes = BTreeMap::new();
    let (a_id, a_node) = node("a", NodeType::Instance, "us-east-1", Some("10.0.0.0/24"));
    let (b_id, b_node) = node("b", NodeType::Instance, "us-east-1", Some("10.1.0.0/24"));
    let (c_id, c_node) = node("c", NodeType::Instance, "us-west-2", Some("10.2.0.0/24"));
    nodes.insert(a_id, a_node);
    nodes.insert(b_id, b_node);
    nodes.insert(c_id, c_node);

    // Only connect a-b, c is isolated
    let topo = NetworkTopology {
        nodes,
        links: vec![link("a", "b", LinkType::Direct, Some(1000))],
    };

    let result = check_connectivity(&topo);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("c"));
}

/// Proof 3: Hub-and-spoke topology is connected.
#[test]
fn hub_and_spoke_connected() {
    let topo = star_topology(5);
    assert!(
        check_connectivity(&topo).is_ok(),
        "Hub-and-spoke should be connected"
    );
}

/// Proof 4: Mesh topology has redundant paths.
#[test]
fn mesh_has_redundant_paths() {
    let topo = fully_connected_topology(4);
    assert!(
        check_redundant_paths(&topo, &NodeId("node_0".to_string()), &NodeId("node_3".to_string())),
        "Mesh topology should have redundant paths"
    );
}

/// Proof 5: No overlapping CIDRs in well-formed topologies (proptest 500).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn no_overlapping_cidrs_proptest(topo in arb_connected_topology()) {
        prop_assert!(
            check_no_overlapping_cidrs(&topo).is_ok(),
            "Generated topology has overlapping CIDRs"
        );
    }
}

/// Proof 6: Single point of failure detected in star topology.
#[test]
fn spof_in_star_topology() {
    let topo = star_topology(4);
    let result = check_no_single_point_of_failure(&topo);
    assert!(
        result.is_err(),
        "Star topology hub should be detected as SPOF"
    );
    assert!(result.unwrap_err().contains("hub"));
}

/// Proof 7: Shortest path correctness.
#[test]
fn shortest_path_correctness() {
    // Linear chain: a - b - c - d
    let mut nodes = BTreeMap::new();
    for id in ["a", "b", "c", "d"] {
        let (nid, nn) = node(id, NodeType::Instance, "us-east-1", None);
        nodes.insert(nid, nn);
    }
    let topo = NetworkTopology {
        nodes,
        links: vec![
            link("a", "b", LinkType::Direct, None),
            link("b", "c", LinkType::Direct, None),
            link("c", "d", LinkType::Direct, None),
        ],
    };

    let path = compute_shortest_path(&topo, &NodeId("a".to_string()), &NodeId("d".to_string()));
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 4);
    assert_eq!(path[0], NodeId("a".to_string()));
    assert_eq!(path[3], NodeId("d".to_string()));
}

/// Proof 8: Shortest path prefers direct route.
#[test]
fn shortest_path_prefers_direct() {
    // a -- b -- c, but also a -- c (direct shortcut)
    let mut nodes = BTreeMap::new();
    for id in ["a", "b", "c"] {
        let (nid, nn) = node(id, NodeType::Instance, "us-east-1", None);
        nodes.insert(nid, nn);
    }
    let topo = NetworkTopology {
        nodes,
        links: vec![
            link("a", "b", LinkType::Direct, None),
            link("b", "c", LinkType::Direct, None),
            link("a", "c", LinkType::Direct, None),
        ],
    };

    let path = compute_shortest_path(&topo, &NodeId("a".to_string()), &NodeId("c".to_string()));
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 2, "Direct path a->c should have 2 nodes");
}

/// Proof 9: Multi-region topology connectivity.
#[test]
fn multi_region_connectivity() {
    let mut nodes = BTreeMap::new();
    let (us_vpc, us_vpc_n) = node("vpc-us", NodeType::Vpc, "us-east-1", Some("10.0.0.0/16"));
    let (eu_vpc, eu_vpc_n) = node("vpc-eu", NodeType::Vpc, "eu-west-1", Some("10.1.0.0/16"));
    let (ap_vpc, ap_vpc_n) = node("vpc-ap", NodeType::Vpc, "ap-southeast-1", Some("10.2.0.0/16"));
    nodes.insert(us_vpc, us_vpc_n);
    nodes.insert(eu_vpc, eu_vpc_n);
    nodes.insert(ap_vpc, ap_vpc_n);

    let topo = NetworkTopology {
        nodes,
        links: vec![
            link("vpc-us", "vpc-eu", LinkType::Peering, Some(1000)),
            link("vpc-eu", "vpc-ap", LinkType::Peering, Some(1000)),
            link("vpc-ap", "vpc-us", LinkType::Peering, Some(1000)),
        ],
    };

    assert!(check_connectivity(&topo).is_ok());
    // Ring of 3 has no SPOF (3 nodes, removing any one leaves 2 still connected)
    assert!(check_no_single_point_of_failure(&topo).is_ok());
}

/// Proof 10: VPN links provide redundancy.
#[test]
fn vpn_links_provide_redundancy() {
    // Two DCs connected by primary + VPN backup
    let mut nodes = BTreeMap::new();
    let (dc1, dc1_n) = node("dc1", NodeType::Vpc, "us-east-1", Some("10.0.0.0/16"));
    let (dc2, dc2_n) = node("dc2", NodeType::Vpc, "us-west-2", Some("10.1.0.0/16"));
    let (relay, relay_n) = node("relay", NodeType::Gateway, "eu-west-1", None);
    nodes.insert(dc1, dc1_n);
    nodes.insert(dc2, dc2_n);
    nodes.insert(relay, relay_n);

    let topo = NetworkTopology {
        nodes,
        links: vec![
            link("dc1", "dc2", LinkType::Direct, Some(10000)),
            link("dc1", "relay", LinkType::Vpn, Some(500)),
            link("relay", "dc2", LinkType::Vpn, Some(500)),
        ],
    };

    assert!(check_redundant_paths(
        &topo,
        &NodeId("dc1".to_string()),
        &NodeId("dc2".to_string())
    ));
}

/// Proof 11: Network serialization roundtrip.
#[test]
fn network_serialization_roundtrip() {
    let topo = pleme_io_network();
    let json = serde_json::to_string(&topo).expect("serialize");
    let deserialized: NetworkTopology = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(topo.nodes.len(), deserialized.nodes.len());
    assert_eq!(topo.links.len(), deserialized.links.len());
    for (id, _node) in &topo.nodes {
        assert!(deserialized.nodes.contains_key(id));
    }
}

/// Proof 12: Real pleme-io network passes connectivity check.
#[test]
fn pleme_io_network_connected() {
    let topo = pleme_io_network();
    assert!(
        check_connectivity(&topo).is_ok(),
        "pleme-io network should be fully connected"
    );
}

/// Proof 13: Real pleme-io network has no overlapping CIDRs.
#[test]
fn pleme_io_network_no_cidr_overlap() {
    let topo = pleme_io_network();
    assert!(
        check_no_overlapping_cidrs(&topo).is_ok(),
        "pleme-io network should have non-overlapping CIDRs"
    );
}

/// Proof 14: No path exists between disconnected nodes.
#[test]
fn no_path_between_disconnected() {
    let mut nodes = BTreeMap::new();
    let (a_id, a_n) = node("a", NodeType::Instance, "us-east-1", None);
    let (b_id, b_n) = node("b", NodeType::Instance, "us-east-1", None);
    nodes.insert(a_id, a_n);
    nodes.insert(b_id, b_n);

    let topo = NetworkTopology {
        nodes,
        links: vec![],
    };

    assert!(compute_shortest_path(&topo, &NodeId("a".to_string()), &NodeId("b".to_string())).is_none());
}

/// Proof 15: Ring topology has no SPOF for 4+ nodes.
#[test]
fn ring_no_spof() {
    let topo = ring_topology(5);
    assert!(check_connectivity(&topo).is_ok());
    assert!(
        check_no_single_point_of_failure(&topo).is_ok(),
        "Ring of 5 should have no SPOF"
    );
}

/// Proof 16: Ring topology has redundant paths.
#[test]
fn ring_redundant_paths() {
    let topo = ring_topology(5);
    assert!(check_redundant_paths(
        &topo,
        &NodeId("node_0".to_string()),
        &NodeId("node_2".to_string()),
    ));
}

/// Proof 17: Empty topology passes all checks.
#[test]
fn empty_topology_passes_all() {
    let topo = NetworkTopology {
        nodes: BTreeMap::new(),
        links: vec![],
    };
    assert!(check_all_network_invariants(&topo).is_ok());
}

/// Proof 18: Shortest path to self is single element.
#[test]
fn shortest_path_to_self() {
    let topo = fully_connected_topology(3);
    let path = compute_shortest_path(&topo, &NodeId("node_0".to_string()), &NodeId("node_0".to_string()));
    assert!(path.is_some());
    let path = path.unwrap();
    assert_eq!(path.len(), 1);
    assert_eq!(path[0], NodeId("node_0".to_string()));
}

/// Proof 19: Connected topologies stay connected (proptest 500).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn connected_topologies_pass(topo in arb_connected_topology()) {
        prop_assert!(
            check_connectivity(&topo).is_ok(),
            "Generated connected topology failed connectivity"
        );
    }
}

/// Proof 20: Mesh topology has no SPOF.
#[test]
fn mesh_no_spof() {
    let topo = fully_connected_topology(4);
    assert!(
        check_no_single_point_of_failure(&topo).is_ok(),
        "Mesh topology should have no SPOF"
    );
}
