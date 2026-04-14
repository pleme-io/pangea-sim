//! Network topology simulation — prove connectivity and fault tolerance.
//!
//! Define network topologies as Rust types. Prove connectivity, redundancy,
//! and fault tolerance. The same convergence model applies: declare topology
//! -> prove invariants -> render to VPC/subnet/NLB -> deploy safely.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A unique identifier for a node in the network.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// A node in the network topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: NodeId,
    pub node_type: NodeType,
    pub region: String,
    pub cidr: Option<String>,
}

/// The type of network node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Vpc,
    Subnet,
    LoadBalancer,
    Instance,
    Gateway,
    Firewall,
}

/// A link between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLink {
    pub from: NodeId,
    pub to: NodeId,
    pub link_type: LinkType,
    pub bandwidth_mbps: Option<u32>,
}

/// The type of network link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkType {
    Peering,
    Transit,
    Direct,
    Vpn,
}

/// A complete network topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: BTreeMap<NodeId, NetworkNode>,
    pub links: Vec<NetworkLink>,
}

impl NetworkTopology {
    /// Build an adjacency list from the links (undirected graph).
    fn adjacency_list(&self) -> BTreeMap<&NodeId, BTreeSet<&NodeId>> {
        let mut adj: BTreeMap<&NodeId, BTreeSet<&NodeId>> = BTreeMap::new();

        // Initialize all nodes
        for node_id in self.nodes.keys() {
            adj.entry(node_id).or_default();
        }

        // Add edges (undirected)
        for link in &self.links {
            if self.nodes.contains_key(&link.from) && self.nodes.contains_key(&link.to) {
                adj.entry(&link.from).or_default().insert(&link.to);
                adj.entry(&link.to).or_default().insert(&link.from);
            }
        }

        adj
    }

    /// BFS from a source node, returning all reachable nodes.
    fn bfs_reachable<'a>(&'a self, start: &'a NodeId, adj: &BTreeMap<&'a NodeId, BTreeSet<&'a NodeId>>) -> BTreeSet<&'a NodeId> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();

        if adj.contains_key(start) {
            visited.insert(start);
            queue.push_back(start);
        }

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adj.get(current) {
                for neighbor in neighbors {
                    if visited.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        visited
    }

    /// BFS from a source node with certain nodes excluded, returning all reachable nodes.
    fn bfs_reachable_excluding<'a>(
        &'a self,
        start: &'a NodeId,
        adj: &BTreeMap<&'a NodeId, BTreeSet<&'a NodeId>>,
        excluded: &BTreeSet<&'a NodeId>,
    ) -> BTreeSet<&'a NodeId> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();

        if adj.contains_key(start) && !excluded.contains(start) {
            visited.insert(start);
            queue.push_back(start);
        }

        while let Some(current) = queue.pop_front() {
            if let Some(neighbors) = adj.get(current) {
                for neighbor in neighbors {
                    if !excluded.contains(neighbor) && visited.insert(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        visited
    }
}

/// Check that all nodes in the topology are reachable from each other
/// (the graph is connected).
///
/// # Errors
///
/// Returns an error if any node is unreachable from the first node.
pub fn check_connectivity(topology: &NetworkTopology) -> Result<(), String> {
    if topology.nodes.is_empty() {
        return Ok(());
    }

    let adj = topology.adjacency_list();
    let start = topology.nodes.keys().next().unwrap();
    let reachable = topology.bfs_reachable(start, &adj);

    if reachable.len() == topology.nodes.len() {
        Ok(())
    } else {
        let unreachable: Vec<&str> = topology
            .nodes
            .keys()
            .filter(|n| !reachable.contains(n))
            .map(|n| n.0.as_str())
            .collect();
        Err(format!(
            "Nodes not reachable from '{}': {:?}",
            start.0, unreachable
        ))
    }
}

/// Check that no two nodes with CIDRs have overlapping address ranges.
///
/// Uses a simplified prefix-based overlap check: two CIDRs overlap if
/// one is a prefix of the other in network terms (same base with one
/// having a shorter prefix length), or they share the same network prefix.
///
/// # Errors
///
/// Returns an error describing the overlapping CIDRs.
pub fn check_no_overlapping_cidrs(topology: &NetworkTopology) -> Result<(), String> {
    let cidrs: Vec<(&NodeId, &str)> = topology
        .nodes
        .iter()
        .filter_map(|(id, node)| node.cidr.as_deref().map(|c| (id, c)))
        .collect();

    for i in 0..cidrs.len() {
        for j in (i + 1)..cidrs.len() {
            let (id_a, cidr_a) = cidrs[i];
            let (id_b, cidr_b) = cidrs[j];
            if cidrs_overlap(cidr_a, cidr_b) {
                return Err(format!(
                    "Overlapping CIDRs: '{}' ({}) and '{}' ({})",
                    id_a.0, cidr_a, id_b.0, cidr_b
                ));
            }
        }
    }
    Ok(())
}

/// Parse a CIDR string into a (network_address_u32, prefix_length) pair.
fn parse_cidr(cidr: &str) -> Option<(u32, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let prefix_len: u8 = parts[1].parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let octets: Vec<&str> = parts[0].split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut addr: u32 = 0;
    for octet in &octets {
        let val: u8 = octet.parse().ok()?;
        addr = (addr << 8) | u32::from(val);
    }
    // Mask to network address
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    Some((addr & mask, prefix_len))
}

/// Check if two CIDR blocks overlap.
fn cidrs_overlap(a: &str, b: &str) -> bool {
    let Some((net_a, prefix_a)) = parse_cidr(a) else {
        return false;
    };
    let Some((net_b, prefix_b)) = parse_cidr(b) else {
        return false;
    };

    // Use the shorter prefix to compare
    let shorter = prefix_a.min(prefix_b);
    let mask = if shorter == 0 {
        0
    } else {
        !0u32 << (32 - shorter)
    };

    (net_a & mask) == (net_b & mask)
}

/// Check if there are redundant (multiple disjoint) paths between two nodes.
///
/// Uses Menger's theorem: remove each intermediate node one at a time.
/// If the destination is still reachable after removing any single
/// intermediate node, there are at least two vertex-disjoint paths.
#[must_use]
pub fn check_redundant_paths(topology: &NetworkTopology, from: &NodeId, to: &NodeId) -> bool {
    if from == to {
        return true;
    }
    if !topology.nodes.contains_key(from) || !topology.nodes.contains_key(to) {
        return false;
    }

    let adj = topology.adjacency_list();

    // First, check basic connectivity
    let reachable = topology.bfs_reachable(from, &adj);
    if !reachable.contains(to) {
        return false;
    }

    // For each intermediate node (not from or to), remove it and check
    // if from can still reach to
    for node_id in topology.nodes.keys() {
        if node_id == from || node_id == to {
            continue;
        }
        let excluded = BTreeSet::from([node_id]);
        let reachable = topology.bfs_reachable_excluding(from, &adj, &excluded);
        if !reachable.contains(to) {
            return false;
        }
    }

    true
}

/// Check that no single node failure disconnects the network.
///
/// A network has no single point of failure if removing any single node
/// still leaves all remaining nodes connected.
///
/// # Errors
///
/// Returns an error describing the single point of failure node.
pub fn check_no_single_point_of_failure(topology: &NetworkTopology) -> Result<(), String> {
    if topology.nodes.len() <= 2 {
        // Trivially: 0 or 1 nodes cannot have SPOF. 2 nodes always have
        // each other as SPOF, but that's unavoidable for 2-node networks.
        return Ok(());
    }

    let adj = topology.adjacency_list();

    for node_id in topology.nodes.keys() {
        let excluded = BTreeSet::from([node_id]);
        let remaining: Vec<&NodeId> = topology.nodes.keys().filter(|n| *n != node_id).collect();

        if remaining.is_empty() {
            continue;
        }

        let start = remaining[0];
        let reachable = topology.bfs_reachable_excluding(start, &adj, &excluded);

        // All remaining nodes should be reachable
        let remaining_count = remaining.len();
        if reachable.len() != remaining_count {
            return Err(format!(
                "Node '{}' is a single point of failure — removing it disconnects the network",
                node_id.0
            ));
        }
    }

    Ok(())
}

/// Compute the shortest path between two nodes using BFS.
///
/// Returns `None` if no path exists.
#[must_use]
pub fn compute_shortest_path(topology: &NetworkTopology, from: &NodeId, to: &NodeId) -> Option<Vec<NodeId>> {
    if from == to {
        return Some(vec![from.clone()]);
    }
    if !topology.nodes.contains_key(from) || !topology.nodes.contains_key(to) {
        return None;
    }

    let adj = topology.adjacency_list();
    let mut visited = BTreeSet::new();
    let mut queue: VecDeque<Vec<&NodeId>> = VecDeque::new();

    visited.insert(from);
    queue.push_back(vec![from]);

    while let Some(path) = queue.pop_front() {
        let current = *path.last().unwrap();

        if let Some(neighbors) = adj.get(current) {
            for neighbor in neighbors {
                if *neighbor == to {
                    let mut result: Vec<NodeId> = path.iter().map(|n| (*n).clone()).collect();
                    result.push(to.clone());
                    return Some(result);
                }
                if visited.insert(neighbor) {
                    let mut new_path = path.clone();
                    new_path.push(neighbor);
                    queue.push_back(new_path);
                }
            }
        }
    }

    None
}

/// Run all network topology invariant checks.
///
/// # Errors
///
/// Returns the first invariant violation found.
pub fn check_all_network_invariants(topology: &NetworkTopology) -> Result<(), String> {
    check_connectivity(topology)?;
    check_no_overlapping_cidrs(topology)?;
    check_no_single_point_of_failure(topology)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_node_topology() -> NetworkTopology {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            NodeId("a".to_string()),
            NetworkNode {
                id: NodeId("a".to_string()),
                node_type: NodeType::Vpc,
                region: "us-east-1".to_string(),
                cidr: Some("10.0.0.0/16".to_string()),
            },
        );
        nodes.insert(
            NodeId("b".to_string()),
            NetworkNode {
                id: NodeId("b".to_string()),
                node_type: NodeType::Subnet,
                region: "us-east-1".to_string(),
                cidr: Some("10.1.0.0/16".to_string()),
            },
        );
        NetworkTopology {
            nodes,
            links: vec![NetworkLink {
                from: NodeId("a".to_string()),
                to: NodeId("b".to_string()),
                link_type: LinkType::Direct,
                bandwidth_mbps: Some(1000),
            }],
        }
    }

    #[test]
    fn two_nodes_connected() {
        let topo = two_node_topology();
        assert!(check_connectivity(&topo).is_ok());
    }

    #[test]
    fn empty_topology_passes() {
        let topo = NetworkTopology {
            nodes: BTreeMap::new(),
            links: vec![],
        };
        assert!(check_connectivity(&topo).is_ok());
    }

    #[test]
    fn overlapping_cidrs_detected() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            NodeId("a".to_string()),
            NetworkNode {
                id: NodeId("a".to_string()),
                node_type: NodeType::Vpc,
                region: "us-east-1".to_string(),
                cidr: Some("10.0.0.0/16".to_string()),
            },
        );
        nodes.insert(
            NodeId("b".to_string()),
            NetworkNode {
                id: NodeId("b".to_string()),
                node_type: NodeType::Subnet,
                region: "us-east-1".to_string(),
                cidr: Some("10.0.1.0/24".to_string()),
            },
        );
        let topo = NetworkTopology {
            nodes,
            links: vec![],
        };
        assert!(check_no_overlapping_cidrs(&topo).is_err());
    }

    #[test]
    fn cidr_parsing() {
        assert_eq!(parse_cidr("10.0.0.0/16"), Some((0x0A00_0000, 16)));
        assert_eq!(parse_cidr("192.168.1.0/24"), Some((0xC0A8_0100, 24)));
        assert_eq!(parse_cidr("invalid"), None);
    }
}
