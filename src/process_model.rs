//! Process model — convergence processes beyond Kubernetes.
//!
//! A convergence process can run on any backend: Kubernetes, EC2, ASG,
//! BareMetal, or Lambda. Each process has a PID, parent PID, DNS identity,
//! and state. The process tree is the convergence platform's operating
//! model — Unix semantics applied to infrastructure.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The compute backend for a convergence process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessBackend {
    Kubernetes {
        cluster_name: String,
        namespace: String,
    },
    Ec2Instance {
        instance_type: String,
        ami_id: String,
    },
    Ec2Asg {
        asg_name: String,
        instance_count: u32,
        spot: bool,
    },
    BareMetal {
        hostname: String,
        ip: String,
    },
    Lambda {
        function_name: String,
        runtime: String,
    },
}

/// DNS zone type for split-horizon resolution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ZoneType {
    Public,
    Private,
    SplitHorizon,
}

/// DNS record type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DnsRecordType {
    A,
    Cname,
    Alias,
}

/// DNS identity for a convergence process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsIdentity {
    pub fqdn: String,
    pub zone_type: ZoneType,
    pub record_type: DnsRecordType,
    pub target: String,
}

/// Lifecycle state of a convergence process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProcessState {
    Pending,
    Provisioning,
    Running,
    Degraded,
    Draining,
    Terminated,
}

/// A single convergence process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConvergenceProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub backend: ProcessBackend,
    pub dns_identity: DnsIdentity,
    pub state: ProcessState,
}

/// A tree of convergence processes — Unix process tree for infrastructure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessTree {
    pub root: ConvergenceProcess,
    pub children: Vec<ProcessTree>,
}

// ═══════════════════════════════════════════════════════════════════
// Invariant checks
// ═══════════════════════════════════════════════════════════════════

/// Collect all PIDs from a process tree.
fn collect_pids(tree: &ProcessTree) -> Vec<u32> {
    let mut pids = vec![tree.root.pid];
    for child in &tree.children {
        pids.extend(collect_pids(child));
    }
    pids
}

/// Collect all processes from a process tree.
fn collect_processes(tree: &ProcessTree) -> Vec<&ConvergenceProcess> {
    let mut procs = vec![&tree.root];
    for child in &tree.children {
        procs.extend(collect_processes(child));
    }
    procs
}

/// Check that all PIDs in the tree are unique.
///
/// # Errors
///
/// Returns a description of duplicate PIDs.
pub fn check_unique_pids(tree: &ProcessTree) -> Result<(), String> {
    let pids = collect_pids(tree);
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for pid in &pids {
        if !seen.insert(pid) {
            duplicates.push(*pid);
        }
    }
    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(format!("duplicate PIDs: {duplicates:?}"))
    }
}

/// Check that every non-root process has a valid parent in the tree.
///
/// # Errors
///
/// Returns a description of orphan processes.
pub fn check_no_orphans(tree: &ProcessTree) -> Result<(), String> {
    let pids: HashSet<u32> = collect_pids(tree).into_iter().collect();
    let processes = collect_processes(tree);
    let mut orphans = Vec::new();
    for proc in &processes {
        // Root process (PID == tree.root.pid) is allowed to have ppid 0
        if proc.pid == tree.root.pid {
            continue;
        }
        if !pids.contains(&proc.ppid) {
            orphans.push(proc.pid);
        }
    }
    if orphans.is_empty() {
        Ok(())
    } else {
        Err(format!("orphan processes (no valid parent): {orphans:?}"))
    }
}

/// Check that no two processes share the same FQDN.
///
/// # Errors
///
/// Returns a description of duplicate FQDNs.
pub fn check_dns_no_overlap(tree: &ProcessTree) -> Result<(), String> {
    let processes = collect_processes(tree);
    let mut seen = HashSet::new();
    let mut duplicates = Vec::new();
    for proc in &processes {
        if !seen.insert(&proc.dns_identity.fqdn) {
            duplicates.push(proc.dns_identity.fqdn.clone());
        }
    }
    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(format!("duplicate FQDNs: {duplicates:?}"))
    }
}

/// Check that every process has a non-empty DNS identity.
///
/// # Errors
///
/// Returns a description of processes missing DNS.
pub fn check_all_have_dns(tree: &ProcessTree) -> Result<(), String> {
    let processes = collect_processes(tree);
    let mut missing = Vec::new();
    for proc in &processes {
        if proc.dns_identity.fqdn.is_empty() || proc.dns_identity.target.is_empty() {
            missing.push(proc.name.clone());
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("processes without DNS identity: {missing:?}"))
    }
}

/// Check that DNS patterns match backend types.
///
/// Convention:
/// - Kubernetes backends: FQDN contains "k8s."
/// - EC2/ASG backends: FQDN contains "builder." or "cache." or matches infra pattern
/// - Lambda backends: FQDN contains "fn."
///
/// # Errors
///
/// Returns a description of mismatched patterns.
pub fn check_backend_dns_pattern(tree: &ProcessTree) -> Result<(), String> {
    let processes = collect_processes(tree);
    let mut mismatches = Vec::new();
    for proc in &processes {
        let fqdn = &proc.dns_identity.fqdn;
        let ok = match &proc.backend {
            ProcessBackend::Kubernetes { .. } => fqdn.contains("k8s."),
            ProcessBackend::Ec2Instance { .. } | ProcessBackend::Ec2Asg { .. } => {
                // EC2 and ASG processes use various infra subdomains
                fqdn.contains("builder.")
                    || fqdn.contains("cache.")
                    || fqdn.contains("dns.")
                    || fqdn.contains("vpc.")
                    || fqdn.contains("infra.")
            }
            ProcessBackend::BareMetal { .. } => {
                fqdn.contains("bare.") || fqdn.contains("metal.") || fqdn.contains("infra.")
            }
            ProcessBackend::Lambda { .. } => fqdn.contains("fn."),
        };
        if !ok {
            mismatches.push(format!(
                "{} (backend {:?}, fqdn {})",
                proc.name,
                backend_kind(&proc.backend),
                fqdn
            ));
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(format!("DNS pattern mismatches: {mismatches:?}"))
    }
}

/// Return a short label for the backend kind.
fn backend_kind(backend: &ProcessBackend) -> &'static str {
    match backend {
        ProcessBackend::Kubernetes { .. } => "Kubernetes",
        ProcessBackend::Ec2Instance { .. } => "Ec2Instance",
        ProcessBackend::Ec2Asg { .. } => "Ec2Asg",
        ProcessBackend::BareMetal { .. } => "BareMetal",
        ProcessBackend::Lambda { .. } => "Lambda",
    }
}

/// Run all process tree invariant checks.
///
/// # Errors
///
/// Returns the first invariant violation found.
pub fn check_all_process_invariants(tree: &ProcessTree) -> Result<(), String> {
    check_unique_pids(tree)?;
    check_no_orphans(tree)?;
    check_dns_no_overlap(tree)?;
    check_all_have_dns(tree)?;
    check_backend_dns_pattern(tree)?;
    Ok(())
}

/// Valid state transitions for `ProcessState`.
///
/// Returns true if transitioning from `from` to `to` is valid.
#[must_use]
pub fn is_valid_transition(from: &ProcessState, to: &ProcessState) -> bool {
    matches!(
        (from, to),
        (ProcessState::Pending, ProcessState::Provisioning)
            | (ProcessState::Provisioning, ProcessState::Running)
            | (ProcessState::Provisioning, ProcessState::Terminated) // provision failure
            | (ProcessState::Running, ProcessState::Degraded)
            | (ProcessState::Running, ProcessState::Draining)
            | (ProcessState::Degraded, ProcessState::Running)    // recovery
            | (ProcessState::Degraded, ProcessState::Draining)
            | (ProcessState::Draining, ProcessState::Terminated)
    )
}

// ═══════════════════════════════════════════════════════════════════
// quero.lol platform process tree
// ═══════════════════════════════════════════════════════════════════

/// Build the quero.lol convergence platform process tree.
///
/// ```text
/// quero-platform (PID 1, orchestrator)
///   +-- quero-dns (PID 2, Ec2Instance -- Route53 management)
///   +-- quero-vpc (PID 3, Ec2Instance -- VPC orchestrator)
///   +-- quero-builders-aarch64 (PID 4, Ec2Asg -- Graviton spot)
///   +-- quero-builders-x86 (PID 5, Ec2Asg -- x86 spot)
///   +-- quero-cache (PID 6, Ec2Instance -- Attic nix cache)
///   +-- quero-seph (PID 7, Kubernetes -- convergence controller)
/// ```
#[must_use]
pub fn quero_process_tree() -> ProcessTree {
    let root = ConvergenceProcess {
        pid: 1,
        ppid: 0,
        name: "quero-platform".to_string(),
        backend: ProcessBackend::Ec2Instance {
            instance_type: "t3.medium".to_string(),
            ami_id: "ami-quero-platform".to_string(),
        },
        dns_identity: DnsIdentity {
            fqdn: "infra.quero.lol".to_string(),
            zone_type: ZoneType::SplitHorizon,
            record_type: DnsRecordType::A,
            target: "10.0.0.10".to_string(),
        },
        state: ProcessState::Running,
    };

    let dns = ProcessTree {
        root: ConvergenceProcess {
            pid: 2,
            ppid: 1,
            name: "quero-dns".to_string(),
            backend: ProcessBackend::Ec2Instance {
                instance_type: "t3.small".to_string(),
                ami_id: "ami-quero-dns".to_string(),
            },
            dns_identity: DnsIdentity {
                fqdn: "dns.quero.lol".to_string(),
                zone_type: ZoneType::SplitHorizon,
                record_type: DnsRecordType::A,
                target: "10.0.0.11".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    let vpc = ProcessTree {
        root: ConvergenceProcess {
            pid: 3,
            ppid: 1,
            name: "quero-vpc".to_string(),
            backend: ProcessBackend::Ec2Instance {
                instance_type: "t3.small".to_string(),
                ami_id: "ami-quero-vpc".to_string(),
            },
            dns_identity: DnsIdentity {
                fqdn: "vpc.quero.lol".to_string(),
                zone_type: ZoneType::Private,
                record_type: DnsRecordType::A,
                target: "10.0.0.12".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    let builders_aarch64 = ProcessTree {
        root: ConvergenceProcess {
            pid: 4,
            ppid: 1,
            name: "quero-builders-aarch64".to_string(),
            backend: ProcessBackend::Ec2Asg {
                asg_name: "quero-aarch64-builders".to_string(),
                instance_count: 2,
                spot: true,
            },
            dns_identity: DnsIdentity {
                fqdn: "builder.aarch64.quero.lol".to_string(),
                zone_type: ZoneType::Private,
                record_type: DnsRecordType::A,
                target: "10.0.1.0".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    let builders_x86 = ProcessTree {
        root: ConvergenceProcess {
            pid: 5,
            ppid: 1,
            name: "quero-builders-x86".to_string(),
            backend: ProcessBackend::Ec2Asg {
                asg_name: "quero-x86-builders".to_string(),
                instance_count: 2,
                spot: true,
            },
            dns_identity: DnsIdentity {
                fqdn: "builder.x86.quero.lol".to_string(),
                zone_type: ZoneType::Private,
                record_type: DnsRecordType::A,
                target: "10.0.2.0".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    let cache = ProcessTree {
        root: ConvergenceProcess {
            pid: 6,
            ppid: 1,
            name: "quero-cache".to_string(),
            backend: ProcessBackend::Ec2Instance {
                instance_type: "m5.large".to_string(),
                ami_id: "ami-quero-cache".to_string(),
            },
            dns_identity: DnsIdentity {
                fqdn: "cache.quero.lol".to_string(),
                zone_type: ZoneType::Private,
                record_type: DnsRecordType::A,
                target: "10.0.3.10".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    let seph = ProcessTree {
        root: ConvergenceProcess {
            pid: 7,
            ppid: 1,
            name: "quero-seph".to_string(),
            backend: ProcessBackend::Kubernetes {
                cluster_name: "seph".to_string(),
                namespace: "convergence".to_string(),
            },
            dns_identity: DnsIdentity {
                fqdn: "k8s.seph.quero.lol".to_string(),
                zone_type: ZoneType::SplitHorizon,
                record_type: DnsRecordType::Cname,
                target: "nlb.seph.quero.lol".to_string(),
            },
            state: ProcessState::Running,
        },
        children: vec![],
    };

    ProcessTree {
        root,
        children: vec![dns, vpc, builders_aarch64, builders_x86, cache, seph],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quero_tree_has_seven_processes() {
        let tree = quero_process_tree();
        let pids = collect_pids(&tree);
        assert_eq!(pids.len(), 7);
    }

    #[test]
    fn quero_tree_passes_all_invariants() {
        let tree = quero_process_tree();
        assert!(check_all_process_invariants(&tree).is_ok());
    }

    #[test]
    fn valid_process_transitions() {
        assert!(is_valid_transition(
            &ProcessState::Pending,
            &ProcessState::Provisioning
        ));
        assert!(is_valid_transition(
            &ProcessState::Provisioning,
            &ProcessState::Running
        ));
        assert!(is_valid_transition(
            &ProcessState::Running,
            &ProcessState::Degraded
        ));
        assert!(is_valid_transition(
            &ProcessState::Degraded,
            &ProcessState::Running
        ));
        assert!(is_valid_transition(
            &ProcessState::Running,
            &ProcessState::Draining
        ));
        assert!(is_valid_transition(
            &ProcessState::Draining,
            &ProcessState::Terminated
        ));
    }

    #[test]
    fn invalid_process_transitions() {
        assert!(!is_valid_transition(
            &ProcessState::Pending,
            &ProcessState::Running
        ));
        assert!(!is_valid_transition(
            &ProcessState::Terminated,
            &ProcessState::Running
        ));
        assert!(!is_valid_transition(
            &ProcessState::Running,
            &ProcessState::Pending
        ));
    }
}
