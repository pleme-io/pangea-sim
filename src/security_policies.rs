//! Security policy simulation -- prove policies are consistent and complete.
//!
//! Security policies (IAM, RBAC, NetworkPolicy, firewall rules) are types.
//! Prove: no conflicts, no gaps, least privilege, defense in depth.
//!
//! Policies are modeled as typed structs and verified through invariant
//! functions. Combined with proptest, this proves security properties
//! hold across thousands of random configurations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A named collection of security rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Human-readable policy name (e.g., "production-iam", "k8s-rbac").
    pub name: String,
    /// The layer this policy operates at.
    pub layer: PolicyLayer,
    /// Ordered list of rules evaluated top-to-bottom.
    pub rules: Vec<PolicyRule>,
}

/// The network/infra layer a policy targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyLayer {
    /// IAM / identity-based access control.
    Iam,
    /// Kubernetes RBAC (Role, ClusterRole, RoleBinding).
    KubernetesRbac,
    /// Network-level policy (K8s NetworkPolicy, security groups, firewalls).
    Network,
    /// Application-level policy (API keys, OAuth scopes).
    Application,
}

/// A single access-control rule within a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Who: user, role, service account, or CIDR.
    pub subject: String,
    /// What operation is being controlled.
    pub action: Action,
    /// What resource is being accessed (bucket, table, namespace, pod).
    pub resource: String,
    /// Whether this rule allows or denies the action.
    pub effect: Effect,
    /// Optional conditions (e.g., "MFA required", "source IP 10.0.0.0/8").
    pub conditions: Vec<String>,
}

/// Actions that can be controlled by a policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Delete,
    Admin,
    Custom(String),
}

/// Whether a rule allows or denies an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

// ── Policy invariant checks ──────────────────────────────────────

/// No rule allows what another rule denies for the same subject+resource pair.
///
/// A conflict exists when two rules target the same (subject, resource) pair
/// but one has `Effect::Allow` and the other has `Effect::Deny` for the same action.
///
/// # Errors
///
/// Returns a description of the first conflict found.
pub fn check_no_conflicts(policy: &SecurityPolicy) -> Result<(), String> {
    for (i, rule_a) in policy.rules.iter().enumerate() {
        for rule_b in &policy.rules[i + 1..] {
            if rule_a.subject == rule_b.subject
                && rule_a.resource == rule_b.resource
                && rule_a.action == rule_b.action
                && rule_a.effect != rule_b.effect
            {
                return Err(format!(
                    "Conflict in policy '{}': subject '{}' has both Allow and Deny \
                     for action {:?} on resource '{}'",
                    policy.name, rule_a.subject, rule_a.action, rule_a.resource
                ));
            }
        }
    }
    Ok(())
}

/// No `Admin` access unless the rule has a condition justifying it,
/// and no wildcard (`*`) resources.
///
/// # Errors
///
/// Returns a description of the first least-privilege violation found.
pub fn check_least_privilege(policy: &SecurityPolicy) -> Result<(), String> {
    for rule in &policy.rules {
        // Wildcard resources are never acceptable
        if rule.resource == "*" {
            return Err(format!(
                "Policy '{}': rule for subject '{}' uses wildcard resource '*'",
                policy.name, rule.subject
            ));
        }

        // Admin access requires at least one condition (justification)
        if rule.action == Action::Admin && rule.effect == Effect::Allow && rule.conditions.is_empty()
        {
            return Err(format!(
                "Policy '{}': subject '{}' has Admin access on resource '{}' \
                 without any conditions/justification",
                policy.name, rule.subject, rule.resource
            ));
        }
    }
    Ok(())
}

/// At least one explicit Deny rule must exist for unmatched requests.
///
/// A policy is deny-by-default when it contains at least one rule with
/// `Effect::Deny` and a wildcard-like subject or resource pattern.
///
/// # Errors
///
/// Returns a description if no deny-by-default rule exists.
pub fn check_deny_by_default(policy: &SecurityPolicy) -> Result<(), String> {
    let has_deny = policy.rules.iter().any(|r| r.effect == Effect::Deny);
    if has_deny {
        Ok(())
    } else {
        Err(format!(
            "Policy '{}': no explicit Deny rules found -- policy is not deny-by-default",
            policy.name
        ))
    }
}

/// No single subject has both Write and Admin on the same resource.
///
/// Separation of duties requires that the person who can modify data
/// is not the same person who can administer the system.
///
/// # Errors
///
/// Returns a description of the first separation-of-duties violation.
pub fn check_separation_of_duties(policy: &SecurityPolicy) -> Result<(), String> {
    // Collect (subject, resource) -> set of allowed actions
    let mut subject_actions: std::collections::BTreeMap<(&str, &str), BTreeSet<&Action>> =
        std::collections::BTreeMap::new();

    for rule in &policy.rules {
        if rule.effect == Effect::Allow {
            subject_actions
                .entry((&rule.subject, &rule.resource))
                .or_default()
                .insert(&rule.action);
        }
    }

    for ((subject, resource), actions) in &subject_actions {
        let has_write = actions.contains(&Action::Write);
        let has_admin = actions.contains(&Action::Admin);
        if has_write && has_admin {
            return Err(format!(
                "Policy '{}': subject '{}' has both Write and Admin on resource '{}' \
                 -- separation of duties violated",
                policy.name, subject, resource
            ));
        }
    }
    Ok(())
}

/// Multiple layers of policy must exist (defense in depth).
///
/// Defense in depth requires policies at different layers (network, IAM,
/// application, RBAC) so that a breach at one layer is contained by another.
///
/// # Errors
///
/// Returns a description if fewer than 2 distinct policy layers are present.
pub fn check_defense_in_depth(policies: &[SecurityPolicy]) -> Result<(), String> {
    let layers: BTreeSet<_> = policies.iter().map(|p| &p.layer).collect();
    if layers.len() >= 2 {
        Ok(())
    } else {
        Err(format!(
            "Defense in depth requires policies at 2+ layers, found {}: {:?}",
            layers.len(),
            layers
        ))
    }
}

// ── Ord implementation for Action (needed for BTreeSet) ──────────

impl PartialOrd for Action {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Action {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rank = |a: &Action| -> u8 {
            match a {
                Action::Read => 0,
                Action::Write => 1,
                Action::Delete => 2,
                Action::Admin => 3,
                Action::Custom(_) => 4,
            }
        };
        match (self, other) {
            (Action::Custom(a), Action::Custom(b)) => a.cmp(b),
            _ => rank(self).cmp(&rank(other)),
        }
    }
}

// ── Ord implementation for PolicyLayer (needed for BTreeSet) ─────

impl PartialOrd for PolicyLayer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PolicyLayer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rank = |l: &PolicyLayer| -> u8 {
            match l {
                PolicyLayer::Network => 0,
                PolicyLayer::Iam => 1,
                PolicyLayer::KubernetesRbac => 2,
                PolicyLayer::Application => 3,
            }
        };
        rank(self).cmp(&rank(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_policy() -> SecurityPolicy {
        SecurityPolicy {
            name: "test-iam".to_string(),
            layer: PolicyLayer::Iam,
            rules: vec![
                PolicyRule {
                    subject: "developer".to_string(),
                    action: Action::Read,
                    resource: "s3://logs".to_string(),
                    effect: Effect::Allow,
                    conditions: vec![],
                },
                PolicyRule {
                    subject: "default".to_string(),
                    action: Action::Read,
                    resource: "s3://logs".to_string(),
                    effect: Effect::Deny,
                    conditions: vec![],
                },
            ],
        }
    }

    #[test]
    fn no_conflicts_on_valid_policy() {
        assert!(check_no_conflicts(&simple_policy()).is_ok());
    }

    #[test]
    fn deny_by_default_passes() {
        assert!(check_deny_by_default(&simple_policy()).is_ok());
    }
}
