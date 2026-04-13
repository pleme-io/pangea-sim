//! Compliance verification -- link invariant proofs to NIST/CIS/FedRAMP controls.
//!
//! Verifies that Terraform JSON satisfies a compliance baseline by running
//! the mapped invariants and collecting control-level results.
//!
//! Feature-gated behind `compliance` -- requires `compliance-controls`.

#[cfg(feature = "compliance")]
use compliance_controls::{
    baseline_coverage, controls_for_invariant, BaselineCoverage, Baseline, Control,
    ALL_INVARIANTS,
};

#[cfg(feature = "compliance")]
use crate::invariants::all_invariants;

use serde::{Deserialize, Serialize};

/// Result of verifying a single control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlResult {
    /// The control identifier (serialized).
    pub control_id: String,
    /// Which invariant was checked.
    pub invariant: String,
    /// Whether the control is satisfied.
    pub satisfied: bool,
    /// Error message if not satisfied.
    pub message: Option<String>,
}

/// Complete compliance verification result for a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    /// Baseline name (e.g., "FedRAMP Moderate").
    pub baseline_name: String,
    /// Total controls in the baseline.
    pub total_controls: usize,
    /// Number of controls satisfied.
    pub satisfied_count: usize,
    /// Number of controls violated.
    pub violated_count: usize,
    /// Per-control results.
    pub results: Vec<ControlResult>,
    /// Whether ALL controls are satisfied.
    pub all_satisfied: bool,
}

/// Map a snake_case invariant name to the PascalCase name used by
/// `compliance-controls` mappings.
#[cfg(feature = "compliance")]
fn invariant_name_to_pascal(snake: &str) -> &'static str {
    match snake {
        "no_public_ssh" => "NoPublicSsh",
        "all_ebs_encrypted" => "AllEbsEncrypted",
        "imdsv2_required" => "ImdsV2Required",
        "no_public_s3" => "NoPublicS3",
        "iam_least_privilege" => "IamLeastPrivilege",
        "no_default_vpc_usage" => "NoDefaultVpcUsage",
        "all_subnets_private" => "AllSubnetsPrivate",
        "encryption_at_rest" => "EncryptionAtRest",
        "logging_enabled" => "LoggingEnabled",
        "tagging_complete" => "TaggingComplete",
        _ => "",
    }
}

/// Format a `Control` for display/serialization.
#[cfg(feature = "compliance")]
fn control_display(control: &Control) -> String {
    match control {
        Control::Nist(n) => n.to_string(),
        Control::Cis(c) => format!("CIS {}", c.section),
        Control::FedRamp(l, n) => format!("FedRAMP {l:?} {n}"),
        Control::PciDss(p) => format!("PCI {}", p.requirement),
        Control::Soc2(s) => format!("SOC2 {}", s.criteria),
    }
}

/// Verify Terraform JSON satisfies a compliance baseline.
///
/// For each control in the baseline, finds which invariant(s) cover it,
/// runs those invariants against the provided Terraform JSON, and collects
/// per-control pass/fail results.
#[cfg(feature = "compliance")]
pub fn verify_baseline(
    tf_json: &serde_json::Value,
    baseline: &Baseline,
) -> ComplianceResult {
    let invariants = all_invariants();
    let mut results = Vec::new();
    let mut satisfied_count: usize = 0;
    let mut violated_count: usize = 0;

    for control in &baseline.controls {
        // Find invariants that map to this control
        let covering_invariant_names: Vec<&str> = ALL_INVARIANTS
            .iter()
            .filter(|inv| controls_for_invariant(inv).contains(control))
            .copied()
            .collect();

        if covering_invariant_names.is_empty() {
            results.push(ControlResult {
                control_id: control_display(control),
                invariant: "none".to_string(),
                satisfied: false,
                message: Some("No invariant covers this control".to_string()),
            });
            violated_count += 1;
            continue;
        }

        // Check if ANY covering invariant passes
        let mut any_passed = false;
        for pascal_name in &covering_invariant_names {
            // Find the invariant object by matching snake_case name
            if let Some(inv) = invariants.iter().find(|i| {
                invariant_name_to_pascal(i.name()) == *pascal_name
            }) {
                match inv.check(tf_json) {
                    Ok(()) => {
                        results.push(ControlResult {
                            control_id: control_display(control),
                            invariant: pascal_name.to_string(),
                            satisfied: true,
                            message: None,
                        });
                        any_passed = true;
                        break;
                    }
                    Err(violations) => {
                        let msg = violations
                            .iter()
                            .map(|v| v.message.clone())
                            .collect::<Vec<_>>()
                            .join("; ");
                        results.push(ControlResult {
                            control_id: control_display(control),
                            invariant: pascal_name.to_string(),
                            satisfied: false,
                            message: Some(msg),
                        });
                    }
                }
            }
        }

        if any_passed {
            satisfied_count += 1;
        } else {
            violated_count += 1;
        }
    }

    ComplianceResult {
        baseline_name: baseline.name.to_string(),
        total_controls: baseline.controls.len(),
        satisfied_count,
        violated_count,
        all_satisfied: violated_count == 0,
        results,
    }
}

/// Get coverage report for how well our invariants cover a baseline.
#[cfg(feature = "compliance")]
#[must_use]
pub fn coverage_report(baseline: &Baseline) -> BaselineCoverage {
    baseline_coverage(baseline)
}
