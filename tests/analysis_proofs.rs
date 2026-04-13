//! Analysis proofs — prove structural properties of architecture analysis.

use pangea_sim::analysis::ArchitectureAnalysis;
use serde_json::{json, Value};

// ── resource_count equals sum of resources_by_type ───────────────

#[test]
fn resource_count_is_sum() {
    let tf = json!({
        "resource": {
            "aws_vpc": {"a": {}, "b": {}},
            "aws_subnet": {"c": {}, "d": {}, "e": {}},
            "aws_security_group": {"f": {}}
        }
    });
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    let sum: usize = a.resources_by_type.values().sum();
    assert_eq!(a.resource_count, sum);
    assert_eq!(a.resource_count, 6);
}

// ── has_resource semantics ───────────────────────────────────────

#[test]
fn has_resource_zero_always_true_for_present_type() {
    let tf = json!({"resource": {"aws_vpc": {"main": {}}}});
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    assert!(a.has_resource("aws_vpc", 0));
    assert!(a.has_resource("aws_vpc", 1));
    assert!(!a.has_resource("aws_vpc", 2));
}

#[test]
fn has_resource_false_for_absent_type() {
    let tf = json!({"resource": {"aws_vpc": {"main": {}}}});
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    assert!(!a.has_resource("aws_subnet", 1));
    // min_count 0 is always true even for absent types (0 >= 0)
    assert!(a.has_resource("aws_subnet", 0));
}

// ── Empty JSON ───────────────────────────────────────────────────

#[test]
fn empty_json_zero_everything() {
    let a = ArchitectureAnalysis::from_terraform_json(&json!({}));
    assert_eq!(a.resource_count, 0);
    assert_eq!(a.data_source_count, 0);
    assert!(a.resources_by_type.is_empty());
    assert!(a.cross_references.is_empty());
}

// ── Cross-references are exactly the ${...} strings ──────────────

#[test]
fn cross_references_match_ref_strings() {
    let tf = json!({
        "resource": {
            "aws_subnet": {
                "a": {"vpc_id": "${aws_vpc.main.id}", "cidr": "10.0.0.0/24"},
                "b": {"vpc_id": "${aws_vpc.main.id}", "az": "us-east-1a"}
            },
            "aws_route_table": {
                "rt": {"vpc_id": "${aws_vpc.main.id}"}
            }
        }
    });
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    assert_eq!(a.cross_references.len(), 3);
    assert!(a.cross_references.iter().all(|r| r.starts_with("${")));
}

// ── Data sources counted independently ───────────────────────────

#[test]
fn data_sources_independent_of_resources() {
    let tf = json!({
        "resource": {"aws_vpc": {"main": {}}},
        "data": {"aws_ami": {"latest": {}, "previous": {}}}
    });
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    assert_eq!(a.resource_count, 1);
    assert_eq!(a.data_source_count, 2);
}

// ── resources_by_type keys are sorted (BTreeMap) ─────────────────

#[test]
fn resources_by_type_sorted() {
    let tf = json!({
        "resource": {
            "aws_vpc": {"a": {}},
            "aws_alb": {"b": {}},
            "aws_subnet": {"c": {}}
        }
    });
    let a = ArchitectureAnalysis::from_terraform_json(&tf);
    let keys: Vec<&String> = a.resources_by_type.keys().collect();
    assert_eq!(keys, vec!["aws_alb", "aws_subnet", "aws_vpc"]);
}

// ── Adding resources increases count ─────────────────────────────

#[test]
fn adding_resource_increases_count() {
    let tf_small = json!({"resource": {"aws_vpc": {"a": {}}}});
    let tf_large = json!({"resource": {"aws_vpc": {"a": {}, "b": {}}, "aws_subnet": {"c": {}}}});

    let a_small = ArchitectureAnalysis::from_terraform_json(&tf_small);
    let a_large = ArchitectureAnalysis::from_terraform_json(&tf_large);

    assert!(a_large.resource_count > a_small.resource_count);
}
