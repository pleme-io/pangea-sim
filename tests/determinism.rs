//! Determinism proofs — prove simulation outputs are reproducible.

use serde_json::{json, Value};

// ── JSON round-trip ──────────────────────────────────────────────

#[test]
fn json_round_trip_simple() {
    let original = json!({"resource": {"aws_vpc": {"main": {"cidr_block": "10.0.0.0/16"}}}});
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn json_round_trip_nested() {
    let original = json!({
        "resource": {
            "aws_launch_template": {
                "lt": {
                    "block_device_mappings": [{"ebs": {"encrypted": true, "volume_size": 100}}],
                    "metadata_options": {"http_tokens": "required"},
                    "tags": {"Name": "test", "ManagedBy": "pangea"}
                }
            }
        }
    });
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original, deserialized);
}

#[test]
fn json_round_trip_refs() {
    let original = json!({
        "resource": {
            "aws_subnet": {
                "sub": {"vpc_id": "${aws_vpc.main.id}", "cidr_block": "10.0.1.0/24"}
            }
        }
    });
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: Value = serde_json::from_str(&serialized).unwrap();
    assert_eq!(original, deserialized);
}

// ── Value equality is reflexive ──────────────────────────────────

#[test]
fn value_equality_reflexive() {
    let v = json!({"a": 1, "b": [2, 3], "c": {"d": true}});
    assert_eq!(v, v.clone());
}

// ── Analysis determinism ─────────────────────────────────────────

#[test]
fn analysis_deterministic() {
    use pangea_sim::analysis::ArchitectureAnalysis;

    let tf = json!({
        "resource": {
            "aws_vpc": {"main": {"cidr_block": "10.0.0.0/16"}},
            "aws_subnet": {
                "a": {"vpc_id": "${aws_vpc.main.id}"},
                "b": {"vpc_id": "${aws_vpc.main.id}"}
            }
        }
    });

    let a1 = ArchitectureAnalysis::from_terraform_json(&tf);
    let a2 = ArchitectureAnalysis::from_terraform_json(&tf);

    assert_eq!(a1.resource_count, a2.resource_count);
    assert_eq!(a1.resources_by_type, a2.resources_by_type);
    assert_eq!(a1.cross_references.len(), a2.cross_references.len());
}
