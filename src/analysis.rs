//! Terraform JSON analysis — extract structure from simulation output.

use serde_json::Value;
use std::collections::BTreeMap;

/// Analysis of a simulated architecture's Terraform JSON.
#[derive(Debug, Clone)]
pub struct ArchitectureAnalysis {
    /// Total number of resources.
    pub resource_count: usize,
    /// Resources by type (e.g., {"aws_vpc": 1, "aws_subnet": 3}).
    pub resources_by_type: BTreeMap<String, usize>,
    /// Total number of data sources.
    pub data_source_count: usize,
    /// Cross-references found (${type.name.attr} patterns).
    pub cross_references: Vec<String>,
}

impl ArchitectureAnalysis {
    /// Analyze a Terraform JSON value.
    #[must_use]
    pub fn from_terraform_json(tf: &Value) -> Self {
        let mut resources_by_type = BTreeMap::new();
        let mut resource_count = 0;
        let mut data_source_count = 0;

        // Count resources
        if let Some(resources) = tf.get("resource").and_then(Value::as_object) {
            for (resource_type, instances) in resources {
                let count = instances.as_object().map_or(0, |m| m.len());
                resources_by_type.insert(resource_type.clone(), count);
                resource_count += count;
            }
        }

        // Count data sources
        if let Some(data) = tf.get("data").and_then(Value::as_object) {
            for (_data_type, instances) in data {
                data_source_count += instances.as_object().map_or(0, |m| m.len());
            }
        }

        // Find cross-references
        let cross_references = find_references(tf);

        Self {
            resource_count,
            resources_by_type,
            data_source_count,
            cross_references,
        }
    }

    /// Check that a specific resource type exists with at least N instances.
    #[must_use]
    pub fn has_resource(&self, resource_type: &str, min_count: usize) -> bool {
        self.resources_by_type.get(resource_type).copied().unwrap_or(0) >= min_count
    }
}

/// Recursively find all ${...} references in a JSON value.
fn find_references(value: &Value) -> Vec<String> {
    let mut refs = Vec::new();
    match value {
        Value::String(s) => {
            if s.starts_with("${") && s.ends_with('}') {
                refs.push(s.clone());
            }
        }
        Value::Array(arr) => {
            for item in arr {
                refs.extend(find_references(item));
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                refs.extend(find_references(v));
            }
        }
        _ => {}
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn analyze_simple_architecture() {
        let tf = json!({
            "resource": {
                "aws_vpc": {
                    "main": { "cidr_block": "10.0.0.0/16" }
                },
                "aws_subnet": {
                    "public": { "vpc_id": "${aws_vpc.main.id}" },
                    "private": { "vpc_id": "${aws_vpc.main.id}" }
                }
            }
        });

        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        assert_eq!(analysis.resource_count, 3);
        assert_eq!(analysis.resources_by_type["aws_vpc"], 1);
        assert_eq!(analysis.resources_by_type["aws_subnet"], 2);
        assert!(analysis.has_resource("aws_vpc", 1));
        assert!(analysis.has_resource("aws_subnet", 2));
        assert!(!analysis.has_resource("aws_subnet", 3));
        assert_eq!(analysis.cross_references.len(), 2);
    }

    #[test]
    fn analyze_empty_json() {
        let tf = json!({});
        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        assert_eq!(analysis.resource_count, 0);
        assert_eq!(analysis.data_source_count, 0);
        assert!(analysis.cross_references.is_empty());
    }

    #[test]
    fn find_nested_references() {
        let tf = json!({
            "resource": {
                "aws_lb": {
                    "nlb": {
                        "subnets": ["${aws_subnet.a.id}", "${aws_subnet.b.id}"],
                        "tags": { "vpc": "${aws_vpc.main.id}" }
                    }
                }
            }
        });

        let analysis = ArchitectureAnalysis::from_terraform_json(&tf);
        assert_eq!(analysis.cross_references.len(), 3);
    }
}
