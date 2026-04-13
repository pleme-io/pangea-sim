//! Shared types and proptest strategies for architecture simulations.

use proptest::prelude::*;
use proptest::prop_oneof;
use serde_json::{json, Value};

/// Deployment profile.
#[derive(Debug, Clone)]
pub enum Profile {
    Dev,
    Production,
}

/// Generate a valid resource name: lowercase, starts with letter, no consecutive hyphens.
pub fn arb_name() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{2,15}".prop_filter("no consecutive hyphens", |s| !s.contains("--"))
}

/// Generate a valid private CIDR block.
pub fn arb_cidr() -> impl Strategy<Value = String> {
    (10..=10_u8, 0..=255_u8).prop_map(|(a, b)| format!("{a}.{b}.0.0/16"))
}

/// Generate a list of availability zones.
pub fn arb_azs() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop_oneof![
            Just("us-east-1a".into()),
            Just("us-east-1b".into()),
            Just("us-east-1c".into()),
        ],
        1..=3,
    )
}

/// Generate a deployment profile.
pub fn arb_profile() -> impl Strategy<Value = Profile> {
    prop_oneof![Just(Profile::Dev), Just(Profile::Production)]
}

/// Generate a valid domain name.
pub fn arb_domain() -> impl Strategy<Value = String> {
    "[a-z]{3,10}\\.(com|io|lol|dev)"
}

/// Generate a common port number.
pub fn arb_port() -> impl Strategy<Value = u16> {
    prop_oneof![
        Just(22u16),
        Just(80),
        Just(443),
        Just(6443),
        Just(8080),
        Just(51822),
    ]
}

/// Generate an instance type.
pub fn arb_instance_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("t3.medium".into()),
        Just("t3.large".into()),
        Just("m5.large".into()),
        Just("m5.xlarge".into()),
        Just("c5.large".into()),
    ]
}

/// Generate an AMI ID.
pub fn arb_ami_id() -> impl Strategy<Value = String> {
    "[a-z0-9]{8}".prop_map(|s| format!("ami-{s}"))
}

/// Generate a volume size in GB.
pub fn arb_volume_size() -> impl Strategy<Value = i64> {
    20..=500_i64
}

/// Required tags for all resources (ManagedBy + Purpose).
pub fn required_tags() -> Value {
    json!({"ManagedBy": "pangea", "Purpose": "simulation"})
}

/// Merge required tags with additional tags.
pub fn tags_with(extra: &[(&str, &str)]) -> Value {
    let mut tags = required_tags();
    let map = tags.as_object_mut().unwrap();
    for (k, v) in extra {
        map.insert((*k).to_string(), json!(v));
    }
    tags
}
