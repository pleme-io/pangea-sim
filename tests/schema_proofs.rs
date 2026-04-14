//! Schema proofs — prove database migration safety through types.
//!
//! 15+ proofs that schema invariants hold across migrations, that
//! backward compatibility is correctly detected, and that real-world
//! schemas (e-commerce) satisfy all invariants.

use proptest::prelude::*;
use std::collections::BTreeMap;

use pangea_sim::schemas::*;

// ── Helpers ────────────────────────────────────────────────────────

fn col(name: &str, col_type: ColumnType, nullable: bool, has_default: bool) -> Column {
    Column {
        name: name.to_string(),
        col_type,
        nullable,
        has_default,
    }
}

fn users_table() -> Table {
    Table {
        name: "users".to_string(),
        columns: vec![
            col("id", ColumnType::Uuid, false, true),
            col("email", ColumnType::Text, false, false),
            col("name", ColumnType::Text, false, false),
            col("created_at", ColumnType::Timestamp, false, true),
        ],
        primary_key: vec!["id".to_string()],
        indexes: vec![
            Index {
                name: "idx_users_email".to_string(),
                columns: vec!["email".to_string()],
                unique: true,
            },
        ],
        foreign_keys: vec![],
    }
}

fn orders_table() -> Table {
    Table {
        name: "orders".to_string(),
        columns: vec![
            col("id", ColumnType::Uuid, false, true),
            col("user_id", ColumnType::Uuid, false, false),
            col("total", ColumnType::Float, false, false),
            col("status", ColumnType::Text, false, false),
            col("created_at", ColumnType::Timestamp, false, true),
        ],
        primary_key: vec!["id".to_string()],
        indexes: vec![
            Index {
                name: "idx_orders_user_id".to_string(),
                columns: vec!["user_id".to_string()],
                unique: false,
            },
        ],
        foreign_keys: vec![ForeignKey {
            column: "user_id".to_string(),
            references_table: "users".to_string(),
            references_column: "id".to_string(),
        }],
    }
}

fn products_table() -> Table {
    Table {
        name: "products".to_string(),
        columns: vec![
            col("id", ColumnType::Uuid, false, true),
            col("name", ColumnType::Text, false, false),
            col("price", ColumnType::Float, false, false),
            col("description", ColumnType::Text, true, false),
            col("created_at", ColumnType::Timestamp, false, true),
        ],
        primary_key: vec!["id".to_string()],
        indexes: vec![],
        foreign_keys: vec![],
    }
}

fn payments_table() -> Table {
    Table {
        name: "payments".to_string(),
        columns: vec![
            col("id", ColumnType::Uuid, false, true),
            col("order_id", ColumnType::Uuid, false, false),
            col("amount", ColumnType::Float, false, false),
            col("method", ColumnType::Text, false, false),
            col("processed_at", ColumnType::Timestamp, true, false),
        ],
        primary_key: vec!["id".to_string()],
        indexes: vec![
            Index {
                name: "idx_payments_order_id".to_string(),
                columns: vec!["order_id".to_string()],
                unique: false,
            },
        ],
        foreign_keys: vec![ForeignKey {
            column: "order_id".to_string(),
            references_table: "orders".to_string(),
            references_column: "id".to_string(),
        }],
    }
}

fn ecommerce_schema_v1() -> Schema {
    let mut tables = BTreeMap::new();
    tables.insert("users".to_string(), users_table());
    tables.insert("orders".to_string(), orders_table());
    tables.insert("products".to_string(), products_table());
    tables.insert("payments".to_string(), payments_table());
    Schema {
        name: "ecommerce".to_string(),
        version: 1,
        tables,
    }
}

fn ecommerce_schema_v2() -> Schema {
    let mut schema = ecommerce_schema_v1();
    schema.version = 2;

    // Add nullable column to users
    if let Some(users) = schema.tables.get_mut("users") {
        users.columns.push(col("phone", ColumnType::Text, true, false));
    }

    // Add a new reviews table
    schema.tables.insert(
        "reviews".to_string(),
        Table {
            name: "reviews".to_string(),
            columns: vec![
                col("id", ColumnType::Uuid, false, true),
                col("user_id", ColumnType::Uuid, false, false),
                col("product_id", ColumnType::Uuid, false, false),
                col("rating", ColumnType::Integer, false, false),
                col("body", ColumnType::Text, true, false),
            ],
            primary_key: vec!["id".to_string()],
            indexes: vec![
                Index {
                    name: "idx_reviews_product".to_string(),
                    columns: vec!["product_id".to_string()],
                    unique: false,
                },
            ],
            foreign_keys: vec![
                ForeignKey {
                    column: "user_id".to_string(),
                    references_table: "users".to_string(),
                    references_column: "id".to_string(),
                },
                ForeignKey {
                    column: "product_id".to_string(),
                    references_table: "products".to_string(),
                    references_column: "id".to_string(),
                },
            ],
        },
    );

    schema
}

// ── Proptest strategies ────────────────────────────────────────────

fn arb_column_type() -> impl Strategy<Value = ColumnType> {
    prop_oneof![
        Just(ColumnType::Text),
        Just(ColumnType::Integer),
        Just(ColumnType::Boolean),
        Just(ColumnType::Timestamp),
        Just(ColumnType::Uuid),
        Just(ColumnType::Json),
        Just(ColumnType::Float),
    ]
}

fn arb_column() -> impl Strategy<Value = Column> {
    (
        "[a-z][a-z_]{1,10}",
        arb_column_type(),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(|(name, col_type, nullable, has_default)| Column {
            name,
            col_type,
            nullable,
            has_default,
        })
}

fn arb_valid_table() -> impl Strategy<Value = (String, Table)> {
    (
        "[a-z][a-z_]{1,10}",
        prop::collection::vec(arb_column(), 1..=8),
    )
        .prop_map(|(name, mut columns)| {
            // Ensure unique column names
            let mut seen = std::collections::BTreeSet::new();
            columns.retain(|c| seen.insert(c.name.clone()));

            // First column is always the PK
            let pk = vec![columns[0].name.clone()];

            let table = Table {
                name: name.clone(),
                columns,
                primary_key: pk,
                indexes: vec![],
                foreign_keys: vec![],
            };
            (name, table)
        })
}

fn arb_valid_schema() -> impl Strategy<Value = Schema> {
    (
        "[a-z][a-z_]{1,10}",
        1..=100u32,
        prop::collection::vec(arb_valid_table(), 1..=5),
    )
        .prop_map(|(name, version, tables_vec)| {
            let mut tables = BTreeMap::new();
            for (table_name, table) in tables_vec {
                tables.entry(table_name).or_insert(table);
            }
            Schema {
                name,
                version,
                tables,
            }
        })
}

// ── Proofs ─────────────────────────────────────────────────────────

/// Proof 1: Schema with valid foreign keys passes FK check.
#[test]
fn valid_foreign_keys_pass() {
    let schema = ecommerce_schema_v1();
    assert!(
        check_no_orphan_foreign_keys(&schema).is_ok(),
        "E-commerce schema should have valid FKs"
    );
}

/// Proof 2: Schema with orphan FK fails check.
#[test]
fn orphan_fk_fails() {
    let mut tables = BTreeMap::new();
    tables.insert(
        "orders".to_string(),
        Table {
            name: "orders".to_string(),
            columns: vec![
                col("id", ColumnType::Uuid, false, true),
                col("user_id", ColumnType::Uuid, false, false),
            ],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![ForeignKey {
                column: "user_id".to_string(),
                references_table: "users".to_string(), // does not exist
                references_column: "id".to_string(),
            }],
        },
    );
    let schema = Schema {
        name: "test".to_string(),
        version: 1,
        tables,
    };
    let result = check_no_orphan_foreign_keys(&schema);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("non-existent table"));
}

/// Proof 3: Schema migration computes correct diffs.
#[test]
fn migration_computes_correct_diffs() {
    let v1 = ecommerce_schema_v1();
    let v2 = ecommerce_schema_v2();
    let migration = compute_migration(&v1, &v2);

    assert_eq!(migration.from_version, 1);
    assert_eq!(migration.to_version, 2);
    assert!(migration.added_tables.contains(&"reviews".to_string()));
    assert!(migration.removed_tables.is_empty());
    // "phone" column added to users
    assert!(migration.added_columns.iter().any(|(t, c)| t == "users" && c == "phone"));
    assert!(migration.removed_columns.iter().all(|(t, _)| t != "users"));
}

/// Proof 4: Adding nullable column is backward compatible.
#[test]
fn adding_nullable_column_is_backward_compatible() {
    let v1 = ecommerce_schema_v1();
    let v2 = ecommerce_schema_v2(); // adds nullable "phone" to users
    assert!(
        is_backward_compatible(&v1, &v2),
        "Adding nullable column should be backward compatible"
    );
}

/// Proof 5: Removing column is NOT backward compatible.
#[test]
fn removing_column_not_backward_compatible() {
    let v1 = ecommerce_schema_v1();
    let mut v2 = v1.clone();
    v2.version = 2;
    // Remove the "name" column from users
    if let Some(users) = v2.tables.get_mut("users") {
        users.columns.retain(|c| c.name != "name");
    }
    assert!(
        !is_backward_compatible(&v1, &v2),
        "Removing column should NOT be backward compatible"
    );
}

/// Proof 6: Adding a required (non-nullable, no default) column is NOT backward compatible.
#[test]
fn adding_required_column_not_backward_compatible() {
    let v1 = ecommerce_schema_v1();
    let mut v2 = v1.clone();
    v2.version = 2;
    if let Some(users) = v2.tables.get_mut("users") {
        users.columns.push(col("required_field", ColumnType::Text, false, false));
    }
    assert!(
        !is_backward_compatible(&v1, &v2),
        "Adding non-nullable column without default should NOT be backward compatible"
    );
}

/// Proof 7: Adding table is backward compatible.
#[test]
fn adding_table_is_backward_compatible() {
    let v1 = ecommerce_schema_v1();
    let mut v2 = v1.clone();
    v2.version = 2;
    v2.tables.insert(
        "audit_log".to_string(),
        Table {
            name: "audit_log".to_string(),
            columns: vec![
                col("id", ColumnType::Uuid, false, true),
                col("event", ColumnType::Text, false, false),
            ],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![],
        },
    );
    assert!(
        is_backward_compatible(&v1, &v2),
        "Adding a new table should be backward compatible"
    );
}

/// Proof 8: Primary keys always reference valid columns (proptest 500).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn primary_keys_always_exist(schema in arb_valid_schema()) {
        prop_assert!(
            check_primary_keys_exist(&schema).is_ok(),
            "Generated schema has invalid primary key"
        );
    }
}

/// Proof 9: No duplicate columns in generated schemas (proptest 500).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn no_duplicate_columns(schema in arb_valid_schema()) {
        prop_assert!(
            check_no_duplicate_columns(&schema).is_ok(),
            "Generated schema has duplicate columns"
        );
    }
}

/// Proof 10: Migration from v1 -> v2 computes the correct tables.
#[test]
fn migration_roundtrip_v1_to_v2() {
    let v1 = ecommerce_schema_v1();
    let v2 = ecommerce_schema_v2();
    let migration = compute_migration(&v1, &v2);

    // The added tables in migration should match the difference
    let v1_tables: std::collections::BTreeSet<&String> = v1.tables.keys().collect();
    let v2_tables: std::collections::BTreeSet<&String> = v2.tables.keys().collect();

    let expected_added: std::collections::BTreeSet<String> =
        v2_tables.difference(&v1_tables).map(|s| (*s).clone()).collect();
    let actual_added: std::collections::BTreeSet<String> =
        migration.added_tables.iter().cloned().collect();

    assert_eq!(expected_added, actual_added);
    assert!(migration.removed_tables.is_empty());
    assert!(migration.is_backward_compatible);
}

/// Proof 11: E-commerce schema (users, orders, products, payments) passes all invariants.
#[test]
fn ecommerce_schema_passes_all_invariants() {
    let schema = ecommerce_schema_v1();
    assert!(check_no_orphan_foreign_keys(&schema).is_ok(), "FK check failed");
    assert!(check_primary_keys_exist(&schema).is_ok(), "PK check failed");
    assert!(check_no_duplicate_columns(&schema).is_ok(), "duplicate column check failed");
    assert!(check_indexes_reference_valid_columns(&schema).is_ok(), "index check failed");
    assert!(check_all_schema_invariants(&schema).is_ok(), "all invariants check failed");
}

/// Proof 12: V2 e-commerce schema also passes all invariants.
#[test]
fn ecommerce_v2_passes_all_invariants() {
    let schema = ecommerce_schema_v2();
    assert!(check_all_schema_invariants(&schema).is_ok());
}

/// Proof 13: Schema serialization roundtrip preserves equality.
#[test]
fn schema_serialization_roundtrip() {
    let schema = ecommerce_schema_v1();
    let json = serde_json::to_string(&schema).expect("serialize");
    let deserialized: Schema = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(schema, deserialized);
}

/// Proof 14: Removing a table is NOT backward compatible.
#[test]
fn removing_table_not_backward_compatible() {
    let v1 = ecommerce_schema_v1();
    let mut v2 = v1.clone();
    v2.version = 2;
    v2.tables.remove("products");
    assert!(
        !is_backward_compatible(&v1, &v2),
        "Removing a table should NOT be backward compatible"
    );
}

/// Proof 15: FK referencing non-existent column in target table fails.
#[test]
fn fk_bad_target_column_fails() {
    let mut tables = BTreeMap::new();
    tables.insert(
        "users".to_string(),
        Table {
            name: "users".to_string(),
            columns: vec![col("id", ColumnType::Uuid, false, true)],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![],
        },
    );
    tables.insert(
        "orders".to_string(),
        Table {
            name: "orders".to_string(),
            columns: vec![
                col("id", ColumnType::Uuid, false, true),
                col("user_id", ColumnType::Uuid, false, false),
            ],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![ForeignKey {
                column: "user_id".to_string(),
                references_table: "users".to_string(),
                references_column: "nonexistent".to_string(), // does not exist
            }],
        },
    );
    let schema = Schema {
        name: "test".to_string(),
        version: 1,
        tables,
    };
    let result = check_no_orphan_foreign_keys(&schema);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not exist"));
}

/// Proof 16: Index referencing non-existent column fails.
#[test]
fn index_bad_column_fails() {
    let mut tables = BTreeMap::new();
    tables.insert(
        "users".to_string(),
        Table {
            name: "users".to_string(),
            columns: vec![col("id", ColumnType::Uuid, false, true)],
            primary_key: vec!["id".to_string()],
            indexes: vec![Index {
                name: "bad_index".to_string(),
                columns: vec!["nonexistent".to_string()],
                unique: false,
            }],
            foreign_keys: vec![],
        },
    );
    let schema = Schema {
        name: "test".to_string(),
        version: 1,
        tables,
    };
    assert!(check_indexes_reference_valid_columns(&schema).is_err());
}

/// Proof 17: Identical schemas produce empty migration.
#[test]
fn identical_schemas_empty_migration() {
    let schema = ecommerce_schema_v1();
    let migration = compute_migration(&schema, &schema);
    assert!(migration.added_tables.is_empty());
    assert!(migration.removed_tables.is_empty());
    assert!(migration.added_columns.is_empty());
    assert!(migration.removed_columns.is_empty());
    assert!(migration.is_backward_compatible);
}

/// Proof 18: FK referencing non-existent source column fails.
#[test]
fn fk_bad_source_column_fails() {
    let mut tables = BTreeMap::new();
    tables.insert(
        "users".to_string(),
        Table {
            name: "users".to_string(),
            columns: vec![col("id", ColumnType::Uuid, false, true)],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![],
        },
    );
    tables.insert(
        "orders".to_string(),
        Table {
            name: "orders".to_string(),
            columns: vec![
                col("id", ColumnType::Uuid, false, true),
                // Note: NO "user_id" column
            ],
            primary_key: vec!["id".to_string()],
            indexes: vec![],
            foreign_keys: vec![ForeignKey {
                column: "user_id".to_string(), // does not exist in this table
                references_table: "users".to_string(),
                references_column: "id".to_string(),
            }],
        },
    );
    let schema = Schema {
        name: "test".to_string(),
        version: 1,
        tables,
    };
    let result = check_no_orphan_foreign_keys(&schema);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not exist in the table"));
}
