//! Database schema simulation — prove migrations are safe.
//!
//! Define schemas as Rust types. Prove migration safety.
//! The same convergence model applies: declare schema -> prove invariants
//! -> render to SQL/MongoDB/DynamoDB -> migrate safely.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A database schema at a specific version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    pub version: u32,
    pub tables: BTreeMap<String, Table>,
}

/// A database table with columns, primary key, indexes, and foreign keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub primary_key: Vec<String>,
    pub indexes: Vec<Index>,
    pub foreign_keys: Vec<ForeignKey>,
}

/// A column in a table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub col_type: ColumnType,
    pub nullable: bool,
    pub has_default: bool,
}

/// Supported column types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColumnType {
    Text,
    Integer,
    Boolean,
    Timestamp,
    Uuid,
    Json,
    Float,
}

/// A database index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
}

/// A foreign key constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignKey {
    pub column: String,
    pub references_table: String,
    pub references_column: String,
}

/// Schema migration — diff between two schema versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaMigration {
    pub from_version: u32,
    pub to_version: u32,
    pub added_tables: Vec<String>,
    pub removed_tables: Vec<String>,
    pub added_columns: Vec<(String, String)>,
    pub removed_columns: Vec<(String, String)>,
    pub is_backward_compatible: bool,
}

/// Compute migration between two schemas.
///
/// Determines which tables/columns were added or removed, and
/// whether the migration is backward compatible.
#[must_use]
pub fn compute_migration(from: &Schema, to: &Schema) -> SchemaMigration {
    let from_tables: BTreeSet<&String> = from.tables.keys().collect();
    let to_tables: BTreeSet<&String> = to.tables.keys().collect();

    let added_tables: Vec<String> = to_tables.difference(&from_tables).map(|s| (*s).clone()).collect();
    let removed_tables: Vec<String> = from_tables.difference(&to_tables).map(|s| (*s).clone()).collect();

    let mut added_columns: Vec<(String, String)> = Vec::new();
    let mut removed_columns: Vec<(String, String)> = Vec::new();

    // For tables that exist in both versions, diff columns
    for table_name in from_tables.intersection(&to_tables) {
        let from_table = &from.tables[*table_name];
        let to_table = &to.tables[*table_name];

        let from_cols: BTreeSet<&String> = from_table.columns.iter().map(|c| &c.name).collect();
        let to_cols: BTreeSet<&String> = to_table.columns.iter().map(|c| &c.name).collect();

        for col in to_cols.difference(&from_cols) {
            added_columns.push(((*table_name).clone(), (*col).clone()));
        }
        for col in from_cols.difference(&to_cols) {
            removed_columns.push(((*table_name).clone(), (*col).clone()));
        }
    }

    // For added tables, all their columns are "added"
    for table_name in &added_tables {
        if let Some(table) = to.tables.get(table_name) {
            for col in &table.columns {
                added_columns.push((table_name.clone(), col.name.clone()));
            }
        }
    }

    // For removed tables, all their columns are "removed"
    for table_name in &removed_tables {
        if let Some(table) = from.tables.get(table_name) {
            for col in &table.columns {
                removed_columns.push((table_name.clone(), col.name.clone()));
            }
        }
    }

    let is_backward_compatible = is_backward_compatible(from, to);

    SchemaMigration {
        from_version: from.version,
        to_version: to.version,
        added_tables,
        removed_tables,
        added_columns,
        removed_columns,
        is_backward_compatible,
    }
}

/// Check that no foreign key references a non-existent table or column.
///
/// # Errors
///
/// Returns an error string describing the orphan foreign key if found.
pub fn check_no_orphan_foreign_keys(schema: &Schema) -> Result<(), String> {
    for (table_name, table) in &schema.tables {
        for fk in &table.foreign_keys {
            // Check that the referenced table exists
            let Some(ref_table) = schema.tables.get(&fk.references_table) else {
                return Err(format!(
                    "Table '{}' FK on column '{}' references non-existent table '{}'",
                    table_name, fk.column, fk.references_table
                ));
            };

            // Check that the source column exists in this table
            if !table.columns.iter().any(|c| c.name == fk.column) {
                return Err(format!(
                    "Table '{}' FK references column '{}' which does not exist in the table",
                    table_name, fk.column
                ));
            }

            // Check that the referenced column exists in the target table
            if !ref_table.columns.iter().any(|c| c.name == fk.references_column) {
                return Err(format!(
                    "Table '{}' FK on column '{}' references column '{}' in table '{}' which does not exist",
                    table_name, fk.column, fk.references_column, fk.references_table
                ));
            }
        }
    }
    Ok(())
}

/// Check that all primary key columns exist in their respective tables.
///
/// # Errors
///
/// Returns an error string describing the missing primary key column.
pub fn check_primary_keys_exist(schema: &Schema) -> Result<(), String> {
    for (table_name, table) in &schema.tables {
        for pk_col in &table.primary_key {
            if !table.columns.iter().any(|c| &c.name == pk_col) {
                return Err(format!(
                    "Table '{}' primary key column '{}' does not exist",
                    table_name, pk_col
                ));
            }
        }
    }
    Ok(())
}

/// Check that no table has duplicate column names.
///
/// # Errors
///
/// Returns an error string describing the duplicate column.
pub fn check_no_duplicate_columns(schema: &Schema) -> Result<(), String> {
    for (table_name, table) in &schema.tables {
        let mut seen = BTreeSet::new();
        for col in &table.columns {
            if !seen.insert(&col.name) {
                return Err(format!(
                    "Table '{}' has duplicate column '{}'",
                    table_name, col.name
                ));
            }
        }
    }
    Ok(())
}

/// Check that all indexes reference columns that exist in the table.
///
/// # Errors
///
/// Returns an error string describing the invalid index column reference.
pub fn check_indexes_reference_valid_columns(schema: &Schema) -> Result<(), String> {
    for (table_name, table) in &schema.tables {
        let col_names: BTreeSet<&String> = table.columns.iter().map(|c| &c.name).collect();
        for index in &table.indexes {
            for idx_col in &index.columns {
                if !col_names.contains(idx_col) {
                    return Err(format!(
                        "Table '{}' index '{}' references non-existent column '{}'",
                        table_name, index.name, idx_col
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Check if a schema migration is backward compatible.
///
/// A migration is backward compatible if:
/// - No tables are removed
/// - No columns are removed from existing tables
/// - Any added columns are nullable or have defaults
#[must_use]
pub fn is_backward_compatible(from: &Schema, to: &Schema) -> bool {
    let from_tables: BTreeSet<&String> = from.tables.keys().collect();
    let to_tables: BTreeSet<&String> = to.tables.keys().collect();

    // Removing tables is not backward compatible
    if from_tables.difference(&to_tables).next().is_some() {
        return false;
    }

    // Check columns in tables that exist in both versions
    for table_name in from_tables.intersection(&to_tables) {
        let from_table = &from.tables[*table_name];
        let to_table = &to.tables[*table_name];

        let from_cols: BTreeSet<&String> = from_table.columns.iter().map(|c| &c.name).collect();
        let to_cols: BTreeSet<&String> = to_table.columns.iter().map(|c| &c.name).collect();

        // Removing columns is not backward compatible
        if from_cols.difference(&to_cols).next().is_some() {
            return false;
        }

        // Added columns must be nullable or have defaults
        for col_name in to_cols.difference(&from_cols) {
            if let Some(col) = to_table.columns.iter().find(|c| &c.name == *col_name) {
                if !col.nullable && !col.has_default {
                    return false;
                }
            }
        }
    }

    true
}

/// Run all schema invariant checks.
///
/// # Errors
///
/// Returns the first invariant violation found.
pub fn check_all_schema_invariants(schema: &Schema) -> Result<(), String> {
    check_no_orphan_foreign_keys(schema)?;
    check_primary_keys_exist(schema)?;
    check_no_duplicate_columns(schema)?;
    check_indexes_reference_valid_columns(schema)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_schema() -> Schema {
        let mut tables = BTreeMap::new();
        tables.insert(
            "users".to_string(),
            Table {
                name: "users".to_string(),
                columns: vec![
                    Column { name: "id".to_string(), col_type: ColumnType::Uuid, nullable: false, has_default: true },
                    Column { name: "email".to_string(), col_type: ColumnType::Text, nullable: false, has_default: false },
                ],
                primary_key: vec!["id".to_string()],
                indexes: vec![
                    Index { name: "idx_users_email".to_string(), columns: vec!["email".to_string()], unique: true },
                ],
                foreign_keys: vec![],
            },
        );
        Schema {
            name: "test".to_string(),
            version: 1,
            tables,
        }
    }

    #[test]
    fn simple_schema_passes_all_checks() {
        let schema = simple_schema();
        assert!(check_all_schema_invariants(&schema).is_ok());
    }

    #[test]
    fn compute_migration_identical_schemas() {
        let schema = simple_schema();
        let migration = compute_migration(&schema, &schema);
        assert!(migration.added_tables.is_empty());
        assert!(migration.removed_tables.is_empty());
        assert!(migration.added_columns.is_empty());
        assert!(migration.removed_columns.is_empty());
        assert!(migration.is_backward_compatible);
    }
}
