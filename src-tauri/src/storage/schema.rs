// Database schema definitions for evidence-grade event storage

use rusqlite::Connection;

/// Create all database tables with indices for performance
pub fn create_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    // Events table - immutable security events
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            os TEXT NOT NULL,
            hostname TEXT NOT NULL,
            severity TEXT NOT NULL,
            process_id INTEGER,
            process_name TEXT,
            file_path TEXT,
            network_dest TEXT,
            user_name TEXT,
            raw_data TEXT NOT NULL,
            tags TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    // Indices for fast queries on events
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name)",
        [],
    )?;

    // Incidents table - correlated event groups
    conn.execute(
        "CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            mitre_tactics TEXT,
            mitre_techniques TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            resolved_at TEXT,
            resolved_by TEXT,
            event_ids TEXT NOT NULL,
            metadata TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)",
        [],
    )?;

    // Alerts table - alert history with acknowledgment tracking
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            event_id TEXT,
            incident_id TEXT,
            acknowledged BOOLEAN DEFAULT 0,
            acknowledged_at TEXT,
            acknowledged_by TEXT,
            notes TEXT,
            metadata TEXT,
            FOREIGN KEY (event_id) REFERENCES events(event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
        [],
    )?;

    // Baselines table - behavioral baselines for anomaly detection
    conn.execute(
        "CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            process_name TEXT NOT NULL UNIQUE,
            normal_cpu_usage REAL NOT NULL DEFAULT 0.0,
            normal_memory_usage REAL NOT NULL DEFAULT 0.0,
            normal_network_usage REAL NOT NULL DEFAULT 0.0,
            normal_file_operations REAL NOT NULL DEFAULT 0.0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_updated TEXT NOT NULL,
            metadata TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_baselines_process ON baselines(process_name)",
        [],
    )?;

    // Policies table - remediation policies and audit trail
    conn.execute(
        "CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            policy_id TEXT NOT NULL UNIQUE,
            policy_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            config_before TEXT,
            config_after TEXT,
            applied_at TEXT,
            applied_by TEXT,
            reverted_at TEXT,
            reverted_by TEXT,
            status TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(policy_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status)",
        [],
    )?;

    // Threat intelligence cache table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS threat_intel_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_type TEXT NOT NULL,
            indicator_value TEXT NOT NULL UNIQUE,
            reputation_score REAL,
            is_malicious BOOLEAN DEFAULT 0,
            source TEXT NOT NULL,
            metadata TEXT,
            cached_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intel_cache(indicator_value)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_threat_intel_expires ON threat_intel_cache(expires_at)",
        [],
    )?;

    // Detection rules table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL UNIQUE,
            rule_name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            os_filter TEXT,
            mitre_tactics TEXT,
            mitre_techniques TEXT,
            rule_definition TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rules_enabled ON detection_rules(enabled)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rules_type ON detection_rules(rule_type)",
        [],
    )?;

    // Remediation actions audit log
    conn.execute(
        "CREATE TABLE IF NOT EXISTS remediation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT NOT NULL UNIQUE,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL,
            preview_diff TEXT,
            rollback_data TEXT,
            executed_at TEXT,
            executed_by TEXT,
            reverted_at TEXT,
            reverted_by TEXT,
            incident_id TEXT,
            metadata TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(incident_id)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_log(status)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_remediation_executed ON remediation_log(executed_at)",
        [],
    )?;

    // Vulnerability findings table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_id TEXT NOT NULL UNIQUE,
            cve_id TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            affected_package TEXT,
            affected_version TEXT,
            fixed_version TEXT,
            discovered_at TEXT NOT NULL,
            resolved_at TEXT,
            status TEXT NOT NULL,
            metadata TEXT
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id)",
        [],
    )?;

    // System inventory table (packages, services, etc.)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_type TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT,
            status TEXT,
            metadata TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(item_type, name)
        )",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inventory_type ON inventory(item_type)",
        [],
    )?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_inventory_name ON inventory(name)",
        [],
    )?;

    Ok(())
}

/// Drop all tables (for testing/reset only)
#[allow(dead_code)]
pub fn drop_all_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute("DROP TABLE IF EXISTS events", [])?;
    conn.execute("DROP TABLE IF EXISTS incidents", [])?;
    conn.execute("DROP TABLE IF EXISTS alerts", [])?;
    conn.execute("DROP TABLE IF EXISTS baselines", [])?;
    conn.execute("DROP TABLE IF EXISTS policies", [])?;
    conn.execute("DROP TABLE IF EXISTS threat_intel_cache", [])?;
    conn.execute("DROP TABLE IF EXISTS detection_rules", [])?;
    conn.execute("DROP TABLE IF EXISTS remediation_log", [])?;
    conn.execute("DROP TABLE IF EXISTS vulnerabilities", [])?;
    conn.execute("DROP TABLE IF EXISTS inventory", [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn test_schema_creation() {
        let conn = Connection::open_in_memory().expect("Failed to create in-memory database for test");
        assert!(create_tables(&conn).is_ok());

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .expect("Failed to prepare SQL statement")
            .query_map([], |row| row.get(0))
            .expect("Failed to query tables")
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to collect table names");

        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"incidents".to_string()));
        assert!(tables.contains(&"alerts".to_string()));
        assert!(tables.contains(&"baselines".to_string()));
        assert!(tables.contains(&"policies".to_string()));
    }

    #[test]
    fn test_schema_idempotent() {
        let conn = Connection::open_in_memory().expect("Failed to create in-memory database for test");
        assert!(create_tables(&conn).is_ok());
        // Should succeed on second call (IF NOT EXISTS)
        assert!(create_tables(&conn).is_ok());
    }
}
