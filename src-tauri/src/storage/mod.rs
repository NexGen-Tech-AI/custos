// Event Storage Layer - SQLite for events, alerts, incidents
// Evidence-grade: immutable events, cryptographic integrity

use rusqlite::{Connection, params};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use parking_lot::Mutex;
use chrono::{DateTime, Utc};
use crate::sensors::SecurityEvent;

pub mod schema;
pub mod queries;

/// Event database manager
pub struct EventDatabase {
    conn: Arc<Mutex<Connection>>,
}

impl EventDatabase {
    /// Create new database connection
    pub fn new(db_path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;

        // Initialize schema
        schema::create_tables(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Create in-memory database (for testing)
    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        schema::create_tables(&conn)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Insert a security event (immutable)
    pub fn insert_event(&self, event: &SecurityEvent) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();

        // Serialize event to JSON for full storage
        let event_json = serde_json::to_string(event)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        conn.execute(
            "INSERT INTO events (
                event_id, timestamp, event_type, os, hostname, severity,
                process_id, process_name, file_path, network_dest,
                user_name, raw_data, tags
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                format!("{:?}", event.event_type),
                format!("{:?}", event.os),
                event.hostname,
                format!("{:?}", event.severity),
                event.process.as_ref().map(|p| p.pid as i64),
                event.process.as_ref().map(|p| p.name.as_str()),
                event.file.as_ref().map(|f| f.path.as_str()),
                event.network.as_ref().map(|n| n.destination_ip.as_str()),
                event.identity.as_ref().map(|i| i.user.as_str()),
                event_json,
                event.tags.join(","),
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Query events by time range
    pub fn query_events(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT raw_data FROM events
             WHERE timestamp >= ?1 AND timestamp <= ?2
             ORDER BY timestamp DESC LIMIT ?3"
        )?;

        let events = stmt.query_map(
            params![start_time.to_rfc3339(), end_time.to_rfc3339(), limit],
            |row| {
                let json: String = row.get(0)?;
                serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ))
            },
        )?;

        events.collect()
    }

    /// Query events by event type
    pub fn query_by_type(
        &self,
        event_type: &str,
        limit: usize,
    ) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT raw_data FROM events
             WHERE event_type = ?1
             ORDER BY timestamp DESC LIMIT ?2"
        )?;

        let events = stmt.query_map(
            params![event_type, limit],
            |row| {
                let json: String = row.get(0)?;
                serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ))
            },
        )?;

        events.collect()
    }

    /// Query suspicious events
    pub fn query_suspicious(&self, limit: usize) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT raw_data FROM events
             WHERE severity IN ('High', 'Critical')
             ORDER BY timestamp DESC LIMIT ?1"
        )?;

        let events = stmt.query_map(
            params![limit],
            |row| {
                let json: String = row.get(0)?;
                serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    ))
            },
        )?;

        events.collect()
    }

    /// Get event count
    pub fn count_events(&self) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Create incident from correlated events
    pub fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
        event_ids: &[String],
    ) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();

        conn.execute(
            "INSERT INTO incidents (
                incident_id, title, description, severity, status,
                created_at, event_ids
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                uuid::Uuid::new_v4().to_string(),
                title,
                description,
                severity,
                "Active",
                Utc::now().to_rfc3339(),
                event_ids.join(","),
            ],
        )?;

        Ok(conn.last_insert_rowid())
    }

    /// Get all active incidents
    pub fn get_active_incidents(&self) -> Result<Vec<Incident>, rusqlite::Error> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT incident_id, title, description, severity, status, created_at, event_ids
             FROM incidents
             WHERE status = 'Active'
             ORDER BY created_at DESC"
        )?;

        let incidents = stmt.query_map([], |row| {
            Ok(Incident {
                incident_id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                severity: row.get(3)?,
                status: row.get(4)?,
                created_at: row.get(5)?,
                event_ids: row.get::<_, String>(6)?
                    .split(',')
                    .map(String::from)
                    .collect(),
            })
        })?;

        incidents.collect()
    }
}

/// Incident record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub incident_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub status: String,
    pub created_at: String,
    pub event_ids: Vec<String>,
}
