// Optimized query functions for event database

use rusqlite::{Connection, params, Row};
use chrono::{DateTime, Utc};
use serde_json;
use crate::sensors::SecurityEvent;

/// Query builder for complex event searches
pub struct EventQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub event_types: Vec<String>,
    pub severities: Vec<String>,
    pub hostname: Option<String>,
    pub process_name: Option<String>,
    pub limit: usize,
    pub offset: usize,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            event_types: Vec::new(),
            severities: Vec::new(),
            hostname: None,
            process_name: None,
            limit: 100,
            offset: 0,
        }
    }
}

impl EventQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_time_range(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.start_time = Some(start);
        self.end_time = Some(end);
        self
    }

    pub fn with_event_types(mut self, types: Vec<String>) -> Self {
        self.event_types = types;
        self
    }

    pub fn with_severities(mut self, severities: Vec<String>) -> Self {
        self.severities = severities;
        self
    }

    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn with_process_name(mut self, name: String) -> Self {
        self.process_name = Some(name);
        self
    }

    pub fn with_pagination(mut self, limit: usize, offset: usize) -> Self {
        self.limit = limit;
        self.offset = offset;
        self
    }

    /// Build SQL query from parameters
    pub fn build_sql(&self) -> (String, Vec<String>) {
        let mut sql = String::from("SELECT raw_data FROM events WHERE 1=1");
        let mut params = Vec::new();

        if let Some(start) = &self.start_time {
            sql.push_str(" AND timestamp >= ?");
            params.push(start.to_rfc3339());
        }

        if let Some(end) = &self.end_time {
            sql.push_str(" AND timestamp <= ?");
            params.push(end.to_rfc3339());
        }

        if !self.event_types.is_empty() {
            let placeholders = vec!["?"; self.event_types.len()].join(",");
            sql.push_str(&format!(" AND event_type IN ({})", placeholders));
            params.extend(self.event_types.clone());
        }

        if !self.severities.is_empty() {
            let placeholders = vec!["?"; self.severities.len()].join(",");
            sql.push_str(&format!(" AND severity IN ({})", placeholders));
            params.extend(self.severities.clone());
        }

        if let Some(hostname) = &self.hostname {
            sql.push_str(" AND hostname = ?");
            params.push(hostname.clone());
        }

        if let Some(process_name) = &self.process_name {
            sql.push_str(" AND process_name LIKE ?");
            params.push(format!("%{}%", process_name));
        }

        sql.push_str(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.push(self.limit.to_string());
        params.push(self.offset.to_string());

        (sql, params)
    }

    /// Execute query and return events
    pub fn execute(&self, conn: &Connection) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
        let (sql, param_values) = self.build_sql();

        let mut stmt = conn.prepare(&sql)?;

        // Convert Vec<String> to Vec<&dyn ToSql>
        let params_refs: Vec<&dyn rusqlite::ToSql> = param_values
            .iter()
            .map(|s| s as &dyn rusqlite::ToSql)
            .collect();

        let events = stmt.query_map(params_refs.as_slice(), |row| {
            let json: String = row.get(0)?;
            serde_json::from_str(&json)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))
        })?;

        events.collect()
    }
}

/// Event statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventStats {
    pub total_events: i64,
    pub events_by_severity: std::collections::HashMap<String, i64>,
    pub events_by_type: std::collections::HashMap<String, i64>,
    pub events_last_24h: i64,
    pub events_last_7d: i64,
    pub top_processes: Vec<(String, i64)>,
    pub top_hosts: Vec<(String, i64)>,
}

/// Get comprehensive event statistics
pub fn get_event_statistics(conn: &Connection) -> Result<EventStats, rusqlite::Error> {
    // Total events
    let total_events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events",
        [],
        |row| row.get(0)
    )?;

    // Events by severity
    let mut events_by_severity = std::collections::HashMap::new();
    let mut stmt = conn.prepare("SELECT severity, COUNT(*) FROM events GROUP BY severity")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (severity, count) = row?;
        events_by_severity.insert(severity, count);
    }

    // Events by type
    let mut events_by_type = std::collections::HashMap::new();
    let mut stmt = conn.prepare("SELECT event_type, COUNT(*) FROM events GROUP BY event_type")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (event_type, count) = row?;
        events_by_type.insert(event_type, count);
    }

    // Events in last 24 hours
    let now = Utc::now();
    let yesterday = now - chrono::Duration::hours(24);
    let events_last_24h: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
        params![yesterday.to_rfc3339()],
        |row| row.get(0)
    )?;

    // Events in last 7 days
    let last_week = now - chrono::Duration::days(7);
    let events_last_7d: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
        params![last_week.to_rfc3339()],
        |row| row.get(0)
    )?;

    // Top processes
    let mut top_processes = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT process_name, COUNT(*) as count FROM events
         WHERE process_name IS NOT NULL
         GROUP BY process_name
         ORDER BY count DESC
         LIMIT 10"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        top_processes.push(row?);
    }

    // Top hosts
    let mut top_hosts = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT hostname, COUNT(*) as count FROM events
         GROUP BY hostname
         ORDER BY count DESC
         LIMIT 10"
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        top_hosts.push(row?);
    }

    Ok(EventStats {
        total_events,
        events_by_severity,
        events_by_type,
        events_last_24h,
        events_last_7d,
        top_processes,
        top_hosts,
    })
}

/// Get event timeline data for visualization
pub fn get_event_timeline(
    conn: &Connection,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    bucket_size_minutes: i64,
) -> Result<Vec<(DateTime<Utc>, i64)>, rusqlite::Error> {
    // This is a simplified version - for production you'd want bucketing logic
    let mut stmt = conn.prepare(
        "SELECT timestamp, COUNT(*)
         FROM events
         WHERE timestamp >= ? AND timestamp <= ?
         GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
         ORDER BY timestamp"
    )?;

    let rows = stmt.query_map(
        params![start.to_rfc3339(), end.to_rfc3339()],
        |row| {
            let timestamp_str: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(Utc::now());
            Ok((timestamp, count))
        }
    )?;

    rows.collect()
}

/// Batch insert events for performance
pub fn batch_insert_events(
    conn: &Connection,
    events: &[crate::sensors::SecurityEvent],
) -> Result<(), rusqlite::Error> {
    let tx = conn.unchecked_transaction()?;

    {
        let mut stmt = tx.prepare(
            "INSERT INTO events (
                event_id, timestamp, event_type, os, hostname, severity,
                process_id, process_name, file_path, network_dest,
                user_name, raw_data, tags
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
        )?;

        for event in events {
            let event_json = serde_json::to_string(event)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            stmt.execute(params![
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
            ])?;
        }
    }

    tx.commit()?;
    Ok(())
}

/// Get events related to a specific incident
pub fn get_incident_events(
    conn: &Connection,
    incident_id: &str,
) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
    // Get event IDs from incident
    let event_ids: String = conn.query_row(
        "SELECT event_ids FROM incidents WHERE incident_id = ?",
        params![incident_id],
        |row| row.get(0)
    )?;

    let event_id_list: Vec<&str> = event_ids.split(',').collect();

    if event_id_list.is_empty() {
        return Ok(Vec::new());
    }

    // Build query with placeholders
    let placeholders = vec!["?"; event_id_list.len()].join(",");
    let sql = format!(
        "SELECT raw_data FROM events WHERE event_id IN ({}) ORDER BY timestamp",
        placeholders
    );

    let mut stmt = conn.prepare(&sql)?;

    let params_refs: Vec<&dyn rusqlite::ToSql> = event_id_list
        .iter()
        .map(|s| s as &dyn rusqlite::ToSql)
        .collect();

    let events = stmt.query_map(params_refs.as_slice(), |row| {
        let json: String = row.get(0)?;
        serde_json::from_str(&json)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(e),
            ))
    })?;

    events.collect()
}

/// Prune old events (for compliance/storage management)
pub fn prune_events_older_than(
    conn: &Connection,
    cutoff: DateTime<Utc>,
) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "DELETE FROM events WHERE timestamp < ?",
        params![cutoff.to_rfc3339()],
    )
}

/// Search events by full-text query (simple LIKE-based)
pub fn search_events(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<SecurityEvent>, rusqlite::Error> {
    let search_pattern = format!("%{}%", query);

    let mut stmt = conn.prepare(
        "SELECT raw_data FROM events
         WHERE raw_data LIKE ?
         OR process_name LIKE ?
         OR file_path LIKE ?
         ORDER BY timestamp DESC
         LIMIT ?"
    )?;

    let events = stmt.query_map(
        params![&search_pattern, &search_pattern, &search_pattern, limit],
        |row| {
            let json: String = row.get(0)?;
            serde_json::from_str(&json)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))
        }
    )?;

    events.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use crate::storage::schema;
    use crate::sensors::{SecurityEvent, EventType};

    #[test]
    fn test_event_query_builder() {
        let query = EventQuery::new()
            .with_severities(vec!["High".to_string(), "Critical".to_string()])
            .with_pagination(50, 0);

        let (sql, params) = query.build_sql();
        assert!(sql.contains("severity IN"));
        assert_eq!(params.len(), 4); // 2 severities + limit + offset
    }

    #[test]
    fn test_batch_insert() {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();

        let events = vec![
            SecurityEvent::new(EventType::ProcessCreated),
            SecurityEvent::new(EventType::FileCreated),
        ];

        assert!(batch_insert_events(&conn, &events).is_ok());

        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_event_statistics() {
        let conn = Connection::open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();

        // Insert some test data
        let events = vec![
            SecurityEvent::new(EventType::ProcessCreated),
            SecurityEvent::new(EventType::NetworkConnection),
        ];
        batch_insert_events(&conn, &events).unwrap();

        let stats = get_event_statistics(&conn).unwrap();
        assert_eq!(stats.total_events, 2);
    }
}
