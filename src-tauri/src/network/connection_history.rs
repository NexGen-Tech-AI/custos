// Network Connection History - Query and analyze historical connections

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use crate::sensors::{SecurityEvent, EventType};
use crate::storage::EventDatabase;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnectionRecord {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub local_ip: Option<String>,
    pub local_port: Option<u16>,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub direction: String,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub duration_seconds: Option<u64>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub process_name: String,
    pub process_id: Option<u32>,
    pub connection_count: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub unique_destinations: usize,
    pub suspicious_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub total_connections: usize,
    pub unique_processes: usize,
    pub unique_destinations: usize,
    pub suspicious_connections: usize,
    pub top_ports: Vec<(u16, usize)>,
    pub top_protocols: Vec<(String, usize)>,
}

pub struct ConnectionHistoryManager {
    db: Option<EventDatabase>,
}

impl ConnectionHistoryManager {
    pub fn new(db: EventDatabase) -> Self {
        Self { db: Some(db) }
    }

    pub fn new_without_db() -> Self {
        Self { db: None }
    }

    /// Get connection history for a time range
    pub fn get_connections(
        &self,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<NetworkConnectionRecord>, String> {
        if let Some(ref db) = self.db {
            let events = db
                .query_events(start_time, end_time, limit)
                .map_err(|e| e.to_string())?;

            let connections: Vec<NetworkConnectionRecord> = events
                .iter()
                .filter(|e| e.event_type == EventType::NetworkConnection)
                .map(Self::event_to_record)
                .collect();

            Ok(connections)
        } else {
            Ok(Vec::new())
        }
    }

    /// Get recent connections (last N hours)
    pub fn get_recent_connections(&self, hours: u64, limit: usize) -> Result<Vec<NetworkConnectionRecord>, String> {
        let end_time = Utc::now();
        let start_time = end_time - chrono::Duration::hours(hours as i64);
        self.get_connections(start_time, end_time, limit)
    }

    /// Get connections for a specific process
    pub fn get_process_connections(
        &self,
        process_name: &str,
        hours: u64,
    ) -> Result<Vec<NetworkConnectionRecord>, String> {
        let connections = self.get_recent_connections(hours, 10000)?;
        Ok(connections
            .into_iter()
            .filter(|c| {
                if let Some(ref pname) = c.process_name {
                    pname.contains(process_name)
                } else {
                    false
                }
            })
            .collect())
    }

    /// Get top talkers (processes with most network activity)
    pub fn get_top_talkers(&self, limit: usize, hours: u64) -> Result<Vec<TopTalker>, String> {
        use std::collections::HashMap;

        let connections = self.get_recent_connections(hours, 100000)?;

        let mut process_stats: HashMap<String, TopTalker> = HashMap::new();

        for conn in connections {
            if let Some(ref pname) = conn.process_name {
                let entry = process_stats.entry(pname.clone()).or_insert(TopTalker {
                    process_name: pname.clone(),
                    process_id: conn.process_id,
                    connection_count: 0,
                    total_bytes_sent: 0,
                    total_bytes_received: 0,
                    unique_destinations: 0,
                    suspicious_connections: 0,
                });

                entry.connection_count += 1;
                entry.total_bytes_sent += conn.bytes_sent.unwrap_or(0);
                entry.total_bytes_received += conn.bytes_received.unwrap_or(0);
            }
        }

        let mut talkers: Vec<TopTalker> = process_stats.into_values().collect();
        talkers.sort_by(|a, b| {
            (b.total_bytes_sent + b.total_bytes_received)
                .cmp(&(a.total_bytes_sent + a.total_bytes_received))
        });
        talkers.truncate(limit);

        Ok(talkers)
    }

    /// Get connection statistics
    pub fn get_stats(&self, hours: u64) -> Result<ConnectionStats, String> {
        use std::collections::{HashMap, HashSet};

        let connections = self.get_recent_connections(hours, 100000)?;

        let mut unique_processes = HashSet::new();
        let mut unique_destinations = HashSet::new();
        let mut port_counts: HashMap<u16, usize> = HashMap::new();
        let mut protocol_counts: HashMap<String, usize> = HashMap::new();

        for conn in &connections {
            if let Some(ref pname) = conn.process_name {
                unique_processes.insert(pname.clone());
            }
            unique_destinations.insert(conn.remote_ip.clone());
            *port_counts.entry(conn.remote_port).or_insert(0) += 1;
            *protocol_counts.entry(conn.protocol.clone()).or_insert(0) += 1;
        }

        let mut top_ports: Vec<(u16, usize)> = port_counts.into_iter().collect();
        top_ports.sort_by(|a, b| b.1.cmp(&a.1));
        top_ports.truncate(10);

        let mut top_protocols: Vec<(String, usize)> = protocol_counts.into_iter().collect();
        top_protocols.sort_by(|a, b| b.1.cmp(&a.1));

        Ok(ConnectionStats {
            total_connections: connections.len(),
            unique_processes: unique_processes.len(),
            unique_destinations: unique_destinations.len(),
            suspicious_connections: 0,  // TODO: Implement suspicious connection detection
            top_ports,
            top_protocols,
        })
    }

    /// Convert SecurityEvent to NetworkConnectionRecord
    fn event_to_record(event: &SecurityEvent) -> NetworkConnectionRecord {
        let network = event.network.as_ref();

        NetworkConnectionRecord {
            id: event.id.clone(),
            timestamp: event.timestamp,
            process_id: event.process.as_ref().map(|p| p.pid),
            process_name: event.process.as_ref().map(|p| p.name.clone()),
            local_ip: network.and_then(|n| n.source_ip.clone()),
            local_port: network.and_then(|n| n.source_port),
            remote_ip: network.map(|n| n.destination_ip.clone()).unwrap_or_default(),
            remote_port: network.map(|n| n.destination_port).unwrap_or(0),
            protocol: network.map(|n| n.protocol.clone()).unwrap_or_default(),
            direction: network
                .map(|n| format!("{:?}", n.direction))
                .unwrap_or_default(),
            bytes_sent: network.and_then(|n| n.bytes_sent),
            bytes_received: network.and_then(|n| n.bytes_received),
            duration_seconds: None,  // Not currently tracked
            state: None,             // Not currently tracked in events
        }
    }
}

impl Default for ConnectionHistoryManager {
    fn default() -> Self {
        Self::new_without_db()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_history_without_db() {
        let manager = ConnectionHistoryManager::new_without_db();
        let result = manager.get_recent_connections(1, 100);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
