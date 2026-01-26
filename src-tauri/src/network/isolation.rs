// Network Isolation - Containment and firewall controls
// Linux: iptables/nftables
// Windows: netsh advfirewall

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IsolationAction {
    TemporaryIsolate {
        hostname: String,
        duration_minutes: u32,
    },
    BlockDestination {
        ip: String,
        duration_minutes: Option<u32>,
    },
    BlockASN {
        asn: u32,
        duration_minutes: Option<u32>,
    },
    BlockPort {
        port: u16,
        protocol: String,
    },
    BlockDomain {
        domain: String,
        duration_minutes: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionPreview {
    pub action: IsolationAction,
    pub affected_connections: usize,
    pub affected_processes: Vec<String>,
    pub will_break: Vec<String>,
    pub reversible: bool,
    pub recommended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action_id: String,
    pub action: IsolationAction,
    pub executed_at: DateTime<Utc>,
    pub executed_by: String,
    pub success: bool,
    pub rollback_info: Option<RollbackInfo>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackInfo {
    pub action_id: String,
    pub original_rules: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationRecord {
    pub id: String,
    pub action: IsolationAction,
    pub executed_at: DateTime<Utc>,
    pub executed_by: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub rolled_back_at: Option<DateTime<Utc>>,
    pub status: IsolationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IsolationStatus {
    Active,
    Expired,
    RolledBack,
}

pub struct IsolationManager {
    records: Vec<IsolationRecord>,
}

impl IsolationManager {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Preview what an action will do
    pub fn preview_action(&self, action: &IsolationAction) -> ActionPreview {
        match action {
            IsolationAction::TemporaryIsolate { hostname, .. } => ActionPreview {
                action: action.clone(),
                affected_connections: 0,  // TODO: Query active connections
                affected_processes: vec![],
                will_break: vec![
                    format!("All network access from {} will be blocked", hostname),
                    "SSH/RDP access will be lost".to_string(),
                ],
                reversible: true,
                recommended: true,
            },
            IsolationAction::BlockDestination { ip, .. } => ActionPreview {
                action: action.clone(),
                affected_connections: 0,
                affected_processes: vec![],
                will_break: vec![format!("All connections to {} will be blocked", ip)],
                reversible: true,
                recommended: true,
            },
            IsolationAction::BlockASN { asn, .. } => ActionPreview {
                action: action.clone(),
                affected_connections: 0,
                affected_processes: vec![],
                will_break: vec![format!(
                    "All connections to AS{} IP ranges will be blocked",
                    asn
                )],
                reversible: true,
                recommended: false,  // ASN blocks are broad
            },
            IsolationAction::BlockPort { port, protocol } => ActionPreview {
                action: action.clone(),
                affected_connections: 0,
                affected_processes: vec![],
                will_break: vec![format!("All {} connections on port {} will be blocked", protocol, port)],
                reversible: true,
                recommended: true,
            },
            IsolationAction::BlockDomain { domain, .. } => ActionPreview {
                action: action.clone(),
                affected_connections: 0,
                affected_processes: vec![],
                will_break: vec![format!("All connections to {} will be blocked", domain)],
                reversible: true,
                recommended: true,
            },
        }
    }

    /// Execute an isolation action
    pub fn execute_action(
        &mut self,
        action: IsolationAction,
        user: String,
    ) -> Result<ActionResult, String> {
        let action_id = uuid::Uuid::new_v4().to_string();
        let executed_at = Utc::now();

        // Get rollback info before executing
        let rollback_info = self.prepare_rollback(&action)?;

        // Execute the action based on OS
        let result = match &action {
            IsolationAction::TemporaryIsolate {
                hostname,
                duration_minutes,
            } => self.isolate_host(hostname, *duration_minutes),
            IsolationAction::BlockDestination { ip, duration_minutes } => {
                self.block_destination(ip, *duration_minutes)
            }
            IsolationAction::BlockPort { port, protocol } => self.block_port(*port, protocol),
            IsolationAction::BlockDomain { domain, duration_minutes } => {
                self.block_domain(domain, *duration_minutes)
            }
            IsolationAction::BlockASN { asn, duration_minutes } => {
                self.block_asn(*asn, *duration_minutes)
            }
        };

        match result {
            Ok(()) => {
                // Record the action
                let record = IsolationRecord {
                    id: action_id.clone(),
                    action: action.clone(),
                    executed_at,
                    executed_by: user.clone(),
                    expires_at: self.calculate_expiration(&action, executed_at),
                    rolled_back_at: None,
                    status: IsolationStatus::Active,
                };
                self.records.push(record);

                Ok(ActionResult {
                    action_id: action_id.clone(),
                    action,
                    executed_at,
                    executed_by: user,
                    success: true,
                    rollback_info: Some(rollback_info),
                    error: None,
                })
            }
            Err(e) => Ok(ActionResult {
                action_id,
                action,
                executed_at,
                executed_by: user,
                success: false,
                rollback_info: None,
                error: Some(e),
            }),
        }
    }

    /// Rollback an action
    pub fn rollback_action(&mut self, action_id: &str) -> Result<(), String> {
        // Find the record and clone the action to avoid borrow conflicts
        let action = if let Some(record) = self.records.iter().find(|r| r.id == action_id) {
            if record.status != IsolationStatus::Active {
                return Err("Action is not active".to_string());
            }
            record.action.clone()
        } else {
            return Err("Action not found".to_string());
        };

        // Execute rollback based on action type
        self.rollback_firewall_rules(&action)?;

        // Update the record
        if let Some(record) = self.records.iter_mut().find(|r| r.id == action_id) {
            record.rolled_back_at = Some(Utc::now());
            record.status = IsolationStatus::RolledBack;
        }

        Ok(())
    }

    /// Get isolation history
    pub fn get_history(&self) -> Vec<IsolationRecord> {
        self.records.clone()
    }

    /// Get active isolations
    pub fn get_active(&self) -> Vec<IsolationRecord> {
        self.records
            .iter()
            .filter(|r| r.status == IsolationStatus::Active)
            .cloned()
            .collect()
    }

    // Platform-specific implementations

    #[cfg(target_os = "linux")]
    fn isolate_host(&self, _hostname: &str, _duration_minutes: u32) -> Result<(), String> {
        // Linux: Use iptables to drop all traffic
        // Example: iptables -I INPUT -j DROP
        //          iptables -I OUTPUT -j DROP
        // In production, this would execute actual iptables commands
        println!("[Mock] Isolating host via iptables");
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn isolate_host(&self, _hostname: &str, _duration_minutes: u32) -> Result<(), String> {
        // Windows: Use netsh advfirewall
        // Example: netsh advfirewall set allprofiles state on
        //          netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound
        println!("[Mock] Isolating host via Windows Firewall");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn isolate_host(&self, _hostname: &str, _duration_minutes: u32) -> Result<(), String> {
        Err("Host isolation not implemented for this platform".to_string())
    }

    #[cfg(target_os = "linux")]
    fn block_destination(&self, ip: &str, _duration: Option<u32>) -> Result<(), String> {
        // Linux: iptables -A OUTPUT -d <ip> -j DROP
        println!("[Mock] Blocking destination {} via iptables", ip);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn block_destination(&self, ip: &str, _duration: Option<u32>) -> Result<(), String> {
        // Windows: netsh advfirewall firewall add rule name="Block IP" dir=out action=block remoteip=<ip>
        println!("[Mock] Blocking destination {} via Windows Firewall", ip);
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn block_destination(&self, _ip: &str, _duration: Option<u32>) -> Result<(), String> {
        Err("Destination blocking not implemented for this platform".to_string())
    }

    fn block_port(&self, port: u16, protocol: &str) -> Result<(), String> {
        println!("[Mock] Blocking {} port {}", protocol, port);
        Ok(())
    }

    fn block_domain(&self, domain: &str, _duration: Option<u32>) -> Result<(), String> {
        // In production, this would modify /etc/hosts or DNS settings
        println!("[Mock] Blocking domain {}", domain);
        Ok(())
    }

    fn block_asn(&self, asn: u32, _duration: Option<u32>) -> Result<(), String> {
        // In production, this would:
        // 1. Resolve ASN to IP ranges via BGP data
        // 2. Block all IP ranges in the ASN
        println!("[Mock] Blocking ASN {}", asn);
        Ok(())
    }

    fn prepare_rollback(&self, _action: &IsolationAction) -> Result<RollbackInfo, String> {
        // In production, capture current firewall rules before modification
        Ok(RollbackInfo {
            action_id: uuid::Uuid::new_v4().to_string(),
            original_rules: vec!["[Mock] Original firewall state".to_string()],
            expires_at: None,
        })
    }

    fn rollback_firewall_rules(&self, _action: &IsolationAction) -> Result<(), String> {
        // Restore original firewall state
        println!("[Mock] Rolling back firewall rules");
        Ok(())
    }

    fn calculate_expiration(
        &self,
        action: &IsolationAction,
        executed_at: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        match action {
            IsolationAction::TemporaryIsolate {
                duration_minutes, ..
            } => Some(executed_at + chrono::Duration::minutes(*duration_minutes as i64)),
            IsolationAction::BlockDestination {
                duration_minutes, ..
            } => duration_minutes
                .map(|d| executed_at + chrono::Duration::minutes(d as i64)),
            IsolationAction::BlockDomain {
                duration_minutes, ..
            } => duration_minutes
                .map(|d| executed_at + chrono::Duration::minutes(d as i64)),
            _ => None,
        }
    }
}

impl Default for IsolationManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preview_action() {
        let manager = IsolationManager::new();

        let action = IsolationAction::BlockDestination {
            ip: "1.2.3.4".to_string(),
            duration_minutes: Some(60),
        };

        let preview = manager.preview_action(&action);
        assert!(preview.reversible);
    }

    #[test]
    fn test_execute_and_rollback() {
        let mut manager = IsolationManager::new();

        let action = IsolationAction::BlockPort {
            port: 4444,
            protocol: "TCP".to_string(),
        };

        let result = manager
            .execute_action(action, "admin".to_string())
            .unwrap();
        assert!(result.success);

        let rollback = manager.rollback_action(&result.action_id);
        assert!(rollback.is_ok());
    }
}
