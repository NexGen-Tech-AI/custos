use super::*;
use std::collections::VecDeque;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::{DateTime, Utc};

/// Alert management system
pub struct AlertManager {
    alerts: Arc<RwLock<VecDeque<Alert>>>,
    config: AlertConfig,
    max_alerts: usize,
    handlers: Vec<Box<dyn AlertHandler + Send + Sync>>,
}

impl AlertManager {
    pub fn new(config: AlertConfig) -> Self {
        let mut manager = Self {
            alerts: Arc::new(RwLock::new(VecDeque::new())),
            config,
            max_alerts: 10000,
            handlers: Vec::new(),
        };

        // Add default handlers
        manager.add_handler(Box::new(ConsoleAlertHandler));
        manager.add_handler(Box::new(LogFileHandler::new()));

        manager
    }

    /// Add a new alert handler
    pub fn add_handler(&mut self, handler: Box<dyn AlertHandler + Send + Sync>) {
        self.handlers.push(handler);
    }

    /// Process a threat event and create alert if necessary
    pub async fn process_threat(&self, event: ThreatEvent) {
        // Check if alert should be generated based on severity
        if event.severity < self.config.min_severity {
            return;
        }

        let alert = Alert {
            id: uuid::Uuid::new_v4().to_string(),
            threat_event: event.clone(),
            created_at: Utc::now(),
            acknowledged: false,
            acknowledged_by: None,
            acknowledged_at: None,
            notes: Vec::new(),
        };

        // Store alert
        {
            let mut alerts = self.alerts.write();
            alerts.push_back(alert.clone());

            // Limit alert history
            while alerts.len() > self.max_alerts {
                alerts.pop_front();
            }
        }

        // Notify handlers
        for handler in &self.handlers {
            if let Err(e) = handler.handle_alert(&alert).await {
                eprintln!("Alert handler error: {}", e);
            }
        }

        // Auto-remediate if enabled
        if self.config.auto_remediate && event.severity >= ThreatSeverity::High {
            self.auto_remediate(&event).await;
        }
    }

    /// Get all alerts
    pub fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.read().iter().cloned().collect()
    }

    /// Get alerts by severity
    pub fn get_alerts_by_severity(&self, min_severity: ThreatSeverity) -> Vec<Alert> {
        self.alerts
            .read()
            .iter()
            .filter(|a| a.threat_event.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Get unacknowledged alerts
    pub fn get_unacknowledged_alerts(&self) -> Vec<Alert> {
        self.alerts
            .read()
            .iter()
            .filter(|a| !a.acknowledged)
            .cloned()
            .collect()
    }

    /// Acknowledge an alert
    pub fn acknowledge_alert(&self, alert_id: &str, user: &str) -> bool {
        let mut alerts = self.alerts.write();

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.acknowledged = true;
            alert.acknowledged_by = Some(user.to_string());
            alert.acknowledged_at = Some(Utc::now());
            return true;
        }

        false
    }

    /// Add note to alert
    pub fn add_note(&self, alert_id: &str, note: String, author: &str) {
        let mut alerts = self.alerts.write();

        if let Some(alert) = alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.notes.push(AlertNote {
                content: note,
                author: author.to_string(),
                created_at: Utc::now(),
            });
        }
    }

    /// Clear acknowledged alerts older than specified days
    pub fn clear_old_alerts(&self, days: i64) {
        let mut alerts = self.alerts.write();
        let cutoff = Utc::now() - chrono::Duration::days(days);

        alerts.retain(|alert| {
            !alert.acknowledged || alert.created_at > cutoff
        });
    }

    /// Auto-remediate threat
    async fn auto_remediate(&self, event: &ThreatEvent) {
        if let Some(process_id) = event.process_id {
            match event.severity {
                ThreatSeverity::Critical => {
                    // Kill process for critical threats
                    println!("AUTO-REMEDIATE: Terminating process {} (PID: {})",
                        event.process_name.as_ref().unwrap_or(&"Unknown".to_string()),
                        process_id
                    );
                    // In production, actually kill the process
                    // Self::kill_process(process_id);
                }
                ThreatSeverity::High => {
                    // Suspend or isolate process
                    println!("AUTO-REMEDIATE: Isolating process {} (PID: {})",
                        event.process_name.as_ref().unwrap_or(&"Unknown".to_string()),
                        process_id
                    );
                    // In production, suspend process or limit its access
                }
                _ => {}
            }
        }
    }

    /// Get alert statistics
    pub fn get_statistics(&self) -> AlertStatistics {
        let alerts = self.alerts.read();

        let mut stats = AlertStatistics {
            total_alerts: alerts.len(),
            unacknowledged: 0,
            by_severity: std::collections::HashMap::new(),
            by_category: std::collections::HashMap::new(),
            last_24h: 0,
        };

        let last_24h = Utc::now() - chrono::Duration::hours(24);

        for alert in alerts.iter() {
            if !alert.acknowledged {
                stats.unacknowledged += 1;
            }

            if alert.created_at > last_24h {
                stats.last_24h += 1;
            }

            *stats.by_severity
                .entry(format!("{:?}", alert.threat_event.severity))
                .or_insert(0) += 1;

            *stats.by_category
                .entry(format!("{:?}", alert.threat_event.category))
                .or_insert(0) += 1;
        }

        stats
    }
}

/// Alert configuration
#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub min_severity: ThreatSeverity,
    pub auto_remediate: bool,
    pub enable_notifications: bool,
    pub enable_email: bool,
    pub email_recipients: Vec<String>,
    pub enable_webhook: bool,
    pub webhook_url: Option<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            min_severity: ThreatSeverity::Medium,
            auto_remediate: false,
            enable_notifications: true,
            enable_email: false,
            email_recipients: Vec::new(),
            enable_webhook: false,
            webhook_url: None,
        }
    }
}

/// Alert with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub threat_event: ThreatEvent,
    pub created_at: DateTime<Utc>,
    pub acknowledged: bool,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub notes: Vec<AlertNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertNote {
    pub content: String,
    pub author: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatistics {
    pub total_alerts: usize,
    pub unacknowledged: usize,
    pub by_severity: std::collections::HashMap<String, usize>,
    pub by_category: std::collections::HashMap<String, usize>,
    pub last_24h: usize,
}

/// Trait for alert handlers
#[async_trait::async_trait]
pub trait AlertHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>>;
}

/// Console alert handler
struct ConsoleAlertHandler;

#[async_trait::async_trait]
impl AlertHandler for ConsoleAlertHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        let event = &alert.threat_event;

        println!("\n{}", "=".repeat(80));
        println!("🚨 SECURITY ALERT: {} - {:?}", event.title, event.severity);
        println!("{}", "=".repeat(80));
        println!("Description: {}", event.description);
        println!("Category: {:?}", event.category);
        println!("Detection: {:?}", event.detection_method);

        if let Some(process) = &event.process_name {
            println!("Process: {} (PID: {})", process, event.process_id.unwrap_or(0));
        }

        if !event.mitre_tactics.is_empty() {
            println!("MITRE Tactics: {}", event.mitre_tactics.join(", "));
        }

        println!("Confidence: {:.0}%", event.confidence * 100.0);
        println!("Timestamp: {}", event.timestamp);

        if !event.recommended_actions.is_empty() {
            println!("\nRecommended Actions:");
            for (i, action) in event.recommended_actions.iter().enumerate() {
                println!("  {}. {}", i + 1, action);
            }
        }

        println!("{}\n", "=".repeat(80));

        Ok(())
    }
}

/// Log file alert handler
struct LogFileHandler {
    log_path: std::path::PathBuf,
}

impl LogFileHandler {
    fn new() -> Self {
        Self {
            log_path: std::path::PathBuf::from("custos_threats.log"),
        }
    }
}

#[async_trait::async_trait]
impl AlertHandler for LogFileHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        use std::io::Write;

        let log_entry = format!(
            "[{}] {:?} - {} - {}\n",
            alert.created_at.format("%Y-%m-%d %H:%M:%S"),
            alert.threat_event.severity,
            alert.threat_event.title,
            alert.threat_event.description
        );

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        file.write_all(log_entry.as_bytes())?;

        Ok(())
    }
}

/// Email alert handler
pub struct EmailAlertHandler {
    smtp_server: String,
    smtp_port: u16,
    username: String,
    password: String,
    from: String,
    to: Vec<String>,
}

#[async_trait::async_trait]
impl AlertHandler for EmailAlertHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        // In production, implement actual email sending
        // Using lettre crate or similar
        println!("EMAIL ALERT: Would send email to {:?}", self.to);
        Ok(())
    }
}

/// Webhook alert handler
pub struct WebhookAlertHandler {
    webhook_url: String,
    client: reqwest::Client,
}

impl WebhookAlertHandler {
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AlertHandler for WebhookAlertHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::json!({
            "alert_id": alert.id,
            "severity": format!("{:?}", alert.threat_event.severity),
            "title": alert.threat_event.title,
            "description": alert.threat_event.description,
            "timestamp": alert.created_at.to_rfc3339(),
        });

        self.client
            .post(&self.webhook_url)
            .json(&payload)
            .send()
            .await?;

        Ok(())
    }
}

/// Desktop notification handler (using system notifications)
pub struct DesktopNotificationHandler;

#[async_trait::async_trait]
impl AlertHandler for DesktopNotificationHandler {
    async fn handle_alert(&self, alert: &Alert) -> Result<(), Box<dyn std::error::Error>> {
        // In production, use notify-rust or similar crate
        println!("DESKTOP NOTIFICATION: {}", alert.threat_event.title);
        Ok(())
    }
}
