# Threat Detection Portal - Implementation Plan

Based on comprehensive backend analysis, here's the phased implementation plan for all portal tabs.

## Executive Summary

**What We Have:**
- ✅ Network sensor with per-process connection mapping
- ✅ Package inventory (multi-distro Linux + Windows)
- ✅ Persistence mechanism detection
- ✅ Comprehensive threat detection engine (signatures, behavioral, AI, threat intel)
- ✅ SQLite event storage with MITRE ATT&CK mapping
- ✅ Alert management with acknowledgment and notes

**What We Need to Build:**
- 🔨 Network Security tab (50% backend exists, needs UI + enhancements)
- 🔨 Vulnerabilities tab (needs CVE database + UI)
- 🔨 Scans tab (scan orchestration + results UI)
- 🔨 AI Analysis tab (interactive analysis UI)
- 🔨 Reports tab (PDF/HTML generation + UI)
- 🔨 Settings tab (configuration UI)

---

## Phase 1: Network Security Tab (Week 1-2)

**Goal:** "What is talking to what, why, and should I stop it?"

### Backend Work Required

#### 1.1 Network Connection History (`src-tauri/src/sensors/network_sensor.rs`)
**Current State:** Network connections are detected but not persisted to database
**Changes Needed:**
```rust
// Add to network_sensor.rs
pub struct NetworkConnectionHistory {
    pub connection_id: String,
    pub timestamp: DateTime<Utc>,
    pub process_id: u32,
    pub process_name: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub protocol: String,
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub duration_seconds: u64,
}

impl NetworkSensor {
    pub fn persist_connections(&self) -> Result<(), String> {
        // Store connections in event database with NetworkConnection event type
    }

    pub fn get_connection_history(&self, hours: u64) -> Result<Vec<NetworkConnectionHistory>, String> {
        // Query database for recent connections
    }
}
```

**Files to Modify:**
- `src-tauri/src/sensors/network_sensor.rs` - Add persistence
- `src-tauri/src/storage/mod.rs` - Add connection history queries
- `src-tauri/src/main.rs` - Add Tauri commands

#### 1.2 DNS Query Tracking Enhancement
**Current State:** DNS queries detected (UDP port 53) but no deep analysis
**Changes Needed:**
```rust
pub struct DNSQuery {
    pub timestamp: DateTime<Utc>,
    pub process_name: String,
    pub query: String,
    pub query_type: String, // A, AAAA, TXT, etc.
    pub response_code: String,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
}

pub fn analyze_dns_query(query: &str) -> DNSAnalysis {
    // Check for:
    // - Excessive subdomain length (DNS tunneling)
    // - High entropy (random-looking domains)
    // - Known bad domains
    // - DGA patterns
    // - Newly registered domains
}
```

**Files to Create:**
- `src-tauri/src/sensors/dns_analyzer.rs` - New module

#### 1.3 Network Segmentation Logic
**Changes Needed:**
```rust
pub enum NetworkSegment {
    LAN,        // Private RFC1918
    Guest,      // Configurable subnet
    IoT,        // Configurable subnet
    Work,       // Configurable subnet
    Servers,    // Configurable subnet
    Internet,   // Everything else
}

pub struct SegmentPolicy {
    pub segment: NetworkSegment,
    pub blocked_asns: Vec<u32>,
    pub allowed_ports: Vec<u16>,
    pub restrict_lateral: bool, // Block SMB/RDP between segments
}

pub fn classify_ip(ip: &str, config: &SegmentConfig) -> NetworkSegment {
    // Classify IP into segment based on user-defined ranges
}
```

**Files to Create:**
- `src-tauri/src/network/segmentation.rs` - New module
- `src-tauri/src/network/policies.rs` - Policy engine

#### 1.4 ASN/GeoIP Lookup
**Integration Needed:**
```rust
// Use MaxMind GeoLite2 database (free)
pub struct GeoIPInfo {
    pub country: String,
    pub city: Option<String>,
    pub asn: u32,
    pub asn_org: String,
    pub is_known_vpn: bool,
    pub is_tor: bool,
    pub is_hosting: bool,
}

pub async fn lookup_ip(ip: &str) -> Result<GeoIPInfo, String> {
    // Query local MaxMind database
}
```

**Dependencies to Add:**
```toml
maxminddb = "0.23"
```

**Files to Create:**
- `src-tauri/src/network/geoip.rs` - New module
- Download MaxMind GeoLite2-ASN.mmdb and GeoLite2-City.mmdb

#### 1.5 Network Isolation Actions
**Changes Needed:**
```rust
pub enum IsolationAction {
    TemporaryIsolate { hostname: String, duration_minutes: u32 },
    BlockDestination { ip: String, duration_minutes: Option<u32> },
    BlockASN { asn: u32, duration_minutes: Option<u32> },
    BlockPort { port: u16, protocol: String },
}

pub struct IsolationManager {
    pub fn preview_action(&self, action: &IsolationAction) -> ActionPreview {
        // Show what will be affected
    }

    pub fn execute_action(&self, action: &IsolationAction) -> Result<ActionResult, String> {
        // Linux: iptables rules
        // Windows: netsh advfirewall
        // Store rollback info
    }

    pub fn rollback_action(&self, action_id: &str) -> Result<(), String> {
        // Restore previous state
    }
}
```

**Files to Create:**
- `src-tauri/src/network/isolation.rs` - New module
- Platform-specific firewall rule management

#### 1.6 New Tauri Commands
**Add to `src-tauri/src/main.rs`:**
```rust
#[tauri::command]
async fn get_network_connections(time_range_hours: u64) -> Result<Vec<NetworkConnectionHistory>, String>

#[tauri::command]
async fn get_dns_queries(time_range_hours: u64) -> Result<Vec<DNSQuery>, String>

#[tauri::command]
async fn get_network_segments() -> Result<Vec<NetworkSegment>, String>

#[tauri::command]
async fn update_segment_policy(segment: NetworkSegment, policy: SegmentPolicy) -> Result<(), String>

#[tauri::command]
async fn get_top_talkers(limit: usize) -> Result<Vec<TopTalker>, String>

#[tauri::command]
async fn preview_isolation(action: IsolationAction) -> Result<ActionPreview, String>

#[tauri::command]
async fn execute_isolation(action: IsolationAction, user: String) -> Result<ActionResult, String>

#[tauri::command]
async fn rollback_isolation(action_id: String) -> Result<(), String>

#[tauri::command]
async fn get_isolation_history() -> Result<Vec<IsolationRecord>, String>
```

### Frontend Work Required

#### 1.7 Network Security Tab Component Structure
```
src/components/sections/network-security/
├── NetworkSecuritySection.tsx       (Main container)
├── NetworkOverview.tsx              (Coverage, risk summary, live anomalies)
├── SegmentsTopology.tsx             (Visual network map + segment policies)
├── SignalsFeed.tsx                  (Live connection feed with actions)
├── ConnectionExplorer.tsx           (Filterable connection history)
├── ResponseControls.tsx             (Isolation controls)
└── components/
    ├── ConnectionRow.tsx
    ├── DNSQueryRow.tsx
    ├── SegmentCard.tsx
    ├── TopologyGraph.tsx
    ├── IsolationDialog.tsx
    └── ActionPreview.tsx
```

#### 1.8 UI Components to Build

**NetworkOverview.tsx:**
- Coverage meter: % of devices reporting
- Risk summary cards: top risky hosts, destinations, segments
- Live anomaly feed: beaconing, DNS tunneling, new ASN spikes
- Kill switch status indicator

**SegmentsTopology.tsx:**
- Network topology visualization (D3.js or react-flow)
- Segment cards with device counts
- Per-segment policy editor
- Top talkers per segment

**SignalsFeed.tsx:**
- Real-time connection feed
- Severity + confidence badges
- Host + process + destination + ASN/geo
- "Why suspicious" explanation
- Action buttons: Allow, Block, Contain, Investigate

**ConnectionExplorer.tsx:**
- Advanced filtering (device, port, protocol, country/ASN, time)
- "Story mode" timeline view
- Export to CSV/JSON

**ResponseControls.tsx:**
- Temporary isolation controls (15m / 1h / until reboot)
- Destination block (domain/IP/ASN)
- DNS policy toggle
- Rollback history

### Estimated Time: **8 hours backend + 12 hours frontend = 20 hours**

---

## Phase 2: Vulnerabilities Tab (Week 3-4)

**Goal:** "What could be exploited here, and what should I fix first?"

### Backend Work Required

#### 2.1 CVE Database Integration
**Options:**
1. **NVD (National Vulnerability Database)** - Free, comprehensive, rate-limited API
2. **OSV (Open Source Vulnerabilities)** - Google's free database, good for package ecosystems
3. **Vulners** - Unified API across multiple sources

**Recommended Approach: OSV + NVD hybrid**

```rust
// src-tauri/src/vulnerability/database.rs
pub struct VulnerabilityDatabase {
    pub fn query_cves_for_package(&self, package: &Package) -> Vec<CVE> {
        // Query OSV API for package CVEs
        // Enrich with NVD CVSS scores
    }

    pub fn update_database(&self) -> Result<(), String> {
        // Periodic CVE database sync (daily)
    }
}

pub struct CVE {
    pub id: String,
    pub description: String,
    pub cvss_score: f64,
    pub severity: String,
    pub exploitability: ExploitStatus,
    pub affected_versions: Vec<String>,
    pub fixed_version: Option<String>,
    pub published_date: DateTime<Utc>,
    pub exploit_available: bool,
    pub exploit_maturity: String, // PoC, Functional, High
}

pub enum ExploitStatus {
    KnownExploited,  // In CISA KEV catalog
    PoCAvailable,
    None,
}
```

**Files to Create:**
- `src-tauri/src/vulnerability/database.rs` - CVE lookup
- `src-tauri/src/vulnerability/scanner.rs` - Package-to-CVE matching
- `src-tauri/src/vulnerability/prioritizer.rs` - Risk-based prioritization

#### 2.2 Vulnerability Scanning
```rust
pub struct VulnerabilityScanner {
    pub fn scan_system(&self) -> ScanResult {
        // Get all packages from package_sensor
        // Query CVE database for each package
        // Apply prioritization logic
    }

    pub fn get_exploitable_exposed(&self) -> Vec<Vulnerability> {
        // Filter for: exploitable + exposed + critical device
    }
}

pub struct Vulnerability {
    pub cve: CVE,
    pub affected_package: Package,
    pub affected_devices: Vec<String>,
    pub exploitability_score: f64,
    pub exposure_score: f64,
    pub blast_radius: BlastRadius,
    pub remediation: Remediation,
}

pub struct Remediation {
    pub action: String, // "Update package X to version Y"
    pub risk_of_change: String, // "May break service Z"
    pub safe_to_apply: bool,
    pub commands: Vec<String>, // Platform-specific commands
}
```

#### 2.3 Misconfiguration Detection
```rust
pub struct MisconfigScanner {
    pub fn check_firewall(&self) -> Vec<MisconfigFinding> {
        // Linux: check ufw/iptables rules
        // Windows: check Windows Firewall
    }

    pub fn check_disk_encryption(&self) -> Vec<MisconfigFinding> {
        // Linux: check LUKS
        // Windows: check BitLocker
    }

    pub fn check_admin_accounts(&self) -> Vec<MisconfigFinding> {
        // Check for weak passwords, default accounts
    }

    pub fn check_exposed_services(&self) -> Vec<MisconfigFinding> {
        // Check for internet-exposed ports
    }
}

pub struct MisconfigFinding {
    pub category: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
    pub remediation: Remediation,
}
```

**Files to Create:**
- `src-tauri/src/vulnerability/misconfig.rs` - Configuration scanner

#### 2.4 New Tauri Commands
```rust
#[tauri::command]
async fn scan_vulnerabilities() -> Result<ScanResult, String>

#[tauri::command]
async fn get_vulnerabilities(filter: VulnFilter) -> Result<Vec<Vulnerability>, String>

#[tauri::command]
async fn get_exploitable_exposed() -> Result<Vec<Vulnerability>, String>

#[tauri::command]
async fn get_misconfigurations() -> Result<Vec<MisconfigFinding>, String>

#[tauri::command]
async fn apply_remediation(vuln_id: String, user: String) -> Result<RemediationResult, String>

#[tauri::command]
async fn get_vulnerability_stats() -> Result<VulnStats, String>

#[tauri::command]
async fn update_vulnerability_database() -> Result<UpdateStatus, String>
```

### Frontend Work Required

#### 2.5 Vulnerabilities Tab Component Structure
```
src/components/sections/vulnerabilities/
├── VulnerabilitiesSection.tsx       (Main container)
├── PostureOverview.tsx              (Fix now, misconfig score, exposed services)
├── FindingsList.tsx                 (CVEs + misconfigs table)
├── RemediationPanel.tsx             (Action previews + apply)
├── BaselineExceptions.tsx           (Exception management)
└── components/
    ├── VulnerabilityCard.tsx
    ├── MisconfigCard.tsx
    ├── RemediationDialog.tsx
    ├── ExceptionDialog.tsx
    └── CVEDetails.tsx
```

**Key Features:**
- Grouping by device, package, or exploit availability
- Severity + exploitability + exposure scoring
- "Why flagged" with evidence
- One-click remediation with rollback support
- Exception workflow with expiration dates
- Drift detection alerts

### Estimated Time: **10 hours backend + 10 hours frontend = 20 hours**

---

## Phase 3: Scans Tab (Week 5)

**Goal:** "Prove what you checked, when, and what changed."

### Backend Work Required

#### 3.1 Scan Orchestration
```rust
pub struct ScanManager {
    pub fn create_scan(&self, config: ScanConfig) -> Result<ScanRun, String> {
        // Orchestrate multiple scan types
    }

    pub fn get_scan_runs(&self) -> Vec<ScanRun> {
        // Historical scan runs
    }

    pub fn compare_scans(&self, run1: String, run2: String) -> ScanDiff {
        // "New since last scan"
        // "Fixed since last scan"
        // "Regressed since last scan"
    }
}

pub struct ScanConfig {
    pub scan_types: Vec<ScanType>,
    pub scope: Vec<String>, // Device IDs or "all"
    pub schedule: Option<Schedule>,
}

pub enum ScanType {
    PackageInventory,      // SBOM generation
    ServiceExposure,       // Port scanning
    ConfigurationCheck,    // Misconfig detection
    VulnerabilityScan,     // CVE matching
}

pub struct ScanRun {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub config: ScanConfig,
    pub status: ScanStatus,
    pub duration_seconds: u64,
    pub devices_scanned: usize,
    pub results_summary: ScanSummary,
}
```

**Files to Create:**
- `src-tauri/src/scanning/manager.rs` - Scan orchestration
- `src-tauri/src/scanning/scheduler.rs` - Cron-like scheduling
- `src-tauri/src/scanning/export.rs` - PDF/JSON export

#### 3.2 SBOM Generation
```rust
pub struct SBOMGenerator {
    pub fn generate_sbom(&self, format: SBOMFormat) -> Result<String, String> {
        // CycloneDX or SPDX format
    }
}

pub enum SBOMFormat {
    CycloneDX,
    SPDX,
}
```

**Dependencies:**
```toml
cyclonedx-bom = "0.5"
```

#### 3.3 New Tauri Commands
```rust
#[tauri::command]
async fn create_scan(config: ScanConfig) -> Result<ScanRun, String>

#[tauri::command]
async fn get_scan_runs() -> Result<Vec<ScanRun>, String>

#[tauri::command]
async fn get_scan_details(scan_id: String) -> Result<ScanRun, String>

#[tauri::command]
async fn compare_scans(scan1: String, scan2: String) -> Result<ScanDiff, String>

#[tauri::command]
async fn export_scan(scan_id: String, format: String) -> Result<String, String>

#[tauri::command]
async fn generate_sbom(format: SBOMFormat) -> Result<String, String>
```

### Frontend Work Required

#### 3.4 Scans Tab Component Structure
```
src/components/sections/scans/
├── ScansSection.tsx
├── ScanRunsTable.tsx
├── ScanConfiguration.tsx
├── ScanDifferential.tsx
└── components/
    ├── ScanRunRow.tsx
    ├── ScanConfigDialog.tsx
    └── ScanDiffView.tsx
```

### Estimated Time: **6 hours backend + 6 hours frontend = 12 hours**

---

## Phase 4: AI Analysis Tab (Week 6)

**Goal:** "Convert noisy telemetry into coherent incident narrative and recommended actions."

### Backend Work Required

#### 4.1 Incident Narrative Generator
```rust
pub struct IncidentAnalyzer {
    pub async fn generate_narrative(&self, incident_id: String) -> Result<IncidentNarrative, String> {
        // Use existing AI analyzer
        // Build timeline from event database
        // Map to MITRE ATT&CK
        // Generate recommended actions
    }
}

pub struct IncidentNarrative {
    pub what_happened: String,
    pub likely_technique: String,
    pub mitre_tactics: Vec<String>,
    pub confidence: f64,
    pub alternatives: Vec<String>,
    pub recommended_actions: Vec<Action>,
    pub blast_radius: BlastRadiusEstimate,
    pub evidence: Vec<Evidence>,
}

pub struct Evidence {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub event_type: String,
}
```

**Files to Create:**
- `src-tauri/src/ai/narrative.rs` - Incident storytelling
- `src-tauri/src/ai/action_simulator.rs` - Action impact prediction

#### 4.2 Local RAG (Retrieval-Augmented Generation)
```rust
pub struct LocalRAG {
    pub fn index_knowledge(&self) {
        // Index Windows event IDs, Sysmon mappings
        // Index Linux auth log patterns
        // Index MITRE ATT&CK knowledge
    }

    pub fn query(&self, question: &str) -> String {
        // Vector similarity search
        // Return relevant context
    }
}
```

**Dependencies:**
```toml
tantivy = "0.21"  // Full-text search
```

**Files to Create:**
- `src-tauri/src/ai/rag.rs` - Local knowledge base

#### 4.3 New Tauri Commands
```rust
#[tauri::command]
async fn generate_incident_narrative(incident_id: String) -> Result<IncidentNarrative, String>

#[tauri::command]
async fn ask_security_question(question: String) -> Result<String, String>

#[tauri::command]
async fn simulate_action(action: RemediationAction) -> Result<ActionSimulation, String>
```

### Frontend Work Required

#### 4.4 AI Analysis Tab Component Structure
```
src/components/sections/ai-analysis/
├── AIAnalysisSection.tsx
├── IncidentNarrativeView.tsx
├── SecurityQA.tsx
├── ActionSimulator.tsx
└── components/
    ├── NarrativeTimeline.tsx
    ├── EvidenceViewer.tsx
    ├── ChatInterface.tsx
    └── SimulationResults.tsx
```

### Estimated Time: **8 hours backend + 8 hours frontend = 16 hours**

---

## Phase 5: Reports Tab (Week 7)

**Goal:** "Easy exports + executive summaries + receipts."

### Backend Work Required

#### 5.1 Report Generation
```rust
pub struct ReportGenerator {
    pub fn generate_weekly_summary(&self) -> Result<Report, String> {
        // Weekly security summary
    }

    pub fn generate_incident_report(&self, incident_id: String) -> Result<Report, String> {
        // Detailed incident report
    }

    pub fn generate_vuln_posture(&self) -> Result<Report, String> {
        // Vulnerability posture
    }

    pub fn generate_device_inventory(&self) -> Result<Report, String> {
        // Device inventory
    }

    pub fn generate_audit_log(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Report, String> {
        // Change log / actions audit
    }
}

pub enum ReportFormat {
    PDF,
    HTML,
    JSON,
}

pub struct Report {
    pub title: String,
    pub generated_at: DateTime<Utc>,
    pub sections: Vec<ReportSection>,
}
```

**Dependencies:**
```toml
printpdf = "0.7"     // PDF generation
tera = "1.19"        // HTML templating
```

**Files to Create:**
- `src-tauri/src/reporting/generator.rs` - Report generation
- `src-tauri/src/reporting/templates/` - HTML templates

#### 5.2 New Tauri Commands
```rust
#[tauri::command]
async fn generate_report(report_type: String, format: ReportFormat) -> Result<String, String>

#[tauri::command]
async fn get_available_reports() -> Result<Vec<ReportTemplate>, String>

#[tauri::command]
async fn schedule_report(report_type: String, schedule: Schedule) -> Result<(), String>
```

### Frontend Work Required

#### 5.3 Reports Tab Component Structure
```
src/components/sections/reports/
├── ReportsSection.tsx
├── ReportTemplates.tsx
├── ReportScheduler.tsx
└── components/
    ├── ReportCard.tsx
    └── ScheduleDialog.tsx
```

### Estimated Time: **6 hours backend + 4 hours frontend = 10 hours**

---

## Phase 6: Settings Tab (Week 8)

**Goal:** "Make it powerful without letting users brick themselves."

### Backend Work Required

#### 6.1 Configuration Management
```rust
pub struct ConfigurationManager {
    pub fn get_config(&self) -> AppConfig {
        // Load from disk
    }

    pub fn update_config(&self, config: AppConfig) -> Result<(), String> {
        // Validate + save
    }

    pub fn export_config(&self) -> Result<String, String> {
        // Export as JSON
    }

    pub fn import_config(&self, json: String) -> Result<(), String> {
        // Validate + import
    }
}

pub struct AppConfig {
    pub scanning: ScanningConfig,
    pub alerts: AlertConfig,
    pub notifications: NotificationConfig,
    pub retention: RetentionConfig,
    pub security: SecurityConfig,
    pub privacy: PrivacyConfig,
    pub automation: AutomationConfig,
}

pub struct ScanningConfig {
    pub schedules: Vec<Schedule>,
    pub enabled_sensors: Vec<String>,
}

pub struct AlertConfig {
    pub sensitivity: f64,  // 0.0-1.0
    pub severities_to_alert: Vec<String>,
}

pub struct SecurityConfig {
    pub tamper_protection: bool,
    pub require_pin: bool,
    pub encrypt_logs: bool,
}

pub struct AutomationConfig {
    pub auto_contain_critical: bool,
    pub auto_block_known_bad: bool,
    pub allowlist: Vec<String>,
}
```

**Files to Create:**
- `src-tauri/src/config/manager.rs` - Configuration CRUD
- `src-tauri/src/config/validation.rs` - Config validation

#### 6.2 New Tauri Commands
```rust
#[tauri::command]
async fn get_configuration() -> Result<AppConfig, String>

#[tauri::command]
async fn update_configuration(config: AppConfig) -> Result<(), String>

#[tauri::command]
async fn export_configuration() -> Result<String, String>

#[tauri::command]
async fn import_configuration(json: String) -> Result<(), String>

#[tauri::command]
async fn reset_to_defaults() -> Result<(), String>
```

### Frontend Work Required

#### 6.3 Settings Tab Component Structure
```
src/components/sections/settings/
├── SettingsSection.tsx
├── CoreSettings.tsx
├── SecurityControls.tsx
├── AutomationSettings.tsx
├── PrivacySettings.tsx
└── components/
    ├── SettingCard.tsx
    ├── ConfigExportDialog.tsx
    └── DangerZone.tsx
```

### Estimated Time: **4 hours backend + 6 hours frontend = 10 hours**

---

## Total Implementation Estimate

| Phase | Backend Hours | Frontend Hours | Total Hours |
|-------|---------------|----------------|-------------|
| 1. Network Security | 8 | 12 | 20 |
| 2. Vulnerabilities | 10 | 10 | 20 |
| 3. Scans | 6 | 6 | 12 |
| 4. AI Analysis | 8 | 8 | 16 |
| 5. Reports | 6 | 4 | 10 |
| 6. Settings | 4 | 6 | 10 |
| **TOTAL** | **42 hours** | **46 hours** | **88 hours** |

**Timeline:** 8 weeks at ~11 hours/week (sustainable pace)

---

## Implementation Priorities

### Ship-Blocking (Must Have)
1. ✅ **Network Security tab** - Core EDR-for-traffic functionality
2. ✅ **Vulnerabilities tab** - Posture visibility
3. ✅ **Settings tab** - User configuration

### High Value (Should Have)
4. **Scans tab** - Compliance proof
5. **Reports tab** - Evidence export

### Nice-to-Have (Could Have)
6. **AI Analysis tab** - Premium feature for deep investigations

---

## Next Steps

1. **Immediate:** Start with Network Security backend enhancements
2. **Week 1:** Complete network connection history persistence
3. **Week 2:** Build Network Security UI
4. **Week 3-4:** Implement Vulnerabilities tab
5. **Week 5-8:** Complete remaining tabs

**Would you like me to start implementing Phase 1 (Network Security tab)?**
