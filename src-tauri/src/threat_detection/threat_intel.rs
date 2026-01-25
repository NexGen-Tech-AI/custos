use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};

/// Threat intelligence service
pub struct ThreatIntelService {
    enabled: bool,
    api_keys: ThreatIntelApiKeys,
    client: reqwest::Client,
    cache: parking_lot::Mutex<HashMap<String, CachedIntelData>>,
    cache_duration: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatIntelApiKeys {
    pub virustotal_api_key: Option<String>,
    pub abuseipdb_api_key: Option<String>,
    pub alienvault_api_key: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedIntelData {
    data: ThreatIntelData,
    cached_at: DateTime<Utc>,
}

impl ThreatIntelService {
    pub fn new(api_keys: ThreatIntelApiKeys) -> Self {
        let enabled = api_keys.virustotal_api_key.is_some() ||
                     api_keys.abuseipdb_api_key.is_some() ||
                     api_keys.alienvault_api_key.is_some();

        Self {
            enabled,
            api_keys,
            client: reqwest::Client::new(),
            cache: parking_lot::Mutex::new(HashMap::new()),
            cache_duration: Duration::hours(24),
        }
    }

    /// Check IP address reputation
    pub async fn check_ip_reputation(&self, ip_address: &str) -> Option<ThreatIntelData> {
        if !self.enabled {
            return None;
        }

        // Check cache first
        if let Some(cached) = self.get_from_cache(&format!("ip:{}", ip_address)) {
            return Some(cached);
        }

        // Try multiple sources
        let mut intel_data = ThreatIntelData {
            source: "Multiple Sources".to_string(),
            reputation_score: 0.5,
            categories: Vec::new(),
            last_seen: None,
            related_malware: Vec::new(),
        };

        // Check AbuseIPDB
        if let Some(data) = self.check_abuseipdb(ip_address).await {
            intel_data.merge(data);
        }

        // Check AlienVault OTX
        if let Some(data) = self.check_alienvault_ip(ip_address).await {
            intel_data.merge(data);
        }

        // Cache the result
        self.cache_intel_data(&format!("ip:{}", ip_address), intel_data.clone());

        Some(intel_data)
    }

    /// Check file hash reputation
    pub async fn check_file_hash(&self, file_hash: &str) -> Option<ThreatIntelData> {
        if !self.enabled {
            return None;
        }

        // Check cache first
        if let Some(cached) = self.get_from_cache(&format!("hash:{}", file_hash)) {
            return Some(cached);
        }

        // Check VirusTotal
        let intel_data = self.check_virustotal(file_hash).await?;

        // Cache the result
        self.cache_intel_data(&format!("hash:{}", file_hash), intel_data.clone());

        Some(intel_data)
    }

    /// Check domain reputation
    pub async fn check_domain(&self, domain: &str) -> Option<ThreatIntelData> {
        if !self.enabled {
            return None;
        }

        // Check cache first
        if let Some(cached) = self.get_from_cache(&format!("domain:{}", domain)) {
            return Some(cached);
        }

        // Check AlienVault OTX
        let intel_data = self.check_alienvault_domain(domain).await?;

        // Cache the result
        self.cache_intel_data(&format!("domain:{}", domain), intel_data.clone());

        Some(intel_data)
    }

    /// Check VirusTotal for file hash
    async fn check_virustotal(&self, file_hash: &str) -> Option<ThreatIntelData> {
        let api_key = self.api_keys.virustotal_api_key.as_ref()?;

        let url = format!("https://www.virustotal.com/api/v3/files/{}", file_hash);

        let response = self.client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let vt_response: VirusTotalResponse = response.json().await.ok()?;

        Some(ThreatIntelData {
            source: "VirusTotal".to_string(),
            reputation_score: Self::calculate_vt_score(&vt_response),
            categories: vt_response.data.attributes.popular_threat_classification
                .threat_label
                .into_iter()
                .map(|(k, _)| k)
                .collect(),
            last_seen: Some(Utc::now()),
            related_malware: vt_response.data.attributes.names.unwrap_or_default(),
        })
    }

    /// Check AbuseIPDB for IP reputation
    async fn check_abuseipdb(&self, ip_address: &str) -> Option<ThreatIntelData> {
        let api_key = self.api_keys.abuseipdb_api_key.as_ref()?;

        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ip_address
        );

        let response = self.client
            .get(&url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await
            .ok()?;

        if !response.status().is_success() {
            return None;
        }

        let abuse_response: AbuseIPDBResponse = response.json().await.ok()?;

        let reputation_score = if abuse_response.data.abuse_confidence_score > 75 {
            0.9
        } else if abuse_response.data.abuse_confidence_score > 50 {
            0.7
        } else if abuse_response.data.abuse_confidence_score > 25 {
            0.5
        } else {
            0.3
        };

        Some(ThreatIntelData {
            source: "AbuseIPDB".to_string(),
            reputation_score,
            categories: vec!["IP Abuse".to_string()],
            last_seen: Some(Utc::now()),
            related_malware: Vec::new(),
        })
    }

    /// Check AlienVault OTX for IP
    async fn check_alienvault_ip(&self, _ip_address: &str) -> Option<ThreatIntelData> {
        // Placeholder for AlienVault integration
        // In production, implement full AlienVault OTX API integration
        None
    }

    /// Check AlienVault OTX for domain
    async fn check_alienvault_domain(&self, _domain: &str) -> Option<ThreatIntelData> {
        // Placeholder for AlienVault integration
        None
    }

    /// Calculate VirusTotal reputation score
    fn calculate_vt_score(response: &VirusTotalResponse) -> f64 {
        let stats = &response.data.attributes.last_analysis_stats;
        let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

        if total == 0 {
            return 0.5;
        }

        let malicious_ratio = stats.malicious as f64 / total as f64;
        let suspicious_ratio = stats.suspicious as f64 / total as f64;

        // High threat if many engines detect as malicious
        if malicious_ratio > 0.5 {
            0.95
        } else if malicious_ratio > 0.25 {
            0.85
        } else if malicious_ratio > 0.10 {
            0.70
        } else if suspicious_ratio > 0.25 {
            0.60
        } else {
            0.30
        }
    }

    /// Get data from cache
    fn get_from_cache(&self, key: &str) -> Option<ThreatIntelData> {
        let cache = self.cache.lock();

        if let Some(cached) = cache.get(key) {
            let age = Utc::now() - cached.cached_at;
            if age < self.cache_duration {
                return Some(cached.data.clone());
            }
        }

        None
    }

    /// Cache intelligence data
    fn cache_intel_data(&self, key: &str, data: ThreatIntelData) {
        let mut cache = self.cache.lock();
        cache.insert(
            key.to_string(),
            CachedIntelData {
                data,
                cached_at: Utc::now(),
            },
        );
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        cache.clear();
    }
}

impl ThreatIntelData {
    /// Merge intelligence from multiple sources
    fn merge(&mut self, other: ThreatIntelData) {
        // Take the higher reputation score (more suspicious)
        if other.reputation_score > self.reputation_score {
            self.reputation_score = other.reputation_score;
        }

        // Merge categories
        for category in other.categories {
            if !self.categories.contains(&category) {
                self.categories.push(category);
            }
        }

        // Merge malware names
        for malware in other.related_malware {
            if !self.related_malware.contains(&malware) {
                self.related_malware.push(malware);
            }
        }

        // Update source to indicate multiple
        if !self.source.contains("Multiple") {
            self.source = format!("{}, {}", self.source, other.source);
        }

        // Use most recent last_seen
        match (self.last_seen, other.last_seen) {
            (Some(a), Some(b)) => {
                if b > a {
                    self.last_seen = Some(b);
                }
            }
            (None, Some(b)) => {
                self.last_seen = Some(b);
            }
            _ => {}
        }
    }
}

// VirusTotal API Response Types
#[derive(Debug, Deserialize)]
struct VirusTotalResponse {
    data: VTData,
}

#[derive(Debug, Deserialize)]
struct VTData {
    attributes: VTAttributes,
}

#[derive(Debug, Deserialize)]
struct VTAttributes {
    last_analysis_stats: VTStats,
    popular_threat_classification: VTThreatClassification,
    names: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct VTStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
}

#[derive(Debug, Deserialize)]
struct VTThreatClassification {
    threat_label: HashMap<String, u32>,
}

// AbuseIPDB API Response Types
#[derive(Debug, Deserialize)]
struct AbuseIPDBResponse {
    data: AbuseIPDBData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AbuseIPDBData {
    abuse_confidence_score: u32,
    is_whitelisted: bool,
    total_reports: u32,
}

/// Local threat intelligence database
pub struct LocalThreatIntel {
    known_malicious_hashes: HashMap<String, String>,
    known_malicious_ips: HashMap<String, String>,
    known_c2_domains: Vec<String>,
}

impl LocalThreatIntel {
    pub fn new() -> Self {
        Self {
            known_malicious_hashes: Self::load_malicious_hashes(),
            known_malicious_ips: Self::load_malicious_ips(),
            known_c2_domains: Self::load_c2_domains(),
        }
    }

    /// Check if hash is known malicious
    pub fn is_malicious_hash(&self, hash: &str) -> Option<&String> {
        self.known_malicious_hashes.get(hash)
    }

    /// Check if IP is known malicious
    pub fn is_malicious_ip(&self, ip: &str) -> Option<&String> {
        self.known_malicious_ips.get(ip)
    }

    /// Check if domain is known C2
    pub fn is_c2_domain(&self, domain: &str) -> bool {
        self.known_c2_domains.iter().any(|d| domain.contains(d))
    }

    /// Load known malicious file hashes
    fn load_malicious_hashes() -> HashMap<String, String> {
        // In production, load from database or file
        // These are example hashes of known malware
        HashMap::from([
            // WannaCry
            ("84c82835a5d21bbcf75a61706d8ab549".to_string(), "WannaCry Ransomware".to_string()),
            // Mimikatz
            ("1c6f4b7c6d0c5a5e5b5c5e5f5d5a5b5c".to_string(), "Mimikatz".to_string()),
        ])
    }

    /// Load known malicious IPs
    fn load_malicious_ips() -> HashMap<String, String> {
        // In production, load from threat feeds
        HashMap::new()
    }

    /// Load known C2 domains
    fn load_c2_domains() -> Vec<String> {
        // In production, load from threat intelligence feeds
        vec![
            "pastebin.com".to_string(), // Often used for C2
            "ngrok.io".to_string(),      // Tunneling service
        ]
    }

    /// Update threat intelligence database
    pub fn update(&mut self) {
        // In production, fetch latest threat feeds
        self.known_malicious_hashes = Self::load_malicious_hashes();
        self.known_malicious_ips = Self::load_malicious_ips();
        self.known_c2_domains = Self::load_c2_domains();
    }
}

impl Default for LocalThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}
