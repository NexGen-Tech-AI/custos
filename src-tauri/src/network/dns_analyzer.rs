// DNS Query Analysis - Detect tunneling, DGA, suspicious domains

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSQuery {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub process_pid: Option<u32>,
    pub process_name: String,
    pub query: String,
    pub query_type: DNSQueryType,
    pub response_code: Option<String>,
    pub is_suspicious: bool,
    pub suspicion_reasons: Vec<String>,
    pub entropy: f64,
    pub subdomain_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DNSQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
    PTR,
    SOA,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DNSAnalyzer {
    // Known bad domains (could be loaded from threat intel)
    bad_domains: Vec<String>,
    // Known good domains (allowlist)
    good_domains: Vec<String>,
}

impl DNSAnalyzer {
    pub fn new() -> Self {
        Self {
            bad_domains: Self::load_bad_domains(),
            good_domains: Self::load_good_domains(),
        }
    }

    /// Analyze a DNS query for suspicious characteristics
    pub fn analyze(&self, query: &str, process_name: &str) -> (bool, Vec<String>) {
        let mut is_suspicious = false;
        let mut reasons = Vec::new();

        // Check if it's in the known bad domains
        if self.is_known_bad(query) {
            is_suspicious = true;
            reasons.push("Known malicious domain".to_string());
        }

        // Check for DNS tunneling (excessive subdomain length)
        if Self::has_excessive_subdomain_length(query) {
            is_suspicious = true;
            reasons.push("Excessive subdomain length (possible DNS tunneling)".to_string());
        }

        // Check for high entropy (DGA - Domain Generation Algorithm)
        let entropy = Self::calculate_entropy(query);
        if entropy > 4.5 {
            is_suspicious = true;
            reasons.push(format!("High entropy: {:.2} (possible DGA)", entropy));
        }

        // Check for excessive subdomain count
        let subdomain_count = query.split('.').count();
        if subdomain_count > 5 {
            is_suspicious = true;
            reasons.push(format!("Excessive subdomain count: {}", subdomain_count));
        }

        // Check for unusual TLDs
        if Self::has_unusual_tld(query) {
            is_suspicious = true;
            reasons.push("Unusual TLD".to_string());
        }

        // Check for IP-like domains (suspicious)
        if Self::looks_like_ip_domain(query) {
            is_suspicious = true;
            reasons.push("Domain resembles IP address".to_string());
        }

        (is_suspicious, reasons)
    }

    /// Check if domain is in known bad list
    fn is_known_bad(&self, query: &str) -> bool {
        for bad_domain in &self.bad_domains {
            if query.ends_with(bad_domain) {
                return true;
            }
        }
        false
    }

    /// Check for excessive subdomain length (DNS tunneling indicator)
    fn has_excessive_subdomain_length(query: &str) -> bool {
        let parts: Vec<&str> = query.split('.').collect();
        for part in parts {
            if part.len() > 40 {
                return true;
            }
        }
        false
    }

    /// Calculate Shannon entropy of domain name
    fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let mut entropy = 0.0;

        for count in freq.values() {
            let p = (*count as f64) / len;
            entropy -= p * p.log2();
        }

        entropy
    }

    /// Check for unusual TLDs
    fn has_unusual_tld(query: &str) -> bool {
        let unusual_tlds = vec![
            ".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs often used by malware
            ".pw", ".top", ".xyz", ".club", ".work",
        ];

        for tld in unusual_tlds {
            if query.ends_with(tld) {
                return true;
            }
        }

        false
    }

    /// Check if domain looks like an IP address (e.g., 192-168-1-1.example.com)
    fn looks_like_ip_domain(query: &str) -> bool {
        // Simple heuristic: contains multiple hyphens or numbers
        let parts: Vec<&str> = query.split('.').collect();
        if let Some(first_part) = parts.first() {
            let hyphen_count = first_part.matches('-').count();
            let digit_count = first_part.chars().filter(|c| c.is_ascii_digit()).count();
            return hyphen_count >= 3 || digit_count > first_part.len() / 2;
        }
        false
    }

    /// Load known bad domains (could be from threat intel feed)
    fn load_bad_domains() -> Vec<String> {
        vec![
            // Examples of known bad domains (in real implementation, load from file/DB)
            "malware.com".to_string(),
            "phishing.example".to_string(),
            "c2server.xyz".to_string(),
        ]
    }

    /// Load known good domains (allowlist)
    fn load_good_domains() -> Vec<String> {
        vec![
            "google.com".to_string(),
            "microsoft.com".to_string(),
            "cloudflare.com".to_string(),
            "amazonaws.com".to_string(),
            "github.com".to_string(),
        ]
    }

    /// Get subdomain count
    pub fn get_subdomain_count(query: &str) -> usize {
        query.split('.').count()
    }

    /// Get entropy
    pub fn get_entropy(query: &str) -> f64 {
        Self::calculate_entropy(query)
    }
}

impl Default for DNSAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        // Low entropy (repeating pattern)
        assert!(DNSAnalyzer::calculate_entropy("aaaaaa") < 1.0);

        // High entropy (random-looking)
        assert!(DNSAnalyzer::calculate_entropy("xk2p9q7m") > 2.5);
    }

    #[test]
    fn test_dga_detection() {
        let analyzer = DNSAnalyzer::new();

        // DGA-like domain
        let (suspicious, reasons) = analyzer.analyze("xjp9k2m7q.com", "malware.exe");
        assert!(suspicious);
        assert!(reasons.iter().any(|r| r.contains("High entropy")));
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let analyzer = DNSAnalyzer::new();

        // DNS tunneling-like query
        let (suspicious, reasons) = analyzer.analyze(
            "verylongsubdomainwithmanycharactersthatlookslikedatatunnelingoverdn.example.com",
            "suspicious.exe",
        );
        assert!(suspicious);
        assert!(reasons.iter().any(|r| r.contains("subdomain length")));
    }
}
