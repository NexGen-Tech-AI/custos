// GeoIP and ASN Lookup - Using MaxMind GeoLite2 databases
// For production: Download GeoLite2-City.mmdb and GeoLite2-ASN.mmdb from MaxMind

use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIPInfo {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
    pub is_known_vpn: bool,
    pub is_tor: bool,
    pub is_hosting: bool,
    pub is_proxy: bool,
}

pub struct GeoIPLookup {
    // In production, these would be MaxMind database readers
    // For now, we'll use a simple in-memory approach
    enabled: bool,
}

impl GeoIPLookup {
    pub fn new() -> Self {
        Self {
            enabled: false,  // Will be true when MaxMind DBs are available
        }
    }

    /// Look up IP address information
    pub fn lookup(&self, ip: &str) -> Result<GeoIPInfo, String> {
        if !self.enabled {
            return Ok(Self::mock_lookup(ip));
        }

        // TODO: Implement actual MaxMind database lookup
        // This would use the maxminddb crate:
        //
        // let reader = maxminddb::Reader::open_readfile(db_path)?;
        // let city: maxminddb::geoip2::City = reader.lookup(ip_addr)?;
        // ...

        Ok(Self::mock_lookup(ip))
    }

    /// Mock lookup for development/testing
    fn mock_lookup(ip: &str) -> GeoIPInfo {
        // Classify IP for demo purposes
        let (is_private, is_vpn, is_tor, country) = Self::classify_ip(ip);

        GeoIPInfo {
            ip: ip.to_string(),
            country_code: if !is_private { Some(country.to_string()) } else { None },
            country_name: if !is_private { Some(Self::country_name(&country)) } else { None },
            city: None,
            asn: if !is_private { Some(Self::mock_asn(ip)) } else { None },
            asn_org: if !is_private {
                Some(Self::mock_asn_org(ip))
            } else {
                None
            },
            is_known_vpn: is_vpn,
            is_tor,
            is_hosting: Self::is_hosting_ip(ip),
            is_proxy: is_vpn,
        }
    }

    /// Classify IP for demo purposes
    fn classify_ip(ip: &str) -> (bool, bool, bool, &'static str) {
        if let Ok(addr) = IpAddr::from_str(ip) {
            match addr {
                IpAddr::V4(v4) => {
                    if v4.is_private() || v4.is_loopback() {
                        return (true, false, false, "");
                    }

                    // Mock classification based on IP ranges
                    let octets = v4.octets();
                    let country = match octets[0] {
                        1..=50 => "US",
                        51..=100 => "EU",
                        101..=150 => "CN",
                        151..=200 => "RU",
                        _ => "XX",
                    };

                    // Mock VPN/Tor detection (in production, use threat intel feeds)
                    let is_vpn = octets[3] % 10 == 0;
                    let is_tor = octets[3] % 20 == 0;

                    (false, is_vpn, is_tor, country)
                }
                IpAddr::V6(_) => (false, false, false, "XX"),
            }
        } else {
            (true, false, false, "")
        }
    }

    /// Mock ASN number
    fn mock_asn(ip: &str) -> u32 {
        // Simple hash of IP to generate consistent ASN
        let hash: u32 = ip.bytes().map(|b| b as u32).sum();
        15169 + (hash % 10000)  // Base ASN around Google's ASN
    }

    /// Mock ASN organization name
    fn mock_asn_org(ip: &str) -> String {
        let asn = Self::mock_asn(ip);
        match asn % 5 {
            0 => "Amazon Web Services".to_string(),
            1 => "Google LLC".to_string(),
            2 => "Cloudflare Inc".to_string(),
            3 => "Microsoft Corporation".to_string(),
            _ => format!("ISP-{}", asn),
        }
    }

    /// Check if IP is likely a hosting provider
    fn is_hosting_ip(ip: &str) -> bool {
        // In production, check against known hosting ranges
        if let Ok(addr) = IpAddr::from_str(ip) {
            if let IpAddr::V4(v4) = addr {
                let octets = v4.octets();
                // Mock: Consider certain ranges as hosting
                return octets[0] >= 3 && octets[0] <= 18;  // AWS ranges (mock)
            }
        }
        false
    }

    /// Get full country name from code
    fn country_name(code: &str) -> String {
        match code {
            "US" => "United States",
            "EU" => "European Union",
            "CN" => "China",
            "RU" => "Russia",
            "GB" => "United Kingdom",
            "DE" => "Germany",
            "FR" => "France",
            "JP" => "Japan",
            "IN" => "India",
            "BR" => "Brazil",
            _ => "Unknown",
        }
        .to_string()
    }

    /// Check if IP is suspicious based on characteristics
    pub fn is_suspicious(&self, info: &GeoIPInfo) -> (bool, Vec<String>) {
        let mut is_suspicious = false;
        let mut reasons = Vec::new();

        if info.is_tor {
            is_suspicious = true;
            reasons.push("Connection from Tor exit node".to_string());
        }

        if info.is_known_vpn && !info.is_hosting {
            // VPN but not from hosting provider (residential VPN)
            reasons.push("Connection from VPN/Proxy".to_string());
        }

        // Check for high-risk countries (configurable in production)
        if let Some(ref country) = info.country_code {
            if matches!(country.as_str(), "CN" | "RU" | "KP" | "IR") {
                reasons.push(format!("Connection from high-risk country: {}", country));
            }
        }

        (is_suspicious, reasons)
    }
}

impl Default for GeoIPLookup {
    fn default() -> Self {
        Self::new()
    }
}

/// ASN reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ASNReputation {
    pub asn: u32,
    pub org: String,
    pub reputation_score: f64,  // 0.0 (malicious) to 1.0 (trustworthy)
    pub known_threats: usize,
    pub is_hosting: bool,
    pub is_vpn: bool,
}

impl ASNReputation {
    /// Get reputation for an ASN (mock implementation)
    pub fn lookup(asn: u32) -> Self {
        // In production, query threat intel feeds
        let reputation_score = match asn {
            15169 => 0.95,  // Google
            16509 => 0.95,  // Amazon
            13335 => 0.95,  // Cloudflare
            _ => {
                // Mock: Lower score for higher ASN numbers
                1.0 - (asn as f64 % 1000.0) / 2000.0
            }
        };

        Self {
            asn,
            org: format!("AS{} Organization", asn),
            reputation_score,
            known_threats: if reputation_score < 0.5 { (asn % 100) as usize } else { 0 },
            is_hosting: matches!(asn, 15169 | 16509 | 13335),
            is_vpn: asn % 7 == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_lookup() {
        let geoip = GeoIPLookup::new();

        let result = geoip.lookup("8.8.8.8").unwrap();
        assert!(result.country_code.is_some());
        assert!(result.asn.is_some());
    }

    #[test]
    fn test_private_ip_lookup() {
        let geoip = GeoIPLookup::new();

        let result = geoip.lookup("192.168.1.1").unwrap();
        assert!(result.country_code.is_none());
        assert!(result.asn.is_none());
    }
}
