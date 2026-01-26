// Network Segmentation - Classify IPs into segments and apply policies

use serde::{Serialize, Deserialize};
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkSegment {
    LAN,        // Private RFC1918 addresses
    Guest,      // Guest network (user-configurable)
    IoT,        // IoT devices (user-configurable)
    Work,       // Work devices (user-configurable)
    Servers,    // Servers/NAS (user-configurable)
    Internet,   // Everything else (external)
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentConfig {
    pub lan_ranges: Vec<String>,
    pub guest_ranges: Vec<String>,
    pub iot_ranges: Vec<String>,
    pub work_ranges: Vec<String>,
    pub server_ranges: Vec<String>,
}

impl Default for SegmentConfig {
    fn default() -> Self {
        Self {
            lan_ranges: vec![
                "192.168.0.0/16".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
            ],
            guest_ranges: vec![],
            iot_ranges: vec![],
            work_ranges: vec![],
            server_ranges: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentPolicy {
    pub segment: NetworkSegment,
    pub blocked_asns: Vec<u32>,
    pub blocked_countries: Vec<String>,
    pub allowed_ports: Option<Vec<u16>>,  // None = all allowed
    pub blocked_ports: Vec<u16>,
    pub restrict_lateral: bool,  // Block lateral movement (SMB/RDP/SSH between segments)
    pub block_internet: bool,    // Block all internet access
}

impl Default for SegmentPolicy {
    fn default() -> Self {
        Self {
            segment: NetworkSegment::LAN,
            blocked_asns: vec![],
            blocked_countries: vec![],
            allowed_ports: None,
            blocked_ports: vec![],
            restrict_lateral: false,
            block_internet: false,
        }
    }
}

pub struct NetworkSegmentationEngine {
    config: SegmentConfig,
    policies: Vec<SegmentPolicy>,
}

impl NetworkSegmentationEngine {
    pub fn new() -> Self {
        Self {
            config: SegmentConfig::default(),
            policies: Self::default_policies(),
        }
    }

    pub fn with_config(config: SegmentConfig) -> Self {
        Self {
            config,
            policies: Self::default_policies(),
        }
    }

    /// Classify an IP address into a network segment
    pub fn classify_ip(&self, ip: &str) -> NetworkSegment {
        if let Ok(addr) = IpAddr::from_str(ip) {
            // Check if it's a private IP
            if !Self::is_global_ip(&addr) {
                // Check user-defined segments first
                if self.is_in_ranges(ip, &self.config.guest_ranges) {
                    return NetworkSegment::Guest;
                }
                if self.is_in_ranges(ip, &self.config.iot_ranges) {
                    return NetworkSegment::IoT;
                }
                if self.is_in_ranges(ip, &self.config.work_ranges) {
                    return NetworkSegment::Work;
                }
                if self.is_in_ranges(ip, &self.config.server_ranges) {
                    return NetworkSegment::Servers;
                }

                // Default to LAN if it's private but not in specific ranges
                return NetworkSegment::LAN;
            } else {
                // Public IP = Internet
                return NetworkSegment::Internet;
            }
        }

        NetworkSegment::Unknown
    }

    /// Check if IP is in any of the given CIDR ranges
    fn is_in_ranges(&self, ip: &str, ranges: &[String]) -> bool {
        for range in ranges {
            if Self::ip_in_cidr(ip, range) {
                return true;
            }
        }
        false
    }

    /// Check if an IP is in a CIDR range
    fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
        // Simple implementation - in production, use ipnetwork crate
        if let Some((network, mask)) = cidr.split_once('/') {
            if let (Ok(ip_addr), Ok(net_addr)) = (IpAddr::from_str(ip), IpAddr::from_str(network)) {
                if let (IpAddr::V4(ip_v4), IpAddr::V4(net_v4)) = (ip_addr, net_addr) {
                    let mask_bits: u32 = mask.parse().unwrap_or(32);
                    let netmask = !0u32 << (32 - mask_bits);

                    let ip_int = u32::from(ip_v4);
                    let net_int = u32::from(net_v4);

                    return (ip_int & netmask) == (net_int & netmask);
                }
            }
        }
        false
    }

    /// Check if an IP is globally routable (not private/loopback)
    fn is_global_ip(addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => {
                !v4.is_private()
                    && !v4.is_loopback()
                    && !v4.is_link_local()
                    && !v4.is_broadcast()
                    && !v4.is_documentation()
                    && !v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                !v6.is_loopback()
                    && !v6.is_unspecified()
                    && !v6.is_multicast()
            }
        }
    }

    /// Get policy for a segment
    pub fn get_policy(&self, segment: &NetworkSegment) -> Option<SegmentPolicy> {
        self.policies
            .iter()
            .find(|p| &p.segment == segment)
            .cloned()
    }

    /// Update policy for a segment
    pub fn update_policy(&mut self, policy: SegmentPolicy) {
        if let Some(existing) = self.policies.iter_mut().find(|p| p.segment == policy.segment) {
            *existing = policy;
        } else {
            self.policies.push(policy);
        }
    }

    /// Get all policies
    pub fn get_policies(&self) -> &[SegmentPolicy] {
        &self.policies
    }

    /// Check if a connection should be blocked
    pub fn should_block_connection(
        &self,
        source_segment: &NetworkSegment,
        dest_segment: &NetworkSegment,
        dest_port: u16,
    ) -> (bool, Option<String>) {
        if let Some(policy) = self.get_policy(source_segment) {
            // Check if lateral movement is restricted
            if policy.restrict_lateral && source_segment != dest_segment {
                // Check for lateral movement ports (SMB, RDP, SSH, WinRM)
                if matches!(dest_port, 22 | 445 | 3389 | 5985 | 5986) {
                    return (true, Some("Lateral movement blocked by policy".to_string()));
                }
            }

            // Check if internet access is blocked
            if policy.block_internet && *dest_segment == NetworkSegment::Internet {
                return (true, Some("Internet access blocked by policy".to_string()));
            }

            // Check allowed ports
            if let Some(ref allowed) = policy.allowed_ports {
                if !allowed.contains(&dest_port) {
                    return (
                        true,
                        Some(format!("Port {} not in allowed list", dest_port)),
                    );
                }
            }

            // Check blocked ports
            if policy.blocked_ports.contains(&dest_port) {
                return (true, Some(format!("Port {} is blocked", dest_port)));
            }
        }

        (false, None)
    }

    /// Default policies (safe defaults)
    fn default_policies() -> Vec<SegmentPolicy> {
        vec![
            SegmentPolicy {
                segment: NetworkSegment::LAN,
                blocked_asns: vec![],
                blocked_countries: vec![],
                allowed_ports: None,
                blocked_ports: vec![],
                restrict_lateral: false,
                block_internet: false,
            },
            SegmentPolicy {
                segment: NetworkSegment::IoT,
                blocked_asns: vec![],
                blocked_countries: vec![],
                allowed_ports: None,
                blocked_ports: vec![22, 23],  // Block SSH/Telnet on IoT by default
                restrict_lateral: true,       // Prevent IoT lateral movement
                block_internet: false,
            },
            SegmentPolicy {
                segment: NetworkSegment::Guest,
                blocked_asns: vec![],
                blocked_countries: vec![],
                allowed_ports: None,
                blocked_ports: vec![],
                restrict_lateral: true,  // Guests can't access other segments
                block_internet: false,
            },
        ]
    }
}

impl Default for NetworkSegmentationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_private_ip() {
        let engine = NetworkSegmentationEngine::new();

        assert_eq!(engine.classify_ip("192.168.1.1"), NetworkSegment::LAN);
        assert_eq!(engine.classify_ip("10.0.0.1"), NetworkSegment::LAN);
        assert_eq!(engine.classify_ip("172.16.0.1"), NetworkSegment::LAN);
    }

    #[test]
    fn test_classify_public_ip() {
        let engine = NetworkSegmentationEngine::new();

        assert_eq!(engine.classify_ip("8.8.8.8"), NetworkSegment::Internet);
        assert_eq!(engine.classify_ip("1.1.1.1"), NetworkSegment::Internet);
    }

    #[test]
    fn test_lateral_movement_blocking() {
        let engine = NetworkSegmentationEngine::new();

        // IoT to LAN on SMB port should be blocked
        let (blocked, reason) = engine.should_block_connection(
            &NetworkSegment::IoT,
            &NetworkSegment::LAN,
            445,
        );

        assert!(blocked);
        assert!(reason.unwrap().contains("Lateral movement"));
    }
}
