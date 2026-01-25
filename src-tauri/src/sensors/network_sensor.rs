// Network Sensor - monitors per-process network connections

use super::*;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Debug, Clone)]
struct Connection {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    protocol: String,
    state: String,
    inode: u64,
    pid: Option<u32>,
}

pub struct NetworkSensor {
    running: bool,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    known_connections: Arc<Mutex<HashSet<String>>>,
}

impl NetworkSensor {
    #[cfg(target_os = "linux")]
    pub fn new_linux() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_connections: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_windows() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_connections: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_macos() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_connections: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "linux")]
    /// Parse /proc/net/tcp or /proc/net/tcp6
    fn parse_proc_net_tcp(path: &str, protocol: &str) -> Vec<Connection> {
        let mut connections = Vec::new();

        if let Ok(content) = fs::read_to_string(path) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue; // Skip header
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                // Parse local address (format: hex_ip:hex_port)
                let local_parts: Vec<&str> = parts[1].split(':').collect();
                if local_parts.len() != 2 {
                    continue;
                }

                // Parse remote address
                let remote_parts: Vec<&str> = parts[2].split(':').collect();
                if remote_parts.len() != 2 {
                    continue;
                }

                let local_ip = Self::parse_hex_ip(local_parts[0], protocol.contains('6'));
                let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);
                let remote_ip = Self::parse_hex_ip(remote_parts[0], protocol.contains('6'));
                let remote_port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

                // Parse state (0A = LISTEN, 01 = ESTABLISHED, etc.)
                let state = match parts[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "04" => "FIN_WAIT1",
                    "05" => "FIN_WAIT2",
                    "06" => "TIME_WAIT",
                    "07" => "CLOSE",
                    "08" => "CLOSE_WAIT",
                    "09" => "LAST_ACK",
                    "0A" => "LISTEN",
                    _ => "UNKNOWN",
                };

                // Parse inode
                let inode = parts[9].parse::<u64>().unwrap_or(0);

                connections.push(Connection {
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    protocol: protocol.to_string(),
                    state: state.to_string(),
                    inode,
                    pid: None,
                });
            }
        }

        connections
    }

    #[cfg(target_os = "linux")]
    /// Parse /proc/net/udp or /proc/net/udp6
    fn parse_proc_net_udp(path: &str, protocol: &str) -> Vec<Connection> {
        let mut connections = Vec::new();

        if let Ok(content) = fs::read_to_string(path) {
            for (i, line) in content.lines().enumerate() {
                if i == 0 {
                    continue;
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let local_parts: Vec<&str> = parts[1].split(':').collect();
                if local_parts.len() != 2 {
                    continue;
                }

                let remote_parts: Vec<&str> = parts[2].split(':').collect();
                if remote_parts.len() != 2 {
                    continue;
                }

                let local_ip = Self::parse_hex_ip(local_parts[0], protocol.contains('6'));
                let local_port = u16::from_str_radix(local_parts[1], 16).unwrap_or(0);
                let remote_ip = Self::parse_hex_ip(remote_parts[0], protocol.contains('6'));
                let remote_port = u16::from_str_radix(remote_parts[1], 16).unwrap_or(0);

                let inode = parts[9].parse::<u64>().unwrap_or(0);

                connections.push(Connection {
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    protocol: protocol.to_string(),
                    state: "UDP".to_string(),
                    inode,
                    pid: None,
                });
            }
        }

        connections
    }

    #[cfg(target_os = "linux")]
    /// Parse hex IP address from /proc/net format
    fn parse_hex_ip(hex: &str, is_ipv6: bool) -> String {
        if is_ipv6 {
            // IPv6 format: 32 hex chars (16 bytes in little-endian)
            if hex.len() == 32 {
                let bytes: Result<Vec<u8>, _> = (0..32)
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                    .collect();

                if let Ok(bytes) = bytes {
                    // Convert to big-endian 16-byte array for IPv6
                    let mut addr_bytes = [0u8; 16];
                    for i in 0..16 {
                        addr_bytes[i] = bytes[i];
                    }
                    let addr = Ipv6Addr::from(addr_bytes);
                    return addr.to_string();
                }
            }
            "::".to_string()
        } else {
            // IPv4 format: 8 hex chars (4 bytes in little-endian)
            if let Ok(hex_val) = u32::from_str_radix(hex, 16) {
                // Convert from little-endian to big-endian
                let bytes = hex_val.to_le_bytes();
                let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                return addr.to_string();
            }
            "0.0.0.0".to_string()
        }
    }

    #[cfg(target_os = "linux")]
    /// Map inodes to PIDs by scanning /proc/[pid]/fd/
    fn map_inodes_to_pids() -> HashMap<u64, u32> {
        let mut inode_to_pid = HashMap::new();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    if let Some(name_str) = name.to_str() {
                        if let Ok(pid) = name_str.parse::<u32>() {
                            // Read /proc/[pid]/fd/
                            let fd_path = path.join("fd");
                            if let Ok(fd_entries) = fs::read_dir(fd_path) {
                                for fd_entry in fd_entries.flatten() {
                                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                                        if let Some(link_str) = link.to_str() {
                                            // Check if it's a socket (format: "socket:[inode]")
                                            if link_str.starts_with("socket:[") {
                                                let inode_str = link_str
                                                    .trim_start_matches("socket:[")
                                                    .trim_end_matches(']');
                                                if let Ok(inode) = inode_str.parse::<u64>() {
                                                    inode_to_pid.insert(inode, pid);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        inode_to_pid
    }

    #[cfg(target_os = "linux")]
    /// Get all current network connections with process mapping
    fn get_connections() -> Vec<Connection> {
        let mut connections = Vec::new();

        // Parse TCP connections
        connections.extend(Self::parse_proc_net_tcp("/proc/net/tcp", "TCP"));
        connections.extend(Self::parse_proc_net_tcp("/proc/net/tcp6", "TCP6"));

        // Parse UDP sockets
        connections.extend(Self::parse_proc_net_udp("/proc/net/udp", "UDP"));
        connections.extend(Self::parse_proc_net_udp("/proc/net/udp6", "UDP6"));

        // Map inodes to PIDs
        let inode_to_pid = Self::map_inodes_to_pids();

        for conn in &mut connections {
            if let Some(pid) = inode_to_pid.get(&conn.inode) {
                conn.pid = Some(*pid);
            }
        }

        connections
    }

    #[cfg(target_os = "linux")]
    /// Create a NetworkConnection event from a connection
    fn create_connection_event(&self, conn: &Connection) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::NetworkConnection);
        event.severity = EventSeverity::Info;

        // Build network context
        event.network = Some(NetworkContext {
            source_ip: Some(conn.local_ip.clone()),
            source_port: Some(conn.local_port),
            destination_ip: conn.remote_ip.clone(),
            destination_port: conn.remote_port,
            protocol: conn.protocol.clone(),
            direction: NetworkDirection::Outbound,
            dns_query: None,
            dns_response: None,
            ja3_hash: None,
            sni: None,
            bytes_sent: None,
            bytes_received: None,
        });

        // Add process info if available
        if let Some(pid) = conn.pid {
            // Try to get process name from /proc/[pid]/comm
            let comm_path = format!("/proc/{}/comm", pid);
            let process_name = fs::read_to_string(&comm_path)
                .unwrap_or_else(|_| "unknown".to_string())
                .trim()
                .to_string();

            let exe_path = format!("/proc/{}/exe", pid);
            let process_path = fs::read_link(&exe_path)
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .unwrap_or_else(|| "unknown".to_string());

            event.process = Some(ProcessContext {
                pid,
                name: process_name.clone(),
                path: process_path,
                command_line: None,
                parent_pid: None,
                parent_name: None,
                parent_path: None,
                user: None,
                integrity_level: None,
                hash_sha256: None,
                hash_md5: None,
                signer: None,
                signed: None,
            });
        }

        // Add tags
        event.add_tag("network");
        event.add_tag(&conn.protocol.to_lowercase());

        // Check for suspicious patterns
        self.check_suspicious_connection(&mut event, conn);

        event
    }

    #[cfg(target_os = "linux")]
    /// Check for suspicious connection patterns
    fn check_suspicious_connection(&self, event: &mut SecurityEvent, conn: &Connection) {
        // Check for connections to unusual ports
        let suspicious_ports = vec![
            4444, 5555, 6666, 7777, 8888, 9999, // Common backdoor ports
            31337, 12345, // Classic hacker ports
        ];

        if suspicious_ports.contains(&conn.remote_port) {
            event.add_tag("suspicious_port");
            event.severity = EventSeverity::Medium;
        }

        // Check for DNS queries (UDP port 53)
        if conn.protocol.contains("UDP") && conn.remote_port == 53 {
            event.event_type = EventType::NetworkDNSQuery;
            event.add_tag("dns");
        }

        // Check for connections to localhost from non-localhost
        if conn.remote_ip == "127.0.0.1" && conn.local_ip != "127.0.0.1" {
            event.add_tag("localhost_connection");
        }

        // Check for common C2 ports
        let c2_ports = vec![443, 8443, 8080]; // HTTPS-based C2
        if c2_ports.contains(&conn.remote_port) && event.process.is_some() {
            // Could be normal HTTPS, but worth tagging for correlation
            event.add_tag("https_connection");
        }

        // Check for connections to private IPs from public IPs
        if Self::is_private_ip(&conn.remote_ip) && !Self::is_private_ip(&conn.local_ip) {
            event.add_tag("private_ip_connection");
        }
    }

    #[cfg(target_os = "linux")]
    /// Check if IP is in private range
    fn is_private_ip(ip: &str) -> bool {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            match addr {
                IpAddr::V4(ipv4) => {
                    let octets = ipv4.octets();
                    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                    octets[0] == 10
                        || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
                        || (octets[0] == 192 && octets[1] == 168)
                        || octets[0] == 127 // localhost
                }
                IpAddr::V6(ipv6) => {
                    ipv6.is_loopback() || ipv6.segments()[0] == 0xfc00 || ipv6.segments()[0] == 0xfd00
                }
            }
        } else {
            false
        }
    }

    // ===== Windows-specific implementations =====

    #[cfg(target_os = "windows")]
    /// Get TCP and UDP connections using GetExtendedTcpTable and GetExtendedUdpTable
    fn get_connections() -> Vec<Connection> {
        let mut connections = Vec::new();

        // Get TCP connections
        connections.extend(Self::get_windows_tcp_connections());

        // Get UDP connections
        connections.extend(Self::get_windows_udp_connections());

        connections
    }

    #[cfg(target_os = "windows")]
    /// Get TCP connections using GetExtendedTcpTable
    fn get_windows_tcp_connections() -> Vec<Connection> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::*;
        use std::mem;

        let mut connections = Vec::new();

        unsafe {
            // First call to get buffer size (IPv4)
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );

                if result.is_ok() {
                    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                    let num_entries = (*table).dwNumEntries as usize;

                    for i in 0..num_entries {
                        let entry_ptr = (table as usize + mem::size_of::<u32>() + i * mem::size_of::<MIB_TCPROW_OWNER_PID>()) as *const MIB_TCPROW_OWNER_PID;
                        let entry = &*entry_ptr;

                        let local_ip = Ipv4Addr::from(u32::from_be(entry.dwLocalAddr));
                        let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);
                        let remote_ip = Ipv4Addr::from(u32::from_be(entry.dwRemoteAddr));
                        let remote_port = u16::from_be((entry.dwRemotePort & 0xFFFF) as u16);

                        let state = match entry.dwState {
                            1 => "CLOSED",
                            2 => "LISTEN",
                            3 => "SYN_SENT",
                            4 => "SYN_RCVD",
                            5 => "ESTABLISHED",
                            6 => "FIN_WAIT1",
                            7 => "FIN_WAIT2",
                            8 => "CLOSE_WAIT",
                            9 => "CLOSING",
                            10 => "LAST_ACK",
                            11 => "TIME_WAIT",
                            12 => "DELETE_TCB",
                            _ => "UNKNOWN",
                        };

                        connections.push(Connection {
                            local_ip: local_ip.to_string(),
                            local_port,
                            remote_ip: remote_ip.to_string(),
                            remote_port,
                            protocol: "tcp".to_string(),
                            state: state.to_string(),
                            inode: 0, // Windows doesn't use inodes
                            pid: Some(entry.dwOwningPid),
                        });
                    }
                }
            }
        }

        connections
    }

    #[cfg(target_os = "windows")]
    /// Get UDP connections using GetExtendedUdpTable
    fn get_windows_udp_connections() -> Vec<Connection> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::*;
        use std::mem;

        let mut connections = Vec::new();

        unsafe {
            // First call to get buffer size (IPv4)
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                );

                if result.is_ok() {
                    let table = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                    let num_entries = (*table).dwNumEntries as usize;

                    for i in 0..num_entries {
                        let entry_ptr = (table as usize + mem::size_of::<u32>() + i * mem::size_of::<MIB_UDPROW_OWNER_PID>()) as *const MIB_UDPROW_OWNER_PID;
                        let entry = &*entry_ptr;

                        let local_ip = Ipv4Addr::from(u32::from_be(entry.dwLocalAddr));
                        let local_port = u16::from_be((entry.dwLocalPort & 0xFFFF) as u16);

                        connections.push(Connection {
                            local_ip: local_ip.to_string(),
                            local_port,
                            remote_ip: "0.0.0.0".to_string(),
                            remote_port: 0,
                            protocol: "udp".to_string(),
                            state: "LISTENING".to_string(),
                            inode: 0, // Windows doesn't use inodes
                            pid: Some(entry.dwOwningPid),
                        });
                    }
                }
            }
        }

        connections
    }

    #[cfg(target_os = "windows")]
    /// Create network connection event (Windows version)
    fn create_connection_event(&self, conn: &Connection) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::NetworkConnection);
        event.severity = EventSeverity::Info;

        event.add_tag("network");
        event.add_tag(&conn.protocol);

        // Add network context
        event.network = Some(NetworkContext {
            source_ip: Some(conn.local_ip.clone()),
            source_port: Some(conn.local_port),
            destination_ip: conn.remote_ip.clone(),
            destination_port: conn.remote_port,
            protocol: conn.protocol.clone(),
            direction: NetworkDirection::Outbound,
            dns_query: None,
            dns_response: None,
            ja3_hash: None,
            sni: None,
            bytes_sent: None,
            bytes_received: None,
        });

        // Check for suspicious patterns
        if Self::is_suspicious_connection(conn) {
            event.add_tag("suspicious");
            event.severity = EventSeverity::Medium;
        }

        // Check for known bad ports
        if Self::is_suspicious_port(conn.remote_port) {
            event.add_tag("suspicious_port");
            event.severity = EventSeverity::High;
            event.set_mitre(
                vec!["Command and Control".to_string()],
                vec!["T1071".to_string()], // Application Layer Protocol
            );
        }

        event
    }

    // ===== Stub implementations for non-Linux, non-Windows platforms =====

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_connections() -> Vec<Connection> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_connection_event(&self, _conn: &Connection) -> SecurityEvent {
        SecurityEvent::new(EventType::NetworkConnection)
    }
}

#[async_trait::async_trait]
impl EventCollector for NetworkSensor {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running = true;

        #[cfg(target_os = "linux")]
        {
            // Initialize known connections
            let connections = Self::get_connections();
            let mut known = self.known_connections.lock();
            for conn in connections {
                let conn_id = format!(
                    "{}:{}->{}:{}",
                    conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
                );
                known.insert(conn_id);
            }
            drop(known);

            // Start background monitoring
            let known_connections = Arc::clone(&self.known_connections);
            let events = Arc::clone(&self.events);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

                loop {
                    interval.tick().await;

                    let connections = NetworkSensor::get_connections();
                    let mut known = known_connections.lock();

                    for conn in connections {
                        // Only track ESTABLISHED connections and UDP with remote port
                        if (conn.state == "ESTABLISHED" || (conn.protocol.contains("UDP") && conn.remote_port != 0))
                            && conn.remote_ip != "0.0.0.0"
                            && conn.remote_ip != "::"
                        {
                            let conn_id = format!(
                                "{}:{}->{}:{}",
                                conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
                            );

                            if !known.contains(&conn_id) {
                                // New connection detected
                                let sensor = NetworkSensor {
                                    running: true,
                                    events: Arc::new(Mutex::new(Vec::new())),
                                    known_connections: Arc::new(Mutex::new(HashSet::new())),
                                };
                                let event = sensor.create_connection_event(&conn);
                                events.lock().push(event);
                                known.insert(conn_id);
                            }
                        }
                    }
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            // Initialize known connections
            let connections = Self::get_connections();
            let mut known = self.known_connections.lock();
            for conn in connections {
                let conn_id = format!(
                    "{}:{}->{}:{}",
                    conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
                );
                known.insert(conn_id);
            }
            drop(known);

            // Start background monitoring
            let known_connections = Arc::clone(&self.known_connections);
            let events = Arc::clone(&self.events);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

                loop {
                    interval.tick().await;

                    let connections = NetworkSensor::get_connections();
                    let mut known = known_connections.lock();

                    for conn in connections {
                        // Only track ESTABLISHED connections and UDP with remote port
                        if (conn.state == "ESTABLISHED" || (conn.protocol.contains("udp") && conn.remote_port != 0))
                            && conn.remote_ip != "0.0.0.0"
                            && conn.remote_ip != "::"
                        {
                            let conn_id = format!(
                                "{}:{}->{}:{}",
                                conn.local_ip, conn.local_port, conn.remote_ip, conn.remote_port
                            );

                            if !known.contains(&conn_id) {
                                // New connection detected
                                let sensor = NetworkSensor {
                                    running: true,
                                    events: Arc::new(Mutex::new(Vec::new())),
                                    known_connections: Arc::new(Mutex::new(HashSet::new())),
                                };
                                let event = sensor.create_connection_event(&conn);
                                events.lock().push(event);
                                known.insert(conn_id);
                            }
                        }
                    }
                }
            });
        }

        Ok(())
    }

    async fn stop(&mut self) {
        self.running = false;
    }

    async fn collect_events(&mut self) -> Vec<SecurityEvent> {
        let mut events = self.events.lock();
        events.drain(..).collect()
    }

    fn is_running(&self) -> bool {
        self.running
    }
}
