// Hardware Detection for AI Model Tier Eligibility
// Detects RAM, VRAM, GPU capabilities to determine which Ollama models can run

use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub total_ram_gb: f64,
    pub available_ram_gb: f64,
    pub gpu_available: bool,
    pub gpu_name: Option<String>,
    pub gpu_vram_gb: Option<f64>,
    pub cpu_cores: usize,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRequirements {
    pub name: String,
    pub min_ram_gb: f64,
    pub recommended_ram_gb: f64,
    pub min_vram_gb: Option<f64>, // None if CPU-only is acceptable
    pub gpu_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TierLevel {
    Standard,
    Pro,
    Elite,
}

impl TierLevel {
    pub fn model_name(&self) -> &str {
        match self {
            TierLevel::Standard => "mistral:7b",
            TierLevel::Pro => "qwen2.5:14b", // Using Qwen 2.5 14B as it's more available than GPT-OSS
            TierLevel::Elite => "llama3.1:70b", // Using Llama 3.1 70B as it's more reliable than GPT-OSS 120B
        }
    }

    pub fn requirements(&self) -> ModelRequirements {
        match self {
            TierLevel::Standard => ModelRequirements {
                name: "Mistral 7B".to_string(),
                min_ram_gb: 8.0,
                recommended_ram_gb: 12.0,
                min_vram_gb: None, // Can run on CPU
                gpu_required: false,
            },
            TierLevel::Pro => ModelRequirements {
                name: "Qwen 2.5 14B".to_string(),
                min_ram_gb: 16.0,
                recommended_ram_gb: 24.0,
                min_vram_gb: Some(12.0),
                gpu_required: false, // Recommended but not required
            },
            TierLevel::Elite => ModelRequirements {
                name: "Llama 3.1 70B".to_string(),
                min_ram_gb: 48.0,
                recommended_ram_gb: 64.0,
                min_vram_gb: Some(48.0),
                gpu_required: true, // Practically required for reasonable performance
            },
        }
    }
}

pub struct HardwareDetector;

impl HardwareDetector {
    /// Detect hardware capabilities of the current system
    pub fn detect() -> Result<HardwareCapabilities, String> {
        let platform = std::env::consts::OS.to_string();

        let (total_ram_gb, available_ram_gb) = Self::detect_ram(&platform)?;
        let cpu_cores = num_cpus::get();
        let (gpu_available, gpu_name, gpu_vram_gb) = Self::detect_gpu(&platform);

        Ok(HardwareCapabilities {
            total_ram_gb,
            available_ram_gb,
            gpu_available,
            gpu_name,
            gpu_vram_gb,
            cpu_cores,
            platform,
        })
    }

    /// Detect RAM (total and available)
    fn detect_ram(platform: &str) -> Result<(f64, f64), String> {
        match platform {
            "linux" => Self::detect_ram_linux(),
            "windows" => Self::detect_ram_windows(),
            "macos" => Self::detect_ram_macos(),
            _ => Err(format!("Unsupported platform: {}", platform)),
        }
    }

    fn detect_ram_linux() -> Result<(f64, f64), String> {
        let output = Command::new("free")
            .arg("-b")
            .output()
            .map_err(|e| format!("Failed to run free command: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse 'free -b' output
        for line in output_str.lines() {
            if line.starts_with("Mem:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    let total_bytes: u64 = parts[1].parse().unwrap_or(0);
                    let available_bytes: u64 = parts[6].parse().unwrap_or(parts[3].parse().unwrap_or(0));

                    let total_gb = total_bytes as f64 / 1_073_741_824.0; // Convert to GB
                    let available_gb = available_bytes as f64 / 1_073_741_824.0;

                    return Ok((total_gb, available_gb));
                }
            }
        }

        Err("Failed to parse RAM information".to_string())
    }

    fn detect_ram_windows() -> Result<(f64, f64), String> {
        // Use systeminfo or wmic
        let output = Command::new("wmic")
            .args(&["OS", "get", "TotalVisibleMemorySize,FreePhysicalMemory", "/value"])
            .output()
            .map_err(|e| format!("Failed to run wmic: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        let mut total_kb = 0u64;
        let mut free_kb = 0u64;

        for line in output_str.lines() {
            if line.starts_with("TotalVisibleMemorySize=") {
                total_kb = line.split('=').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
            } else if line.starts_with("FreePhysicalMemory=") {
                free_kb = line.split('=').nth(1).unwrap_or("0").trim().parse().unwrap_or(0);
            }
        }

        let total_gb = total_kb as f64 / 1_048_576.0; // KB to GB
        let available_gb = free_kb as f64 / 1_048_576.0;

        Ok((total_gb, available_gb))
    }

    fn detect_ram_macos() -> Result<(f64, f64), String> {
        // Get total RAM
        let output = Command::new("sysctl")
            .arg("hw.memsize")
            .output()
            .map_err(|e| format!("Failed to run sysctl: {}", e))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let total_bytes: u64 = output_str
            .split(':')
            .nth(1)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);

        // Get available RAM (approximate using vm_stat)
        let vm_output = Command::new("vm_stat")
            .output()
            .map_err(|e| format!("Failed to run vm_stat: {}", e))?;

        let vm_str = String::from_utf8_lossy(&vm_output.stdout);
        let mut free_pages = 0u64;

        for line in vm_str.lines() {
            if line.contains("Pages free:") {
                free_pages = line
                    .split(':')
                    .nth(1)
                    .and_then(|s| s.trim().trim_end_matches('.').parse().ok())
                    .unwrap_or(0);
                break;
            }
        }

        let page_size = 4096u64; // macOS page size
        let available_bytes = free_pages * page_size;

        let total_gb = total_bytes as f64 / 1_073_741_824.0;
        let available_gb = available_bytes as f64 / 1_073_741_824.0;

        Ok((total_gb, available_gb))
    }

    /// Detect GPU (availability, name, VRAM)
    fn detect_gpu(platform: &str) -> (bool, Option<String>, Option<f64>) {
        match platform {
            "linux" => Self::detect_gpu_linux(),
            "windows" => Self::detect_gpu_windows(),
            "macos" => Self::detect_gpu_macos(),
            _ => (false, None, None),
        }
    }

    fn detect_gpu_linux() -> (bool, Option<String>, Option<f64>) {
        // Try nvidia-smi first
        if let Ok(output) = Command::new("nvidia-smi")
            .args(&["--query-gpu=name,memory.total", "--format=csv,noheader"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(line) = output_str.lines().next() {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 2 {
                    let gpu_name = parts[0].trim().to_string();
                    let vram_str = parts[1].trim().replace(" MiB", "");
                    let vram_mb: f64 = vram_str.parse().unwrap_or(0.0);
                    let vram_gb = vram_mb / 1024.0;

                    return (true, Some(gpu_name), Some(vram_gb));
                }
            }
        }

        // Try lspci for AMD or Intel GPUs
        if let Ok(output) = Command::new("lspci").output() {
            let output_str = String::from_utf8_lossy(&output.stdout);
            for line in output_str.lines() {
                if line.contains("VGA compatible controller") || line.contains("3D controller") {
                    let gpu_info = line.split(':').last().unwrap_or("Unknown GPU").trim().to_string();
                    return (true, Some(gpu_info), None); // Can't reliably get VRAM without nvidia-smi
                }
            }
        }

        (false, None, None)
    }

    fn detect_gpu_windows() -> (bool, Option<String>, Option<f64>) {
        // Use wmic to query GPU
        if let Ok(output) = Command::new("wmic")
            .args(&["path", "win32_VideoController", "get", "name,AdapterRAM", "/value"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut gpu_name = None;
            let mut vram_bytes = None;

            for line in output_str.lines() {
                if line.starts_with("Name=") {
                    gpu_name = Some(line.split('=').nth(1).unwrap_or("Unknown").trim().to_string());
                } else if line.starts_with("AdapterRAM=") {
                    let ram_str = line.split('=').nth(1).unwrap_or("0").trim();
                    vram_bytes = ram_str.parse::<u64>().ok();
                }
            }

            if let (Some(name), Some(vram)) = (gpu_name, vram_bytes) {
                let vram_gb = vram as f64 / 1_073_741_824.0;
                return (true, Some(name), Some(vram_gb));
            }
        }

        (false, None, None)
    }

    fn detect_gpu_macos() -> (bool, Option<String>, Option<f64>) {
        // Use system_profiler
        if let Ok(output) = Command::new("system_profiler")
            .arg("SPDisplaysDataType")
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            let mut gpu_name = None;
            let mut vram_gb = None;

            for line in output_str.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("Chipset Model:") {
                    gpu_name = Some(trimmed.split(':').nth(1).unwrap_or("Unknown").trim().to_string());
                } else if trimmed.starts_with("VRAM") {
                    // Parse "VRAM (Total): 8 GB" or similar
                    if let Some(vram_str) = trimmed.split(':').nth(1) {
                        let vram_value = vram_str
                            .split_whitespace()
                            .next()
                            .and_then(|s| s.parse::<f64>().ok());
                        vram_gb = vram_value;
                    }
                }
            }

            if gpu_name.is_some() {
                return (true, gpu_name, vram_gb);
            }
        }

        (false, None, None)
    }

    /// Check if hardware meets requirements for a specific tier
    pub fn can_run_tier(capabilities: &HardwareCapabilities, tier: &TierLevel) -> (bool, Vec<String>) {
        let requirements = tier.requirements();
        let mut reasons = Vec::new();
        let mut can_run = true;

        // Check RAM
        if capabilities.total_ram_gb < requirements.min_ram_gb {
            can_run = false;
            reasons.push(format!(
                "Insufficient RAM: {:.1}GB available, {:.1}GB required (Recommended: {:.1}GB)",
                capabilities.total_ram_gb,
                requirements.min_ram_gb,
                requirements.recommended_ram_gb
            ));
        } else if capabilities.total_ram_gb < requirements.recommended_ram_gb {
            reasons.push(format!(
                "RAM below recommended: {:.1}GB available, {:.1}GB recommended for best performance",
                capabilities.total_ram_gb,
                requirements.recommended_ram_gb
            ));
        }

        // Check GPU if required
        if requirements.gpu_required && !capabilities.gpu_available {
            can_run = false;
            reasons.push("GPU required but not detected".to_string());
        }

        // Check VRAM if specified
        if let Some(required_vram) = requirements.min_vram_gb {
            if let Some(available_vram) = capabilities.gpu_vram_gb {
                if available_vram < required_vram {
                    can_run = false;
                    reasons.push(format!(
                        "Insufficient VRAM: {:.1}GB available, {:.1}GB required",
                        available_vram,
                        required_vram
                    ));
                }
            } else if requirements.gpu_required {
                reasons.push("Could not detect VRAM, GPU may not be suitable".to_string());
            }
        }

        (can_run, reasons)
    }

    /// Get all eligible tiers for the current hardware
    pub fn get_eligible_tiers(capabilities: &HardwareCapabilities) -> Vec<(TierLevel, Vec<String>)> {
        let tiers = vec![TierLevel::Standard, TierLevel::Pro, TierLevel::Elite];
        let mut eligible = Vec::new();

        for tier in tiers {
            let (can_run, reasons) = Self::can_run_tier(capabilities, &tier);
            if can_run {
                eligible.push((tier, reasons));
            }
        }

        eligible
    }

    /// Get the highest tier available for the current hardware
    pub fn get_max_tier(capabilities: &HardwareCapabilities) -> Option<TierLevel> {
        let eligible = Self::get_eligible_tiers(capabilities);
        eligible.last().map(|(tier, _)| tier.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_detection() {
        let caps = HardwareDetector::detect();
        assert!(caps.is_ok());
        let caps = caps.unwrap();
        println!("Detected hardware: {:#?}", caps);
        assert!(caps.total_ram_gb > 0.0);
    }

    #[test]
    fn test_tier_eligibility() {
        let caps = HardwareDetector::detect().unwrap();
        let eligible = HardwareDetector::get_eligible_tiers(&caps);
        println!("Eligible tiers: {:#?}", eligible);
    }
}
