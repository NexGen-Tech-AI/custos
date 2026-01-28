/*!
 * Sudo Authentication Module
 *
 * Provides secure sudo authentication for privileged operations like eBPF monitoring.
 * Uses Tauri's dialog system to prompt users for their password.
 */

use std::process::{Command, Stdio};
use std::io::Write;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoRequest {
    pub operation: String,
    pub reason: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SudoResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Check if the current process has sudo/root privileges
pub fn has_root_privileges() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        // On Windows, check if running as administrator
        is_elevated_windows()
    }
}

#[cfg(windows)]
fn is_elevated_windows() -> bool {
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let mut token = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut return_length = 0;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Execute a command with sudo privileges
///
/// This will validate the password and execute the command if authentication succeeds.
///
/// # Security Notes
/// - Password is never stored
/// - Password is passed via stdin (not command line args)
/// - Command is validated before execution
#[cfg(unix)]
pub fn execute_with_sudo(command: &str, args: &[&str], password: &str) -> Result<String, String> {
    // Validate command to prevent injection
    if command.contains("..") || command.contains(";") || command.contains("|") {
        return Err("Invalid command: potential injection detected".to_string());
    }

    // Build full command
    let mut sudo_cmd = Command::new("sudo");
    sudo_cmd.arg("-S") // Read password from stdin
        .arg(command)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Spawn process
    let mut child = sudo_cmd.spawn().map_err(|e| format!("Failed to spawn sudo: {}", e))?;

    // Write password to stdin
    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", password)
            .map_err(|e| format!("Failed to write password: {}", e))?;
    }

    // Wait for completion
    let output = child.wait_with_output()
        .map_err(|e| format!("Failed to wait for command: {}", e))?;

    if output.status.success() {
        String::from_utf8(output.stdout)
            .map_err(|e| format!("Invalid UTF-8 output: {}", e))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("Command failed: {}", stderr))
    }
}

#[cfg(windows)]
pub fn execute_with_sudo(command: &str, args: &[&str], _password: &str) -> Result<String, String> {
    // On Windows, use runas or elevate
    // This requires UAC prompt, password parameter is ignored
    Err("Windows elevation not yet implemented. Please run as administrator.".to_string())
}

/// Verify sudo password without executing a command
#[cfg(unix)]
pub fn verify_sudo_password(password: &str) -> Result<bool, String> {
    let mut sudo_cmd = Command::new("sudo");
    sudo_cmd.arg("-S")
        .arg("-v") // Validate credentials
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = sudo_cmd.spawn().map_err(|e| format!("Failed to spawn sudo: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        writeln!(stdin, "{}", password)
            .map_err(|e| format!("Failed to write password: {}", e))?;
    }

    let output = child.wait_with_output()
        .map_err(|e| format!("Failed to wait for sudo: {}", e))?;

    Ok(output.status.success())
}

#[cfg(windows)]
pub fn verify_sudo_password(_password: &str) -> Result<bool, String> {
    // Windows uses UAC, not password-based sudo
    Ok(is_elevated_windows())
}

/// Request sudo access with a user-friendly dialog
/// This should be called from the frontend via Tauri command
pub struct SudoAuthenticator {
    cached_valid: std::sync::Arc<std::sync::atomic::AtomicBool>,
    last_check: std::sync::Arc<parking_lot::Mutex<std::time::Instant>>,
}

impl SudoAuthenticator {
    pub fn new() -> Self {
        Self {
            cached_valid: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_check: std::sync::Arc::new(parking_lot::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(3600)
            )),
        }
    }

    /// Check if we have cached sudo access (typically valid for 15 minutes)
    pub fn has_cached_access(&self) -> bool {
        let last = self.last_check.lock();
        let elapsed = last.elapsed();

        // Sudo typically caches for 15 minutes
        if elapsed < std::time::Duration::from_secs(15 * 60) {
            self.cached_valid.load(std::sync::atomic::Ordering::Relaxed)
        } else {
            false
        }
    }

    /// Validate credentials and cache the result
    pub fn authenticate(&self, password: &str) -> Result<bool, String> {
        let valid = verify_sudo_password(password)?;

        if valid {
            *self.last_check.lock() = std::time::Instant::now();
            self.cached_valid.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(valid)
    }

    /// Clear cached credentials
    pub fn clear_cache(&self) {
        self.cached_valid.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for SudoAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_root_privileges() {
        // Just ensure it doesn't panic
        let _ = has_root_privileges();
    }

    #[test]
    fn test_sudo_authenticator() {
        let auth = SudoAuthenticator::new();
        assert!(!auth.has_cached_access());
    }
}
