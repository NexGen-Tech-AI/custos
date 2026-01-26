// Secure API key storage using OS-native keychain/credential manager
// - macOS: Keychain
// - Windows: Credential Manager
// - Linux: Secret Service (libsecret)

use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::error::Error;

const SERVICE_NAME: &str = "com.nexgentech.custos";

/// API key types supported by the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiKeyType {
    Claude,
    VirusTotal,
    AbuseIPDB,
    AlienVault,
}

impl ApiKeyType {
    fn as_str(&self) -> &'static str {
        match self {
            ApiKeyType::Claude => "claude_api_key",
            ApiKeyType::VirusTotal => "virustotal_api_key",
            ApiKeyType::AbuseIPDB => "abuseipdb_api_key",
            ApiKeyType::AlienVault => "alienvault_api_key",
        }
    }
}

/// Secure keychain manager for API keys
pub struct KeychainManager;

impl KeychainManager {
    /// Store an API key securely in the OS keychain
    pub fn set_api_key(key_type: ApiKeyType, api_key: &str) -> Result<(), Box<dyn Error>> {
        let entry = Entry::new(SERVICE_NAME, key_type.as_str())?;
        entry.set_password(api_key)?;
        Ok(())
    }

    /// Retrieve an API key from the OS keychain
    pub fn get_api_key(key_type: ApiKeyType) -> Result<Option<String>, Box<dyn Error>> {
        let entry = Entry::new(SERVICE_NAME, key_type.as_str())?;
        match entry.get_password() {
            Ok(password) => Ok(Some(password)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Delete an API key from the OS keychain
    pub fn delete_api_key(key_type: ApiKeyType) -> Result<(), Box<dyn Error>> {
        let entry = Entry::new(SERVICE_NAME, key_type.as_str())?;
        match entry.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Check if an API key exists in the keychain
    pub fn has_api_key(key_type: ApiKeyType) -> bool {
        Self::get_api_key(key_type).ok().flatten().is_some()
    }

    /// Load API key with fallback to environment variable
    pub fn load_api_key_with_fallback(
        key_type: ApiKeyType,
        env_var: &str,
    ) -> Option<String> {
        // Try keychain first
        if let Ok(Some(key)) = Self::get_api_key(key_type.clone()) {
            if !key.is_empty() {
                return Some(key);
            }
        }

        // Fall back to environment variable
        std::env::var(env_var).ok()
    }

    /// Get all configured API keys (returns which keys are set, not the actual keys)
    pub fn get_configured_keys() -> Vec<ApiKeyType> {
        let mut configured = Vec::new();

        if Self::has_api_key(ApiKeyType::Claude) {
            configured.push(ApiKeyType::Claude);
        }
        if Self::has_api_key(ApiKeyType::VirusTotal) {
            configured.push(ApiKeyType::VirusTotal);
        }
        if Self::has_api_key(ApiKeyType::AbuseIPDB) {
            configured.push(ApiKeyType::AbuseIPDB);
        }
        if Self::has_api_key(ApiKeyType::AlienVault) {
            configured.push(ApiKeyType::AlienVault);
        }

        configured
    }

    /// Clear all API keys from the keychain
    pub fn clear_all_keys() -> Result<(), Box<dyn Error>> {
        let _ = Self::delete_api_key(ApiKeyType::Claude);
        let _ = Self::delete_api_key(ApiKeyType::VirusTotal);
        let _ = Self::delete_api_key(ApiKeyType::AbuseIPDB);
        let _ = Self::delete_api_key(ApiKeyType::AlienVault);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_set_get_delete() {
        let test_key = "test_api_key_12345";

        // Set key
        KeychainManager::set_api_key(ApiKeyType::Claude, test_key)
            .expect("Failed to set test API key");

        // Get key
        let retrieved = KeychainManager::get_api_key(ApiKeyType::Claude)
            .expect("Failed to get API key");
        assert_eq!(retrieved, Some(test_key.to_string()));

        // Check has_api_key
        assert!(KeychainManager::has_api_key(ApiKeyType::Claude));

        // Delete key
        KeychainManager::delete_api_key(ApiKeyType::Claude)
            .expect("Failed to delete API key");

        // Verify deletion
        let after_delete = KeychainManager::get_api_key(ApiKeyType::Claude)
            .expect("Failed to check deleted key");
        assert_eq!(after_delete, None);
        assert!(!KeychainManager::has_api_key(ApiKeyType::Claude));
    }

    #[test]
    fn test_get_nonexistent_key() {
        // Ensure key doesn't exist
        let _ = KeychainManager::delete_api_key(ApiKeyType::VirusTotal);

        let result = KeychainManager::get_api_key(ApiKeyType::VirusTotal)
            .expect("Failed to query nonexistent key");
        assert_eq!(result, None);
    }

    #[test]
    fn test_update_existing_key() {
        let key1 = "first_key";
        let key2 = "second_key";

        // Set initial key
        KeychainManager::set_api_key(ApiKeyType::AbuseIPDB, key1)
            .expect("Failed to set first key");

        // Update to new key
        KeychainManager::set_api_key(ApiKeyType::AbuseIPDB, key2)
            .expect("Failed to update key");

        // Verify update
        let retrieved = KeychainManager::get_api_key(ApiKeyType::AbuseIPDB)
            .expect("Failed to get updated key");
        assert_eq!(retrieved, Some(key2.to_string()));

        // Cleanup
        let _ = KeychainManager::delete_api_key(ApiKeyType::AbuseIPDB);
    }
}
