//! # System Monitor
//! 
//! A high-performance, modular system monitoring library written in Rust.
//! 
//! ## Features
//! 
//! - **Asynchronous**: Built on Tokio for efficient concurrent monitoring
//! - **Modular**: Plugin-based architecture for different system components
//! - **Cross-platform**: Works on Linux, Windows, and macOS
//! - **Type-safe**: Leverages Rust's type system for safety
//! - **Configurable**: Extensive configuration options via TOML files
//! - **Real-time**: Sub-second metric collection intervals
//! 
//! ## Quick Start
//! 
//! ```rust,ignore
//! use system_monitor::services::MonitoringService;
//! use system_monitor::core::ConfigManager;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load configuration
//!     let config_manager = ConfigManager::new()?;
//!     
//!     // Initialize monitoring service
//!     let service = MonitoringService::new();
//!     service.initialize().await?;
//!     service.apply_config(config_manager.config()).await?;
//!     
//!     // Start monitoring
//!     service.start().await?;
//!     
//!     // Subscribe to metrics
//!     let mut receiver = service.subscribe();
//!     while let Ok(metrics) = receiver.recv().await {
//!         println!("CPU: {:.1}%", metrics.cpu.usage_percent);
//!     }
//!     
//!     Ok(())
//! }
//! ```

/// Backend monitoring implementations for various system components
/// (legacy: feature "legacy-backend").
#[cfg(feature = "legacy-backend")]
pub mod backend;

/// Core types, traits, and abstractions
pub mod core;

/// High-level monitoring services (legacy: built on `backend`).
#[cfg(feature = "legacy-backend")]
pub mod services;

#[cfg(all(test, feature = "legacy-backend"))]
mod tests;