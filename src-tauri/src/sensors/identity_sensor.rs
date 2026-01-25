// Identity Sensor - monitors authentication and privilege changes

use super::*;
use std::sync::Arc;
use parking_lot::Mutex;

pub struct IdentitySensor {
    running: bool,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl IdentitySensor {
    #[cfg(target_os = "linux")]
    pub fn new_linux() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_windows() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_macos() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }
}

#[async_trait::async_trait]
impl EventCollector for IdentitySensor {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running = true;
        // TODO: Implement auth monitoring (utmp/wtmp/lastlog/Event 4624/etc)
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
