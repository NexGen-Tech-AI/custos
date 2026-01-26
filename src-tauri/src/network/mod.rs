// Network Security Module - EDR for Traffic
// Provides network segmentation, DNS analysis, GeoIP lookup, and isolation controls

pub mod dns_analyzer;
pub mod geoip;
pub mod segmentation;
pub mod isolation;
pub mod connection_history;

pub use dns_analyzer::*;
pub use geoip::*;
pub use segmentation::*;
pub use isolation::*;
pub use connection_history::*;
