//! # Syslog Message Serialization Module
//!
//! This module provides functionality for serializing and deserializing syslog messages
//! using Cap'n Proto as the serialization format. It includes a data structure for
//! representing syslog messages and functions for converting between this representation
//! and Cap'n Proto.
//!
//! The primary use case is for efficient storage and transmission of syslog data
//! while preserving all relevant fields including timestamps, source addresses,
//! severity levels, and the raw message content.

use anyhow::Result;
use capnp::message::Builder;
use capnp::serialize;
use chrono::{DateTime, TimeZone, Utc};
use std::net::IpAddr;
use std::str::FromStr;

pub mod schema_capnp {
    include!(concat!(env!("OUT_DIR"), "/schema/syslog_capnp.rs"));
}
use schema_capnp::syslog_message;

/// Represents a syslog message with all its associated metadata.
///
/// This structure contains the core components of a syslog message including
/// the timestamp when the message was generated, the source IP address,
/// facility and severity codes as defined in the syslog protocol (RFC 5424),
/// and the raw message content.
#[derive(Debug, Clone)]
pub struct SyslogMessageData {
    /// Timestamp when the message was generated, stored as UTC
    pub timestamp: DateTime<chrono::Utc>, // comes in a UNIX EPOCH time and should stay that way in this application and db
    /// Source IP address (can be either IPv4 or IPv6)
    pub source: IpAddr,
    /// Syslog facility code (0-23)
    pub facility: i32,
    /// Syslog severity level (0-7)
    pub severity: i32,
    /// The original raw message text
    pub raw_message: String,
}

impl SyslogMessageData {
    /// Converts a Cap'n Proto SyslogMessage reader into a SyslogMessageData struct.
    ///
    /// # Arguments
    ///
    /// * `msg` - A Cap'n Proto reader for a syslog_message
    ///
    /// # Returns
    ///
    /// A Result containing the converted SyslogMessageData or an error
    ///
    /// # Errors
    ///
    /// Returns an error if any field conversion fails, such as invalid timestamp,
    /// invalid IP address format, or issues with string conversion.
    fn from_syslog_capnp(msg: syslog_message::Reader) -> Result<Self> {
        Ok(SyslogMessageData {
            timestamp: Utc
                .timestamp_millis_opt(msg.get_timestamp() as i64)
                .single()
                .ok_or_else(|| anyhow::anyhow!("Invalid timestamp"))?,
            source: IpAddr::from_str(msg.get_source()?.to_str()?)?,
            facility: msg.get_facility() as i32,
            severity: msg.get_severity() as i32,
            raw_message: msg.get_raw_message()?.to_str()?.to_owned(),
        })
    }

    /// Converts this SyslogMessageData struct into a serialized Cap'n Proto message.
    ///
    /// # Returns
    ///
    /// A Result containing a `Vec<u8>` of the serialized message or an error
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails for any reason, such as
    /// memory allocation failures or issues with Cap'n Proto.
    pub fn to_capnp_message(&self) -> Result<Vec<u8>> {
        // Create a new Cap'n Proto message builder
        let mut message = Builder::new_default();
        // Create a new SyslogMessage
        let mut syslog_message = message.init_root::<syslog_message::Builder>();
        // Convert DateTime<Utc> to timestamp (milliseconds since epoch)
        let timestamp_millis = self.timestamp.timestamp_millis() as u64;
        syslog_message.set_timestamp(timestamp_millis);
        // Set the source address as a string
        syslog_message.set_source(&self.source.to_string());
        // Set facility and severity
        syslog_message.set_facility(self.facility as u8);
        syslog_message.set_severity(self.severity as u8);
        // Set the raw message
        syslog_message.set_raw_message(&self.raw_message);
        // Serialize to a Vec<u8>
        let mut serialized_data = Vec::new();
        serialize::write_message(&mut serialized_data, &message)?;
        Ok(serialized_data)
    }
}

/// Serializes a SyslogMessageData struct into a binary representation.
///
/// This function takes a reference to a SyslogMessageData struct and converts it
/// into a binary format using Cap'n Proto serialization.
///
/// # Arguments
///
/// * `message_data` - A reference to the SyslogMessageData to serialize
///
/// # Returns
///
/// A Result containing a `Vec<u8>` of the serialized data or an error
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use chrono::Utc;
/// use sersyscap::{SyslogMessageData, serialize_message};
/// 
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let message = SyslogMessageData {
///     timestamp: Utc::now(),
///     source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
///     facility: 1,
///     severity: 6,
///     raw_message: "System restarted".to_string(),
/// };
///
/// let bytes = serialize_message(&message)?;
/// # Ok(())
/// # }
/// ```
pub fn serialize_message(message_data: &SyslogMessageData) -> Result<Vec<u8>> {
    message_data.to_capnp_message()
}

/// Deserializes a binary representation into a SyslogMessageData struct.
///
/// This function takes a byte slice containing a Cap'n Proto serialized syslog message
/// and converts it back into a SyslogMessageData struct.
///
/// # Arguments
///
/// * `bytes` - A byte slice containing the serialized data
///
/// # Returns
///
/// A Result containing the deserialized SyslogMessageData or an error
///
/// # Errors
///
/// Returns an error if deserialization fails, such as if the input data is not
/// a valid Cap'n Proto message or doesn't match the expected schema.
///
/// # Examples
///
/// ```
/// use sersyscap::{SyslogMessageData, deserialize_message, serialize_message};
/// use std::net::{IpAddr, Ipv4Addr};
/// use chrono::Utc;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // First create and serialize a message
/// let original = SyslogMessageData {
///     timestamp: Utc::now(),
///     source: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
///     facility: 0,
///     severity: 0,
///     raw_message: "Test message".to_string(),
/// };
///
/// let bytes = serialize_message(&original)?;
///
/// // Now deserialize it
/// let deserialized = deserialize_message(&bytes)?;
/// println!("Received message: {:?}", deserialized);
/// # Ok(())
/// # }
/// ```
pub fn deserialize_message(bytes: &[u8]) -> Result<SyslogMessageData> {
    let mut slice = bytes;
    let reader =
        serialize::read_message_from_flat_slice(&mut slice, capnp::message::ReaderOptions::new())?;
    let msg = reader.get_root::<syslog_message::Reader>()?;
    SyslogMessageData::from_syslog_capnp(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_basic_serialization_deserialization() -> Result<()> {
        // Create a sample message with IPv4 address
        let original = SyslogMessageData {
            timestamp: Utc.with_ymd_and_hms(2023, 4, 15, 12, 30, 45).unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            facility: 23,
            severity: 6,
            raw_message: "User authentication failed".to_string(),
        };

        // Serialize
        let serialized = serialize_message(&original)?;

        // Deserialize
        let deserialized = deserialize_message(&serialized)?;

        // Verify the result
        assert_eq!(original.timestamp, deserialized.timestamp);
        assert_eq!(original.source, deserialized.source);
        assert_eq!(original.facility, deserialized.facility);
        assert_eq!(original.severity, deserialized.severity);
        assert_eq!(original.raw_message, deserialized.raw_message);

        Ok(())
    }

    #[test]
    fn test_ipv6_address() -> Result<()> {
        // Create a sample message with IPv6 address
        let original = SyslogMessageData {
            timestamp: Utc.with_ymd_and_hms(2023, 4, 15, 12, 30, 45).unwrap(),
            source: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            facility: 23,
            severity: 6,
            raw_message: "User authentication failed".to_string(),
        };

        // Serialize and deserialize
        let serialized = serialize_message(&original)?;
        let deserialized = deserialize_message(&serialized)?;

        // IPv6 addresses should be preserved correctly
        assert_eq!(original.source, deserialized.source);

        Ok(())
    }

    #[test]
    fn test_empty_message() -> Result<()> {
        // Create a message with empty raw_message
        let original = SyslogMessageData {
            timestamp: Utc.with_ymd_and_hms(2023, 4, 15, 12, 30, 45).unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            facility: 0,
            severity: 0,
            raw_message: "".to_string(),
        };

        // Serialize and deserialize
        let serialized = serialize_message(&original)?;
        let deserialized = deserialize_message(&serialized)?;

        // Empty message should be preserved
        assert_eq!(original.raw_message, deserialized.raw_message);

        Ok(())
    }

    #[test]
    fn test_unicode_message() -> Result<()> {
        // Create a message with Unicode characters
        let original = SyslogMessageData {
            timestamp: Utc.with_ymd_and_hms(2023, 4, 15, 12, 30, 45).unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            facility: 10,
            severity: 2,
            raw_message: "こんにちは世界! 👋 ñ á é í ó ú".to_string(),
        };

        // Serialize and deserialize
        let serialized = serialize_message(&original)?;
        let deserialized = deserialize_message(&serialized)?;

        // Unicode should be preserved
        assert_eq!(original.raw_message, deserialized.raw_message);

        Ok(())
    }

    #[test]
    fn test_extreme_timestamp() -> Result<()> {
        // Test with extreme timestamp values
        let original = SyslogMessageData {
            // January 1, 1970 (Unix epoch)
            timestamp: Utc.timestamp_millis_opt(0).single().unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            facility: 23,
            severity: 6,
            raw_message: "Epoch message".to_string(),
        };

        // Serialize and deserialize
        let serialized = serialize_message(&original)?;
        let deserialized = deserialize_message(&serialized)?;

        assert_eq!(original.timestamp, deserialized.timestamp);

        // Far future timestamp
        let future = SyslogMessageData {
            // Year 2100
            timestamp: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            facility: 23,
            severity: 6,
            raw_message: "Future message".to_string(),
        };

        let serialized = serialize_message(&future)?;
        let deserialized = deserialize_message(&serialized)?;

        assert_eq!(future.timestamp, deserialized.timestamp);

        Ok(())
    }

    #[test]
    fn test_long_message() -> Result<()> {
        // Test with a very long message
        let long_message = "a".repeat(10000);

        let original = SyslogMessageData {
            timestamp: Utc::now(),
            source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            facility: 23,
            severity: 6,
            raw_message: long_message.clone(),
        };

        // Serialize and deserialize
        let serialized = serialize_message(&original)?;
        let deserialized = deserialize_message(&serialized)?;

        assert_eq!(original.raw_message, deserialized.raw_message);
        assert_eq!(deserialized.raw_message.len(), 10000);

        Ok(())
    }

    #[test]
    fn test_roundtrip_performance() -> Result<()> {
        use std::time::Instant;

        // Create 1000 messages and measure serialization/deserialization time
        let mut total_size = 0;
        let start = Instant::now();

        for i in 0..1000 {
            let original = SyslogMessageData {
                timestamp: Utc::now(),
                source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                facility: 23,
                severity: 6,
                raw_message: format!("Test message number {}", i),
            };

            let serialized = serialize_message(&original)?;
            total_size += serialized.len();

            let _deserialized = deserialize_message(&serialized)?;
        }

        let duration = start.elapsed();

        println!("Processed 1000 messages in {:?}", duration);
        println!("Average message size: {} bytes", total_size / 1000);
        println!("Average time per message: {:?}", duration / 1000);

        // No real assertion, just informational
        Ok(())
    }

    #[test]
    fn test_roundtrip_performance_1_000_000() -> Result<()> {
        use std::time::Instant;

        // Create 1_000_000 messages and measure serialization/deserialization time
        let mut total_size = 0;
        let start = Instant::now();

        for i in 0..1_000_000 {
            let original = SyslogMessageData {
                timestamp: Utc::now(),
                source: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                facility: 23,
                severity: 6,
                raw_message: format!("Test message number {}", i),
            };

            let serialized = serialize_message(&original)?;
            total_size += serialized.len();

            let _deserialized = deserialize_message(&serialized)?;
        }

        let duration = start.elapsed();

        println!("Processed 1m messages in {:?}", duration);
        println!("Average message size: {} bytes", total_size / 1_000_000);
        println!("Average time per message: {:?}", duration / 1_000_000);

        // No real assertion, just informational
        Ok(())
    }

    #[test]
    fn test_invalid_data() {
        // Test deserializing invalid data
        let invalid_data = vec![1, 2, 3, 4, 5]; // Not a valid Cap'n Proto message

        let result = deserialize_message(&invalid_data);
        assert!(result.is_err(), "Deserializing invalid data should fail");

        // Test empty data
        let empty_data: Vec<u8> = vec![];

        let result = deserialize_message(&empty_data);
        assert!(result.is_err(), "Deserializing empty data should fail");
    }
}
