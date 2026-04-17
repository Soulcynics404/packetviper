//! GeoIP lookup for IP geolocation

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;

pub struct GeoIpLookup {
    reader: Option<Reader<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub struct GeoInfo {
    pub country: String,
    pub country_code: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

impl Default for GeoInfo {
    fn default() -> Self {
        Self {
            country: "Unknown".to_string(),
            country_code: "??".to_string(),
            city: "Unknown".to_string(),
            latitude: 0.0,
            longitude: 0.0,
        }
    }
}

impl std::fmt::Display for GeoInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.city != "Unknown" {
            write!(f, "{}, {} ({})", self.city, self.country, self.country_code)
        } else {
            write!(f, "{} ({})", self.country, self.country_code)
        }
    }
}

impl GeoIpLookup {
    /// Create a new GeoIP lookup with the database path
    pub fn new(db_path: &str) -> Self {
        let reader = if Path::new(db_path).exists() {
            match Reader::open_readfile(db_path) {
                Ok(r) => {
                    log::info!("GeoIP database loaded: {}", db_path);
                    Some(r)
                }
                Err(e) => {
                    log::warn!("Failed to load GeoIP database: {}", e);
                    None
                }
            }
        } else {
            log::warn!("GeoIP database not found: {}", db_path);
            None
        };

        Self { reader }
    }

    /// Check if the database is loaded
    pub fn is_available(&self) -> bool {
        self.reader.is_some()
    }

    /// Look up an IP address
    pub fn lookup(&self, ip_str: &str) -> Option<GeoInfo> {
        let reader = self.reader.as_ref()?;

        // Clean IP (remove port if present)
        let clean_ip = Self::clean_ip(ip_str);

        // Skip private/local IPs
        if Self::is_private_ip(&clean_ip) {
            return None;
        }

        let ip: IpAddr = clean_ip.parse().ok()?;

        match reader.lookup::<geoip2::City>(ip) {
            Ok(city_data) => {
                let country = city_data
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let country_code = city_data
                    .country
                    .as_ref()
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "??".to_string());

                let city = city_data
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());

                let (latitude, longitude) = city_data
                    .location
                    .as_ref()
                    .map(|l| {
                        (
                            l.latitude.unwrap_or(0.0),
                            l.longitude.unwrap_or(0.0),
                        )
                    })
                    .unwrap_or((0.0, 0.0));

                Some(GeoInfo {
                    country,
                    country_code,
                    city,
                    latitude,
                    longitude,
                })
            }
            Err(_) => None,
        }
    }

    /// Get country flag emoji from country code
    pub fn country_flag(country_code: &str) -> String {
        if country_code.len() != 2 || country_code == "??" {
            return "🌐".to_string();
        }
        let bytes = country_code.to_uppercase().as_bytes().to_vec();
        if bytes.len() == 2 {
            let c1 = char::from_u32(0x1F1E6 + (bytes[0] - b'A') as u32);
            let c2 = char::from_u32(0x1F1E6 + (bytes[1] - b'A') as u32);
            if let (Some(c1), Some(c2)) = (c1, c2) {
                return format!("{}{}", c1, c2);
            }
        }
        "🌐".to_string()
    }

    fn clean_ip(ip_str: &str) -> String {
        // Handle IPv4:port
        if let Some(last_colon) = ip_str.rfind(':') {
            let after_colon = &ip_str[last_colon + 1..];
            if after_colon.parse::<u16>().is_ok() {
                let colon_count = ip_str.matches(':').count();
                if colon_count == 1 {
                    return ip_str[..last_colon].to_string();
                }
            }
        }
        ip_str.to_string()
    }

    fn is_private_ip(ip_str: &str) -> bool {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_multicast()
                        || v4.is_unspecified()
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_multicast()
                        || v6.is_unspecified()
                        // fe80::/10 link-local
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                        // fc00::/7 unique local
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                }
            }
        } else {
            true // If can't parse, treat as private
        }
    }
}