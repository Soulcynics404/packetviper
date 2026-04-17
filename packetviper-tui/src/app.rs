use packetviper_core::packets::CapturedPacket;
use packetviper_core::filters::engine::FilterEngine;
use packetviper_core::stats::bandwidth::BandwidthMonitor;
use packetviper_core::stats::connections::ConnectionTracker;
use packetviper_core::threat::detector::ThreatDetector;
use packetviper_core::threat::geoip::GeoIpLookup;
use packetviper_core::export::{Exporter, json::JsonExporter, csv::CsvExporter, pcap::PcapExporter};

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ActiveTab {
    Dashboard,
    Inspection,
    Stats,
    Filters,
    Threats,
    Help,
}

impl ActiveTab {
    pub fn titles() -> Vec<&'static str> {
        vec!["Dashboard", "Inspection", "Stats", "Filters", "Threats", "Help"]
    }

    pub fn index(&self) -> usize {
        match self {
            ActiveTab::Dashboard => 0,
            ActiveTab::Inspection => 1,
            ActiveTab::Stats => 2,
            ActiveTab::Filters => 3,
            ActiveTab::Threats => 4,
            ActiveTab::Help => 5,
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ActiveTab::Dashboard => ActiveTab::Inspection,
            ActiveTab::Inspection => ActiveTab::Stats,
            ActiveTab::Stats => ActiveTab::Filters,
            ActiveTab::Filters => ActiveTab::Threats,
            ActiveTab::Threats => ActiveTab::Help,
            ActiveTab::Help => ActiveTab::Dashboard,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ActiveTab::Dashboard => ActiveTab::Help,
            ActiveTab::Inspection => ActiveTab::Dashboard,
            ActiveTab::Stats => ActiveTab::Inspection,
            ActiveTab::Filters => ActiveTab::Stats,
            ActiveTab::Threats => ActiveTab::Filters,
            ActiveTab::Help => ActiveTab::Threats,
        }
    }
}

pub struct App {
    pub running: bool,
    pub active_tab: ActiveTab,
    pub packets: Vec<CapturedPacket>,
    pub filtered_indices: Vec<usize>,
    pub selected_index: usize,
    pub show_detail: bool,
    pub filter_engine: FilterEngine,
    pub bandwidth_monitor: BandwidthMonitor,
    pub connection_tracker: ConnectionTracker,
    pub threat_detector: ThreatDetector,
    pub geoip: GeoIpLookup,
    pub interface: String,
    pub capturing: bool,
    pub total_bytes: u64,
    pub status_message: String,
    pub filter_input: String,
    pub filter_input_active: bool,
    pub auto_scroll: bool,
    pub last_export_path: Option<String>,
    pub bookmarked_packets: HashSet<u64>,
    pub show_bookmarks_only: bool,
}

impl App {
    pub fn new(interface: &str) -> Self {
        // Try multiple paths for GeoIP database
        let geoip_paths = [
            "data/GeoLite2-City.mmdb",
            "/usr/share/GeoIP/GeoLite2-City.mmdb",
            "../data/GeoLite2-City.mmdb",
        ];

        let mut geoip = GeoIpLookup::new("");
        for path in &geoip_paths {
            let g = GeoIpLookup::new(path);
            if g.is_available() {
                geoip = g;
                break;
            }
        }

        Self {
            running: true,
            active_tab: ActiveTab::Dashboard,
            packets: Vec::new(),
            filtered_indices: Vec::new(),
            selected_index: 0,
            show_detail: false,
            filter_engine: FilterEngine::new(),
            bandwidth_monitor: BandwidthMonitor::new(),
            connection_tracker: ConnectionTracker::new(),
            threat_detector: ThreatDetector::new(),
            geoip,
            interface: interface.to_string(),
            capturing: false,
            total_bytes: 0,
            status_message: String::from("Press 'c' to start capture, 'q' to quit"),
            filter_input: String::new(),
            filter_input_active: false,
            auto_scroll: true,
            last_export_path: None,
            bookmarked_packets: HashSet::new(),
            show_bookmarks_only: false,
        }
    }

    pub fn add_packet(&mut self, packet: CapturedPacket) {
        self.total_bytes += packet.length as u64;
        self.bandwidth_monitor.record_packet(&packet);
        self.threat_detector.analyze(&packet);
        self.connection_tracker.track_packet(&packet);

        self.packets.push(packet);
        let idx = self.packets.len() - 1;

        if self.filter_engine.matches(&self.packets[idx]) {
            if !self.show_bookmarks_only
                || self.bookmarked_packets.contains(&self.packets[idx].id)
            {
                self.filtered_indices.push(idx);
            }
        }

        if self.auto_scroll && !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
        }
    }

    pub fn tick(&mut self) {
        self.bandwidth_monitor.tick();
    }

    pub fn apply_filter(&mut self) {
        if self.filter_input.is_empty() {
            self.filter_engine.clear();
        } else {
            match self.filter_engine.set_filter(&self.filter_input) {
                Ok(()) => {
                    self.status_message = format!("Filter applied: {}", self.filter_input);
                }
                Err(e) => {
                    self.status_message = format!("Filter error: {}", e);
                    return;
                }
            }
        }
        self.rebuild_filtered_indices();
    }

    pub fn clear_filter(&mut self) {
        self.filter_engine.clear();
        self.filter_input.clear();
        self.show_bookmarks_only = false;
        self.rebuild_filtered_indices();
        self.status_message = "Filter cleared".to_string();
    }

    pub fn rebuild_filtered_indices(&mut self) {
        self.filtered_indices.clear();
        for (idx, pkt) in self.packets.iter().enumerate() {
            if self.filter_engine.matches(pkt) {
                if !self.show_bookmarks_only
                    || self.bookmarked_packets.contains(&pkt.id)
                {
                    self.filtered_indices.push(idx);
                }
            }
        }
        self.selected_index = 0;
    }

    pub fn toggle_bookmark(&mut self) {
        if let Some(pkt) = self.selected_packet() {
            let id = pkt.id;
            if self.bookmarked_packets.contains(&id) {
                self.bookmarked_packets.remove(&id);
                self.status_message = format!("Bookmark removed: packet #{}", id);
            } else {
                self.bookmarked_packets.insert(id);
                self.status_message = format!("Bookmarked: packet #{}", id);
            }
        }
    }

    pub fn toggle_bookmarks_view(&mut self) {
        self.show_bookmarks_only = !self.show_bookmarks_only;
        self.rebuild_filtered_indices();
        if self.show_bookmarks_only {
            self.status_message = format!(
                "Showing {} bookmarked packets",
                self.bookmarked_packets.len()
            );
        } else {
            self.status_message = "Showing all packets".to_string();
        }
    }

    pub fn is_bookmarked(&self, packet_id: u64) -> bool {
        self.bookmarked_packets.contains(&packet_id)
    }

    pub fn lookup_geo(&self, ip: &str) -> Option<String> {
        self.geoip.lookup(ip).map(|info| {
            let flag = GeoIpLookup::country_flag(&info.country_code);
            format!("{} {}", flag, info)
        })
    }

    pub fn export_json(&mut self) {
        let path = format!(
            "packetviper_export_{}.json",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let exporter = JsonExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message =
                    format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => self.status_message = format!("Export failed: {}", e),
        }
    }

    pub fn export_csv(&mut self) {
        let path = format!(
            "packetviper_export_{}.csv",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let exporter = CsvExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message =
                    format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => self.status_message = format!("Export failed: {}", e),
        }
    }

    pub fn export_pcap(&mut self) {
        let path = format!(
            "packetviper_export_{}.pcap",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let exporter = PcapExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message =
                    format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => self.status_message = format!("Export failed: {}", e),
        }
    }

    pub fn selected_packet(&self) -> Option<&CapturedPacket> {
        self.filtered_indices
            .get(self.selected_index)
            .and_then(|&idx| self.packets.get(idx))
    }

    pub fn scroll_up(&mut self) {
        self.auto_scroll = false;
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        if self.selected_index + 1 < self.filtered_indices.len() {
            self.selected_index += 1;
        }
        if self.selected_index == self.filtered_indices.len().saturating_sub(1) {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        if !self.filtered_indices.is_empty() {
            self.selected_index = self.filtered_indices.len() - 1;
            self.auto_scroll = true;
        }
    }

    pub fn toggle_detail(&mut self) {
        self.show_detail = !self.show_detail;
    }

    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }
}