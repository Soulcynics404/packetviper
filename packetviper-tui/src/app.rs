use packetviper_core::packets::CapturedPacket;
use packetviper_core::filters::engine::FilterEngine;
use packetviper_core::stats::bandwidth::BandwidthMonitor;
use packetviper_core::threat::detector::ThreatDetector;
use packetviper_core::export::{Exporter, json::JsonExporter, csv::CsvExporter, pcap::PcapExporter};

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
    pub threat_detector: ThreatDetector,
    pub interface: String,
    pub capturing: bool,
    pub total_bytes: u64,
    pub status_message: String,
    pub filter_input: String,
    pub filter_input_active: bool,
    pub auto_scroll: bool,
    pub last_export_path: Option<String>,
}

impl App {
    pub fn new(interface: &str) -> Self {
        Self {
            running: true,
            active_tab: ActiveTab::Dashboard,
            packets: Vec::new(),
            filtered_indices: Vec::new(),
            selected_index: 0,
            show_detail: false,
            filter_engine: FilterEngine::new(),
            bandwidth_monitor: BandwidthMonitor::new(),
            threat_detector: ThreatDetector::new(),
            interface: interface.to_string(),
            capturing: false,
            total_bytes: 0,
            status_message: String::from("Press 'c' to start capture, 'q' to quit"),
            filter_input: String::new(),
            filter_input_active: false,
            auto_scroll: true,
            last_export_path: None,
        }
    }

    pub fn add_packet(&mut self, packet: CapturedPacket) {
        self.total_bytes += packet.length as u64;

        // Record in stats
        self.bandwidth_monitor.record_packet(&packet);

        // Analyze for threats
        self.threat_detector.analyze(&packet);

        self.packets.push(packet);
        let idx = self.packets.len() - 1;

        if self.filter_engine.matches(&self.packets[idx]) {
            self.filtered_indices.push(idx);
        }

        // Auto-scroll to bottom
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
        // Rebuild filtered indices
        self.filtered_indices.clear();
        for (idx, pkt) in self.packets.iter().enumerate() {
            if self.filter_engine.matches(pkt) {
                self.filtered_indices.push(idx);
            }
        }
        self.selected_index = 0;
    }

    pub fn clear_filter(&mut self) {
        self.filter_engine.clear();
        self.filter_input.clear();
        self.filtered_indices = (0..self.packets.len()).collect();
        self.status_message = "Filter cleared".to_string();
    }

    pub fn export_json(&mut self) {
        let path = format!("packetviper_export_{}.json",
            chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let exporter = JsonExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message = format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => {
                self.status_message = format!("Export failed: {}", e);
            }
        }
    }

    pub fn export_csv(&mut self) {
        let path = format!("packetviper_export_{}.csv",
            chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let exporter = CsvExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message = format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => {
                self.status_message = format!("Export failed: {}", e);
            }
        }
    }

    pub fn export_pcap(&mut self) {
        let path = format!("packetviper_export_{}.pcap",
            chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let exporter = PcapExporter;
        match exporter.export(&self.packets, &path) {
            Ok(()) => {
                self.status_message = format!("Exported {} packets to {}", self.packets.len(), path);
                self.last_export_path = Some(path);
            }
            Err(e) => {
                self.status_message = format!("Export failed: {}", e);
            }
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