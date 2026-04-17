mod app;
mod events;
mod handler;
mod ui;

use std::io;
use std::thread;

use crossbeam_channel::bounded;
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use packetviper_core::capture;
use packetviper_core::capture::engine::CaptureEngine;

use app::App;
use events::{AppEvent, EventHandler};
use handler::handle_key_event;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("\n  🐍 PacketViper — Network Traffic Analyzer\n");
        println!("  Usage: sudo {} <interface>\n", args[0]);
        println!("  Available interfaces:");
        println!("  {}", "─".repeat(60));

        let interfaces = capture::list_interfaces();
        for iface in &interfaces {
            let status = if iface.is_up { "✅ UP" } else { "❌ DOWN" };
            println!(
                "    {:<15} {} {} IPs: [{}]",
                iface.name,
                status,
                if iface.is_loopback { "(lo)" } else { "" },
                iface.ips.join(", ")
            );
        }
        println!("\n  Example: sudo {} wlan0\n", args[0]);
        return Ok(());
    }

    let interface_name = args[1].clone();

    let interfaces = capture::list_interfaces();
    if !interfaces.iter().any(|i| i.name == interface_name) {
        eprintln!("  ❌ Interface '{}' not found!", interface_name);
        return Ok(());
    }

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(&interface_name);

    let (pkt_tx, pkt_rx) = bounded(10000);

    let engine = CaptureEngine::new(&interface_name);
    let running_flag = engine.get_running_flag();

    let capture_thread = thread::spawn(move || {
        if let Err(e) = engine.start_capture(pkt_tx) {
            log::error!("Capture error: {}", e);
        }
    });

    app.capturing = true;
    app.status_message = format!(
        "Capturing on {} — '/' filter, 'e' export, 'q' quit, Tab switch",
        interface_name
    );

    let event_handler = EventHandler::new(50);

    loop {
        // Draw UI
        terminal.draw(|f| ui::render(f, &app))?;

        // Drain packets
        while let Ok(packet) = pkt_rx.try_recv() {
            app.add_packet(packet);
        }

        // Tick stats
        app.tick();

        // Handle events
        match event_handler.next()? {
            AppEvent::Key(key) => handle_key_event(&mut app, key),
            AppEvent::Resize => {}
            AppEvent::Tick => {}
        }

        if !app.running {
            break;
        }

        if !app.capturing {
            running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }

    running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    let _ = capture_thread.join();

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    println!("\n  🐍 PacketViper session ended.");
    println!(
        "  Captured {} packets ({}).\n",
        app.packet_count(),
        ui::format_bytes(app.total_bytes),
    );

    Ok(())
}