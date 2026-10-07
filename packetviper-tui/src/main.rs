mod theme; 
mod app;
mod events;
mod handler;
mod ui;

use std::io;
use std::thread;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crossbeam_channel::bounded;
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
    let args: Vec<String> = std::env::args().collect();

    // Subcommands. Everything else is treated as `<interface>` for the interactive TUI.
    match args.get(1).map(|s| s.as_str()) {
        Some("serve") => return run_serve(args.get(2).map(|s| s.as_str())),
        Some("install-autostart") => return install_autostart(args.get(2).map(|s| s.as_str())),
        Some("remove-autostart") => return remove_autostart(),
        _ => {}
    }

    if args.len() < 2 {
        println!("\n  🐍 PacketViper — Network Traffic Analyzer\n");
        println!("  Usage: {}{} <interface> [session.json]\n", RUN_AS, args[0]);
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
            // On Windows the name is a device path; the description says which adapter it is.
            if !iface.description.is_empty() && iface.description != iface.name {
                println!("    {:<15} └─ {}", "", iface.description);
            }
        }
        println!("\n  Example: {}{} {}\n", RUN_AS, args[0], EXAMPLE_IFACE);
        println!("  Background / autostart:");
        println!("    {}{} serve <interface>              run headless (no UI), alerts to desktop", RUN_AS, args[0]);
        println!("    {}{} install-autostart <interface>  run in background on every boot (opt-in)", RUN_AS, args[0]);
        println!("    {}{} remove-autostart               undo autostart\n", RUN_AS, args[0]);
        return Ok(());
    }

    let interface_name = args[1].clone();

    let interfaces = capture::list_interfaces();
    if !interfaces.iter().any(|i| i.name == interface_name) {
        eprintln!("  ❌ Interface '{}' not found!", interface_name);
        return Ok(());
    }

    let log_path = init_logging();
    log::info!("PacketViper started on interface {} (log: {})", interface_name, log_path.as_deref().unwrap_or("unavailable"));
    let started = std::time::Instant::now();

    let config = packetviper_core::config::Config::load();
    let autosave_flag = Arc::new(AtomicBool::new(config.autosave));

    let mut app = App::new(&interface_name);
    app.threat_detector.auto_block = config.auto_block;
    app.autosave_flag = autosave_flag.clone();
    app.config = config.clone();
    app.threat_detector.set_local_ips(interfaces.iter().flat_map(|i| i.ips.clone()));
    app.threat_detector.set_local_macs(interfaces.iter().filter_map(|i| i.mac.clone()));
    match packetviper_core::platform::default_gateway(&interface_name) {
        Some((ip, mac)) => app.threat_detector.set_gateway(&interface_name, &ip, &mac),
        None => log::warn!("No default gateway found on {}: gateway-spoofing and MITM-relay detection are off", interface_name),
    }
    app.threat_detector.probe_firewall();
    if let Some(session_path) = args.get(2) {
        app.load_session(session_path);
    }

    // Restore the terminal even if we panic, so the shell isn't left in raw mode.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        log::error!("PANIC: {}", info);
        restore_terminal();
        default_hook(info);
    }));

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;

    let (pkt_tx, pkt_rx) = bounded(10000);
    let mut engine = CaptureEngine::new(&interface_name);
    // Open the rolling capture file so autosave can be toggled on/off live; writes only happen when on.
    let capture_dir = config.sanitized_capture_dir();
    match packetviper_core::capture::ring::RingWriter::new(&capture_dir, config.ring_bytes()) {
        Ok(ring) => {
            engine = engine.with_autosave(ring, autosave_flag.clone());
            log::info!("Autosave ready: dir={} cap={} MB, enabled={}", capture_dir, config.ring_buffer_mb, config.autosave);
        }
        Err(e) => log::warn!("Autosave unavailable (cannot open capture dir '{}'): {}", capture_dir, e),
    }
    let running_flag = engine.get_running_flag();
    let capture_thread = thread::spawn(move || {
        if let Err(e) = engine.start_capture(pkt_tx) {
            log::error!("Capture error: {}", e);
        }
    });

    app.capturing = true;
    app.status_message = format!("Capturing on {} — '/' filter, 'e' export, 'q' quit, Tab switch", interface_name);

    // Run the loop in its own function so cleanup below happens even when it returns an error.
    // A panic is caught here too, so firewall rules are still removed and the log summary still written.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_loop(&mut terminal, &mut app, &pkt_rx)))
        .unwrap_or_else(|_| Err("PacketViper crashed (panic); see log".into()));

    running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    if let Err(e) = &result {
        log::error!("Main loop error: {}", e);
    }
    let td = &app.threat_detector;
    log::info!(
        "Session summary: {} packets ({}), {} alerts ({} high/critical), {} IP(s) blocked at exit, ran {}s",
        app.packet_count(), ui::format_bytes(app.total_bytes), td.alert_count(), td.critical_count(),
        td.active_blocks.len(), started.elapsed().as_secs(),
    );
    // Don't leave DROP rules in the system firewall after we exit.
    app.threat_detector.unblock_all();
    log::info!("PacketViper exited");
    log::logger().flush();
    restore_terminal();
    drop(pkt_rx); // unblocks the capture thread if it is waiting to send
    let _ = capture_thread.join();
    result?;

    println!("\n  🐍 PacketViper session ended.");
    println!("  Captured {} packets ({}).", app.packet_count(), ui::format_bytes(app.total_bytes));
    if let Some(p) = &log_path {
        println!("  Log saved: {}\n", p);
    }
    Ok(())
}

/// Max packets pulled from the capture channel per frame, so a flood can't starve the redraw.
const MAX_PACKETS_PER_FRAME: usize = 2000;

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    pkt_rx: &crossbeam_channel::Receiver<packetviper_core::packets::CapturedPacket>,
) -> Result<(), Box<dyn std::error::Error>> {
    let event_handler = EventHandler::new(50);
    while app.running {
        if app.force_redraw {
            terminal.clear()?;
            app.force_redraw = false;
        }
        terminal.draw(|f| ui::render(f, app))?;
        if app.take_bell() {
            // BEL: the terminal beeps/flashes. A control byte, so it doesn't disturb the screen.
            use std::io::Write;
            let _ = io::stdout().write_all(b"\x07").and_then(|_| io::stdout().flush());
        }

        // Capture keeps running while paused; paused packets are dropped so resume works instantly.
        for packet in pkt_rx.try_iter().take(MAX_PACKETS_PER_FRAME) {
            if app.capturing {
                app.add_packet(packet);
            }
        }

        app.tick();

        match event_handler.next()? {
            AppEvent::Key(key) => handle_key_event(app, key),
            AppEvent::Resize => app.force_redraw = true,
            AppEvent::Tick => {}
        }
    }
    Ok(())
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, crossterm::cursor::Show);
}

/// Starts logging to logs/packetviper_<timestamp>.log (one file per run, written as events happen, so it
/// survives a crash). Level is info unless RUST_LOG overrides it. Returns the log path.
/// Logging never goes to stderr: that would draw over the TUI.
/// How to launch with the needed privileges, for the usage text.
const RUN_AS: &str = if cfg!(windows) { "(as Administrator) " } else { "sudo " };
const EXAMPLE_IFACE: &str = if cfg!(windows) { "\\Device\\NPF_{...}" } else if cfg!(target_os = "macos") { "en0" } else { "wlan0" };

fn init_logging() -> Option<String> {
    use std::io::Write;
    // We run as root: never follow a symlinked "logs" (it could point at a system directory we'd then chown).
    match std::fs::symlink_metadata("logs") {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return None,
        Ok(_) => {}
        Err(_) => std::fs::create_dir("logs").ok()?,
    }
    let path = format!("logs/packetviper_{}.log", chrono::Local::now().format("%Y%m%d_%H%M%S"));
    // create_new (O_EXCL) refuses an existing file or symlink at this path.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(&path).ok()?;
    #[cfg(unix)]
    if let Some((uid, gid)) = sudo_user() {
        let _ = std::os::unix::fs::lchown("logs", Some(uid), Some(gid));
        let _ = std::os::unix::fs::fchown(&file, Some(uid), Some(gid));
    }
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .format(|buf, record| {
            writeln!(buf, "{} {:<5} {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"), record.level(), record.args())
        })
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();
    Some(path)
}

/// The user who ran sudo, so the log can be handed to them instead of staying root-owned.
#[cfg(unix)]
fn sudo_user() -> Option<(u32, u32)> {
    let id = |var| std::env::var(var).ok().and_then(|v| v.parse::<u32>().ok());
    Some((id("SUDO_UID")?, id("SUDO_GID")?))
}

/// Headless monitor: capture + detect + alert + autosave with no terminal UI. Used by the autostart
/// service so PacketViper can run in the background. Desktop danger alerts still fire (via tick()).
/// Runs until the process is stopped (e.g. SIGTERM from the service manager).
fn run_serve(iface: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(iface) = iface else {
        eprintln!("Usage: packetviper serve <interface>");
        return Ok(());
    };
    let _log = init_logging();
    let interfaces = capture::list_interfaces();
    if !interfaces.iter().any(|i| i.name == iface) {
        log::error!("serve: interface '{}' not found", iface);
        eprintln!("Interface '{}' not found", iface);
        return Ok(());
    }

    let config = packetviper_core::config::Config::load();
    let autosave_flag = Arc::new(AtomicBool::new(config.autosave));
    let mut app = App::new(iface);
    app.threat_detector.auto_block = config.auto_block;
    app.autosave_flag = autosave_flag.clone();
    app.config = config.clone();
    app.threat_detector.set_local_ips(interfaces.iter().flat_map(|i| i.ips.clone()));
    app.threat_detector.set_local_macs(interfaces.iter().filter_map(|i| i.mac.clone()));
    if let Some((ip, mac)) = packetviper_core::platform::default_gateway(iface) {
        app.threat_detector.set_gateway(iface, &ip, &mac);
    }
    app.threat_detector.probe_firewall();

    let (pkt_tx, pkt_rx) = bounded(10000);
    let mut engine = CaptureEngine::new(iface);
    let capture_dir = config.sanitized_capture_dir();
    if let Ok(ring) = packetviper_core::capture::ring::RingWriter::new(&capture_dir, config.ring_bytes()) {
        engine = engine.with_autosave(ring, autosave_flag.clone());
    }
    let running_flag = engine.get_running_flag();
    let capture_thread = thread::spawn(move || {
        if let Err(e) = engine.start_capture(pkt_tx) { log::error!("Capture error: {}", e); }
    });

    app.capturing = true;
    log::info!("serve: monitoring {} in the background (auto-defence={}, autosave={})", iface, config.auto_block, config.autosave);

    // Stop cleanly on Ctrl-C / SIGTERM so firewall rules are removed and the capture file is flushed.
    ctrlc_lite::install();

    while !ctrlc_lite::should_stop() {
        for packet in pkt_rx.try_iter().take(MAX_PACKETS_PER_FRAME) {
            app.add_packet(packet);
        }
        app.tick(); // raises danger alarms + desktop notifications
        thread::sleep(std::time::Duration::from_millis(50));
    }

    running_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    app.threat_detector.unblock_all();
    drop(pkt_rx);
    let _ = capture_thread.join();
    log::info!("serve: stopped");
    Ok(())
}

/// Installs an opt-in autostart service so PacketViper monitors in the background on every boot.
/// Linux: a systemd system service running `serve` as root from the current directory. Other OSes
/// get printed instructions. Nothing is enabled unless the user runs this command.
fn install_autostart(iface: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(iface) = iface else {
        eprintln!("Usage: {}packetviper install-autostart <interface>", RUN_AS);
        return Ok(());
    };
    let exe = std::env::current_exe()?;
    let cwd = std::env::current_dir()?;

    #[cfg(target_os = "linux")]
    {
        let unit = format!(
            "[Unit]\nDescription=PacketViper network monitor\nAfter=network-online.target\nWants=network-online.target\n\n\
             [Service]\nType=simple\nUser=root\nWorkingDirectory={cwd}\nExecStart={exe} serve {iface}\nRestart=on-failure\nRestartSec=5\n\n\
             [Install]\nWantedBy=multi-user.target\n",
            cwd = cwd.display(), exe = exe.display(), iface = iface,
        );
        let path = "/etc/systemd/system/packetviper.service";
        if let Err(e) = std::fs::write(path, unit) {
            eprintln!("Could not write {} ({}). Run with sudo.", path, e);
            return Ok(());
        }
        let ok = std::process::Command::new("systemctl").arg("daemon-reload").status().map(|s| s.success()).unwrap_or(false)
            && std::process::Command::new("systemctl").args(["enable", "--now", "packetviper"]).status().map(|s| s.success()).unwrap_or(false);
        if ok {
            println!("✅ Autostart enabled. PacketViper now monitors {} in the background on every boot.", iface);
            println!("   Watch:  journalctl -u packetviper -f        (and the logs/ folder)");
            println!("   Stop:   sudo systemctl stop packetviper");
            println!("   Remove: sudo {} remove-autostart", exe.display());
            println!("   Config/captures/logs are kept in: {}", cwd.display());
        } else {
            eprintln!("Wrote the service file but systemctl enable failed. Check: systemctl status packetviper");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        println!("Automatic autostart setup is Linux-only for now.");
        println!("To run on boot manually, have your system start this on login/boot:");
        println!("   {} serve {}", exe.display(), iface);
        if cfg!(windows) { println!("Windows: create a Task Scheduler task 'At startup', run as Administrator."); }
        else { println!("macOS: add a LaunchDaemon that runs the command above."); }
        let _ = cwd;
    }
    Ok(())
}

/// Removes the autostart service installed by `install-autostart` (Linux).
fn remove_autostart() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl").args(["disable", "--now", "packetviper"]).status();
        let path = "/etc/systemd/system/packetviper.service";
        match std::fs::remove_file(path) {
            Ok(()) => {
                let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
                println!("✅ Autostart removed.");
            }
            Err(e) => eprintln!("Could not remove {} ({}). Run with sudo.", path, e),
        }
    }
    #[cfg(not(target_os = "linux"))]
    println!("Autostart removal is Linux-only; undo the Task Scheduler task / LaunchDaemon you created.");
    Ok(())
}

/// Minimal Ctrl-C / SIGTERM handling without extra crates. The handler only sets an atomic flag
/// (async-signal-safe); the serve loop polls `should_stop()`.
mod ctrlc_lite {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STOP: AtomicBool = AtomicBool::new(false);

    /// Installs handlers for SIGINT (2) and SIGTERM (15). No-op on non-Unix.
    pub fn install() {
        #[cfg(unix)]
        unsafe {
            extern "C" { fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize; }
            signal(2, on_signal);
            signal(15, on_signal);
        }
    }

    #[cfg(unix)]
    extern "C" fn on_signal(_sig: i32) { STOP.store(true, Ordering::SeqCst); }

    pub fn should_stop() -> bool { STOP.load(Ordering::SeqCst) }
}
