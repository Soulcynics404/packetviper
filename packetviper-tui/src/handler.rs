use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crate::app::{ActiveTab, App, Confirm};

pub fn handle_key_event(app: &mut App, key: KeyEvent) {
    // A pending confirmation swallows the next key: 'y' runs it, anything else cancels.
    if let Some(action) = app.pending_confirm.take() {
        if matches!(key.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
            match action { Confirm::KillInterface => app.kill_interface() }
        } else {
            log::info!("Interface kill cancelled by user");
            app.status_message = "Cancelled".to_string();
        }
        return;
    }

    match key.code {
        KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => { app.force_redraw = true; return; }
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { app.running = false; return; }
        KeyCode::Char('q') if !app.filter_input_active => { app.running = false; return; }
        KeyCode::Tab | KeyCode::Right if !app.filter_input_active => { app.active_tab = app.active_tab.next(); return; }
        KeyCode::BackTab | KeyCode::Left if !app.filter_input_active => { app.active_tab = app.active_tab.prev(); return; }
        _ => {}
    }

    if app.filter_input_active {
        match key.code {
            KeyCode::Enter => { app.filter_input_active = false; app.apply_filter(); }
            KeyCode::Esc => { app.filter_input_active = false; app.filter_input.clear(); app.status_message = "Filter cancelled".to_string(); }
            KeyCode::Backspace => { app.filter_input.pop(); }
            KeyCode::Char(c) => { app.filter_input.push(c); }
            _ => {}
        }
        return;
    }

    if app.active_tab == ActiveTab::Firewall {
        let n = app.threat_detector.active_blocks.len();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => { app.firewall_selected = app.firewall_selected.saturating_sub(1); return; }
            KeyCode::Down | KeyCode::Char('j') => { if app.firewall_selected + 1 < n { app.firewall_selected += 1; } return; }
            KeyCode::Char('u') => { app.unblock_selected(); return; }
            KeyCode::Char('U') => { app.unblock_all(); return; }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Char('K') => {
            app.pending_confirm = Some(Confirm::KillInterface);
            log::warn!("Interface kill requested for {}, waiting for confirmation", app.interface);
            app.status_message = format!("Take interface {} DOWN? This cuts your network. y = yes, any other key = cancel", app.interface);
        }
        KeyCode::Char('A') => app.toggle_auto_block(),
        KeyCode::Char('w') => app.toggle_autosave(),
        KeyCode::Char('o') => app.show_connect = !app.show_connect,
        KeyCode::Char(']') => { let mb = app.config.ring_buffer_mb + 256; app.set_ring_size_mb(mb); }
        KeyCode::Char('[') => { let mb = app.config.ring_buffer_mb.saturating_sub(256).max(16); app.set_ring_size_mb(mb); }
        KeyCode::Char(' ') => app.acknowledge_alarm(),
        KeyCode::Char('?') => app.active_tab = ActiveTab::Help,
        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
        KeyCode::Enter => app.toggle_detail(),
        KeyCode::Char('G') => app.scroll_to_bottom(),
        KeyCode::Char('g') => { app.selected_index = 0; app.auto_scroll = false; }
        KeyCode::Char('c') => {
            app.capturing = !app.capturing;
            app.status_message = if app.capturing { format!("Capturing on {}...", app.interface) } else { "Paused".to_string() };
        }
        KeyCode::Char('/') => { app.filter_input_active = true; app.filter_input.clear(); app.status_message = "Filter: Enter=apply, Esc=cancel".to_string(); }
        KeyCode::Char('x') => app.clear_filter(),
        KeyCode::Char('a') => { app.auto_scroll = !app.auto_scroll; app.status_message = format!("Auto-scroll: {}", if app.auto_scroll { "ON" } else { "OFF" }); }
        KeyCode::Char('b') => app.toggle_bookmark(),
        KeyCode::Char('B') => app.toggle_bookmarks_view(),
        KeyCode::Char('e') => app.export_json(),
        KeyCode::Char('E') => app.export_csv(),
        KeyCode::Char('p') => app.export_pcap(),
        KeyCode::Char('t') => app.cycle_theme(),
        KeyCode::Char('s') => app.save_session(),
        _ => {}
    }
}