use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use crate::app::App;

pub fn handle_key_event(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => { app.running = false; return; }
        KeyCode::Char('q') if !app.filter_input_active => { app.running = false; return; }
        KeyCode::Tab => { app.active_tab = app.active_tab.next(); return; }
        KeyCode::BackTab => { app.active_tab = app.active_tab.prev(); return; }
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

    match key.code {
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