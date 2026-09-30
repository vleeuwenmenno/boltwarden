use crate::config::{self, AppSettings};
use crate::icons::IconCache;
use crate::model::{BwItem, SshAgentStatus, SyncStatus};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText, Ui};

const SEARCH_INPUT_ID: &str = "vault-search-input";
const SSH_PATH_INPUT_ID: &str = "settings-ssh-socket-path";
const SETTINGS_ROWS: usize = 7;
const IDLE_TIMEOUT_ROW: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchView {
    Results,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayEntry {
    SettingsCommand,
    LockCommand,
    VaultItem(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenSelectedAction {
    None,
    OpenResult(usize),
    LockVault,
}

pub struct SearchState {
    pub query: String,
    pub results: Vec<BwItem>,
    pub selected: usize,
    pub error: Option<String>,
    pub warning: Option<String>,
    pub in_flight: bool,
    pub focus_search: bool,
    pub last_query: String,
    pub last_query_time: Option<std::time::Instant>,
    pub sync_status: Option<SyncStatus>,
    pub view: SearchView,
    /// Draft of the SSH socket path; `None` until the settings panel loads the saved value.
    pub ssh_agent_path_input: Option<String>,
    pub settings_selected: usize,
    /// Row the list last scrolled to, so it only scrolls when the selection moves.
    scrolled_to: Option<usize>,
}

impl Default for SearchState {
    fn default() -> Self {
        Self {
            query: String::new(),
            results: Vec::new(),
            selected: 0,
            error: None,
            warning: None,
            in_flight: false,
            focus_search: true,
            last_query: String::new(),
            last_query_time: None,
            sync_status: None,
            view: SearchView::Results,
            ssh_agent_path_input: None,
            settings_selected: 0,
            scrolled_to: None,
        }
    }
}

impl SearchState {
    pub fn reset_results_for_empty_query(&mut self) {
        if self.query.trim().is_empty() {
            self.results.clear();
            self.selected = 0;
            self.error = None;
            self.warning = None;
            self.sync_status = None;
            self.view = SearchView::Results;
            if self.in_flight {
                self.in_flight = false;
            }
        }
    }

    pub fn needs_search(&self) -> bool {
        let query = self.query.trim();
        if query.is_empty() {
            return false;
        }
        if self.in_flight {
            return false;
        }
        if query == self.last_query {
            return false;
        }
        if let Some(t) = self.last_query_time {
            t.elapsed() >= std::time::Duration::from_millis(200)
        } else {
            true
        }
    }

    pub fn mark_queried(&mut self) {
        self.last_query = self.query.trim().to_string();
        self.last_query_time = Some(std::time::Instant::now());
    }

    pub fn force_refresh(&mut self) {
        self.last_query = "\u{0}".to_string();
        self.last_query_time = None;
    }

    pub fn reset_for_reopen(&mut self) {
        self.query.clear();
        self.results.clear();
        self.selected = 0;
        self.error = None;
        self.warning = None;
        self.in_flight = false;
        self.sync_status = None;
        self.view = SearchView::Results;
        self.ssh_agent_path_input = None;
        self.settings_selected = 0;
        self.scrolled_to = None;
        self.force_refresh();
        self.focus_search = true;
    }

    pub fn move_selection(&mut self, delta: i32) {
        let entry_count = self.display_entry_count();
        if entry_count == 0 {
            return;
        }
        let len = entry_count as i32;
        self.selected = ((self.selected as i32 + delta + len) % len) as usize;
    }

    pub fn open_selected_entry(&mut self) -> OpenSelectedAction {
        match self.display_entry(self.selected) {
            Some(DisplayEntry::SettingsCommand) => {
                self.view = SearchView::Settings;
                self.selected = 0;
                self.settings_selected = 0;
                OpenSelectedAction::None
            }
            Some(DisplayEntry::LockCommand) => OpenSelectedAction::LockVault,
            Some(DisplayEntry::VaultItem(idx)) => OpenSelectedAction::OpenResult(idx),
            None => OpenSelectedAction::None,
        }
    }

    pub fn close_settings_panel(&mut self) {
        self.view = SearchView::Results;
        self.selected = 0;
        self.ssh_agent_path_input = None;
        self.focus_search = true;
    }

    fn settings_command_visible(&self) -> bool {
        settings_command_matches(&self.query)
    }

    fn lock_command_visible(&self) -> bool {
        lock_command_matches(&self.query)
    }

    fn display_entry_count(&self) -> usize {
        usize::from(self.settings_command_visible())
            + usize::from(self.lock_command_visible())
            + self.results.len()
    }

    fn display_entry(&self, display_idx: usize) -> Option<DisplayEntry> {
        let mut cursor = 0;
        if self.settings_command_visible() {
            if display_idx == cursor {
                return Some(DisplayEntry::SettingsCommand);
            }
            cursor += 1;
        }
        if self.lock_command_visible() {
            if display_idx == cursor {
                return Some(DisplayEntry::LockCommand);
            }
            cursor += 1;
        }
        let item_idx = display_idx.checked_sub(cursor)?;
        self.results
            .get(item_idx)
            .map(|_| DisplayEntry::VaultItem(item_idx))
    }
}

pub fn settings_command_matches(query: &str) -> bool {
    let query = query.trim();
    query.chars().count() >= 2 && "settings".starts_with(&query.to_ascii_lowercase())
}

pub fn lock_command_matches(query: &str) -> bool {
    let query = query.trim();
    query.chars().count() >= 2 && "lock".starts_with(&query.to_ascii_lowercase())
}

pub fn draw_search(
    ctx: &Context,
    state: &mut SearchState,
    settings: &AppSettings,
    ssh_agent_status: &SshAgentStatus,
    icons: &mut IconCache,
) -> Option<SearchAction> {
    let mut action = None;
    let t = theme();

    if state.view == SearchView::Settings && !state.settings_command_visible() {
        state.close_settings_panel();
    }
    // Keys are consumed before the search field is drawn so it does not also receive them.
    handle_keys(ctx, state, settings, &mut action);

    let status = if let Some(error) = &state.error {
        Some((error.as_str(), t.danger))
    } else {
        state.warning.as_deref().map(|warning| (warning, t.warning))
    };
    if settings.show_keyboard_shortcuts || status.is_some() {
        let hints: &[(&str, &str)] = match (settings.show_keyboard_shortcuts, state.view) {
            (false, _) => &[],
            (true, SearchView::Results) => &[("↑↓", "Navigate"), ("⏎", "Open"), ("Esc", "Hide")],
            (true, SearchView::Settings) => {
                &[("↑↓", "Select"), ("Space", "Toggle"), ("Esc", "Back")]
            }
        };
        egui::TopBottomPanel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(ctx, |ui| widgets::footer(ui, hints, status));
    }

    egui::TopBottomPanel::top("header")
        .frame(widgets::header_frame())
        .show(ctx, |ui| draw_search_field(ui, state));

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(ctx, |ui| {
            if state.view == SearchView::Settings {
                if let Some(settings_action) = draw_settings(ui, state, settings, ssh_agent_status)
                {
                    action = Some(settings_action);
                }
            } else if state.query.trim().is_empty() {
                widgets::empty_state(
                    ui,
                    t.icon("\u{f002}", "🔎"),
                    "Type to search your vault · \"settings\" and \"lock\" are commands",
                    false,
                );
            } else if state.display_entry_count() == 0 {
                if state.in_flight || state.last_query.is_empty() {
                    widgets::empty_state(ui, "", "Searching…", true);
                } else {
                    widgets::empty_state(ui, t.icon("\u{f05e}", "∅"), "No matching items", false);
                }
            } else if let Some(row_action) = draw_results(ui, state, icons) {
                action = Some(row_action);
            }
        });

    action
}

fn handle_keys(
    ctx: &Context,
    state: &mut SearchState,
    settings: &AppSettings,
    action: &mut Option<SearchAction>,
) {
    let path_focused = ctx.memory(|m| m.has_focus(egui::Id::new(SSH_PATH_INPUT_ID)));
    let cursor_at_end = search_cursor_at_end(ctx, &state.query);
    ctx.input_mut(|input| match state.view {
        SearchView::Settings => {
            if path_focused {
                return;
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                state.settings_selected = (state.settings_selected + 1) % SETTINGS_ROWS;
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                state.settings_selected =
                    (state.settings_selected + SETTINGS_ROWS - 1) % SETTINGS_ROWS;
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Space)
                || input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
            {
                *action = toggle_setting(state.settings_selected, settings);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
                || input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft)
            {
                state.close_settings_panel();
            }
        }
        SearchView::Results => {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                state.move_selection(1);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                state.move_selection(-1);
            }
            // Right arrow opens only at the end of the query; elsewhere it moves the cursor.
            let open = input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                || (cursor_at_end
                    && state.display_entry_count() > 0
                    && input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowRight));
            // Enter while a newer search runs would open a row from the previous query.
            if open && !state.in_flight {
                match state.open_selected_entry() {
                    OpenSelectedAction::OpenResult(idx) => {
                        *action = Some(SearchAction::OpenResult(idx))
                    }
                    OpenSelectedAction::LockVault => *action = Some(SearchAction::LockVault),
                    OpenSelectedAction::None => {}
                }
            }
        }
    });
}

fn search_cursor_at_end(ctx: &Context, query: &str) -> bool {
    egui::TextEdit::load_state(ctx, egui::Id::new(SEARCH_INPUT_ID))
        .and_then(|edit| edit.cursor.char_range())
        .is_none_or(|range| range.primary.index >= query.chars().count())
}

fn draw_search_field(ui: &mut Ui, state: &mut SearchState) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(t.icon("\u{f002}", "🔎"))
                .size(t.input())
                .color(t.text_muted),
        );
        ui.add_space(6.0);
        let trailing = 44.0;
        let mut field = egui::TextEdit::singleline(&mut state.query)
            .id(egui::Id::new(SEARCH_INPUT_ID))
            .font(t.font(t.input()))
            .text_color(t.text_strong)
            .hint_text(RichText::new("Search vault").color(t.text_faint))
            .frame(false)
            .vertical_align(egui::Align::Center);
        if state.focus_search {
            field = field.cursor_at_end(true);
        }
        let response = ui.add_sized([(ui.available_width() - trailing).max(120.0), 32.0], field);
        if state.focus_search {
            response.request_focus();
            state.focus_search = false;
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if state.in_flight {
                ui.add(egui::Spinner::new().color(t.text_muted));
            } else if !state.query.trim().is_empty() && state.view == SearchView::Results {
                ui.label(RichText::new(state.results.len().to_string()).color(t.text_faint));
            }
        });
    });
}

fn draw_results(ui: &mut Ui, state: &mut SearchState, icons: &mut IconCache) -> Option<SearchAction> {
    let t = theme();
    let mut action = None;
    let scroll_to = (state.scrolled_to != Some(state.selected)).then_some(state.selected);
    state.scrolled_to = Some(state.selected);

    // The keyboard selection gets the first available worker, even before scrolling
    // brings it into view. Only visible rows request the remaining icons.
    if let Some(DisplayEntry::VaultItem(idx)) = state.display_entry(state.selected)
        && let Some(host) = state.results[idx].icon_host.as_deref()
    {
        icons.get(host);
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for i in 0..state.display_entry_count() {
                let Some(entry) = state.display_entry(i) else {
                    continue;
                };
                let selected = i == state.selected;
                let (rect, response) = widgets::row(ui, selected, widgets::ROW_HEIGHT);
                match entry {
                    DisplayEntry::SettingsCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f013}", "⚙"),
                        None,
                        "Settings",
                        Some("Quick access preferences"),
                        Some("command"),
                        selected,
                    ),
                    DisplayEntry::LockCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f023}", "🔒"),
                        None,
                        "Lock vault",
                        Some("Require the master password again"),
                        Some("command"),
                        selected,
                    ),
                    DisplayEntry::VaultItem(idx) => {
                        let item = &state.results[idx];
                        let image = ui
                            .is_rect_visible(rect)
                            .then(|| item.icon_host.as_deref().and_then(|host| icons.get(host)))
                            .flatten();
                        widgets::paint_row_content(
                            ui,
                            rect,
                            t.item_icon(&item.item_type),
                            image.as_ref(),
                            &item.name,
                            item.username.as_deref(),
                            item.folder.as_deref(),
                            selected,
                        );
                    }
                }
                if scroll_to == Some(i) {
                    ui.scroll_to_rect(rect, None);
                }
                if response.clicked() {
                    state.selected = i;
                    match entry {
                        DisplayEntry::SettingsCommand => {
                            state.open_selected_entry();
                        }
                        DisplayEntry::LockCommand => action = Some(SearchAction::LockVault),
                        DisplayEntry::VaultItem(idx) => {
                            action = Some(SearchAction::OpenResult(idx))
                        }
                    }
                }
            }
        });
    action
}

fn toggle_setting(row: usize, settings: &AppSettings) -> Option<SearchAction> {
    Some(match row {
        0 => SearchAction::SetKeyboardShortcuts(!settings.show_keyboard_shortcuts),
        1 => SearchAction::SetCloseAfterCopy(!settings.close_after_copy),
        2 => SearchAction::SetRestoreRecentItem(!settings.restore_recent_item),
        3 => SearchAction::SetShowWebsiteIcons(!settings.show_website_icons),
        4 => SearchAction::SetLockOnSystemLock(!settings.lock_on_system_lock),
        IDLE_TIMEOUT_ROW => SearchAction::SetLockAfterIdleTimeout(!settings.lock_after_idle_timeout),
        6 => SearchAction::SetSshAgentEnabled(!settings.ssh_agent_enabled),
        _ => return None,
    })
}

fn draw_settings(
    ui: &mut Ui,
    state: &mut SearchState,
    settings: &AppSettings,
    ssh_agent_status: &SshAgentStatus,
) -> Option<SearchAction> {
    let t = theme();
    let mut action = None;
    let rows: [(bool, &str, &str); SETTINGS_ROWS] = [
        (
            settings.show_keyboard_shortcuts,
            "Show keyboard shortcuts",
            "Show the hint bar at the bottom of the window",
        ),
        (
            settings.close_after_copy,
            "Close after copying",
            "Hide quick access after a value is copied",
        ),
        (
            settings.restore_recent_item,
            "Restore recent item",
            "Reopen the last item for 30 seconds after hiding",
        ),
        (
            settings.show_website_icons,
            "Show website icons",
            "Fetch icons from your server's icon service; cached for 30 days",
        ),
        (
            settings.lock_on_system_lock,
            "Lock when the screen locks",
            "Lock the vault when the desktop session locks",
        ),
        (
            settings.lock_after_idle_timeout,
            "Lock after idle timeout",
            "Lock the vault after the session has been idle",
        ),
        (
            settings.ssh_agent_enabled,
            "Enable SSH agent",
            "Serve SSH keys from the vault over a local agent socket",
        ),
    ];

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for (idx, (on, title, description)) in rows.iter().enumerate() {
                let response = widgets::toggle_row(
                    ui,
                    state.settings_selected == idx,
                    *on,
                    title,
                    description,
                );
                if response.clicked() {
                    state.settings_selected = idx;
                    action = toggle_setting(idx, settings);
                }
                if idx == IDLE_TIMEOUT_ROW && settings.lock_after_idle_timeout {
                    ui.horizontal(|ui| {
                        ui.add_space(54.0);
                        ui.label(RichText::new("Idle timeout").color(t.text_muted));
                        let mut minutes = settings.idle_lock_timeout_minutes.clamp(1, 1440);
                        let response = ui.add(
                            egui::DragValue::new(&mut minutes)
                                .range(1..=1440)
                                .speed(1)
                                .suffix(" min"),
                        );
                        // Save once a drag ends instead of on every intermediate value.
                        if response.changed() && !response.dragged() || response.drag_stopped() {
                            action = Some(SearchAction::SetIdleLockTimeoutMinutes(minutes));
                        }
                    });
                    ui.add_space(4.0);
                }
            }

            if settings.ssh_agent_enabled {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.add_space(54.0);
                    ui.vertical(|ui| {
                        let path = state
                            .ssh_agent_path_input
                            .get_or_insert_with(|| settings.ssh_agent_socket_path.clone());
                        widgets::field_label(ui, "Socket path (Enter to apply)");
                        let response = widgets::text_input(
                            ui,
                            egui::Id::new(SSH_PATH_INPUT_ID),
                            path,
                            "$HOME/.bitwarden-ssh.sock",
                            false,
                            t.body(),
                        );
                        let commit =
                            response.lost_focus() && *path != settings.ssh_agent_socket_path;
                        match config::expand_ssh_agent_socket_path(path) {
                            Ok(expanded) => {
                                if commit {
                                    action =
                                        Some(SearchAction::SetSshAgentSocketPath(path.clone()));
                                }
                                ui.label(
                                    RichText::new(format!("SSH_AUTH_SOCK={}", expanded.display()))
                                        .size(t.small())
                                        .color(t.text_muted),
                                );
                            }
                            Err(e) => widgets::error_line(ui, &e),
                        }
                        ui.label(
                            RichText::new(&ssh_agent_status.message)
                                .size(t.small())
                                .color(if ssh_agent_status.active {
                                    t.success
                                } else {
                                    t.text_muted
                                }),
                        );
                    });
                });
            }
        });
    action
}

pub enum SearchAction {
    OpenResult(usize),
    SetKeyboardShortcuts(bool),
    SetCloseAfterCopy(bool),
    SetRestoreRecentItem(bool),
    SetShowWebsiteIcons(bool),
    SetLockOnSystemLock(bool),
    SetLockAfterIdleTimeout(bool),
    SetIdleLockTimeoutMinutes(u64),
    SetSshAgentEnabled(bool),
    SetSshAgentSocketPath(String),
    LockVault,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str) -> BwItem {
        BwItem {
            id: id.to_string(),
            name: format!("Item {id}"),
            username: None,
            folder: None,
            item_type: "login".to_string(),
            icon_host: None,
        }
    }

    #[test]
    fn settings_command_matches_query_prefixes_after_two_chars() {
        assert!(!settings_command_matches(""));
        assert!(!settings_command_matches("s"));
        assert!(settings_command_matches("se"));
        assert!(settings_command_matches("set"));
        assert!(settings_command_matches("settings"));
        assert!(settings_command_matches("SeT"));
        assert!(!settings_command_matches("settingsx"));
        assert!(!settings_command_matches("vault"));
    }

    #[test]
    fn settings_command_is_pinned_before_vault_results() {
        let mut state = SearchState {
            query: "set".to_string(),
            results: vec![item("1"), item("2")],
            ..SearchState::default()
        };

        assert_eq!(state.display_entry_count(), 3);
        assert_eq!(state.open_selected_entry(), OpenSelectedAction::None);
        assert_eq!(state.view, SearchView::Settings);

        state.close_settings_panel();
        state.move_selection(1);
        assert_eq!(
            state.open_selected_entry(),
            OpenSelectedAction::OpenResult(0)
        );
    }

    #[test]
    fn lock_command_matches_query_prefixes_after_two_chars() {
        assert!(!lock_command_matches(""));
        assert!(!lock_command_matches("l"));
        assert!(lock_command_matches("lo"));
        assert!(lock_command_matches("loc"));
        assert!(lock_command_matches("lock"));
        assert!(lock_command_matches("Lo"));
        assert!(!lock_command_matches("locked"));
        assert!(!lock_command_matches("settings"));
    }

    #[test]
    fn lock_command_is_pinned_before_vault_results() {
        let mut state = SearchState {
            query: "lo".to_string(),
            results: vec![item("1"), item("2")],
            ..SearchState::default()
        };

        assert_eq!(state.display_entry_count(), 3);
        assert_eq!(state.open_selected_entry(), OpenSelectedAction::LockVault);

        state.move_selection(1);
        assert_eq!(
            state.open_selected_entry(),
            OpenSelectedAction::OpenResult(0)
        );
    }

    #[test]
    fn closing_settings_panel_returns_to_results_without_quitting_state() {
        let mut state = SearchState {
            query: "settings".to_string(),
            view: SearchView::Settings,
            selected: 3,
            ..SearchState::default()
        };

        state.close_settings_panel();

        assert_eq!(state.view, SearchView::Results);
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn reset_for_reopen_clears_stale_results_and_allows_same_query_again() {
        let mut state = SearchState {
            query: "tail".to_string(),
            results: vec![item("1"), item("2")],
            selected: 1,
            in_flight: true,
            last_query: "tail".to_string(),
            last_query_time: Some(std::time::Instant::now()),
            sync_status: Some(SyncStatus::default()),
            focus_search: false,
            ..SearchState::default()
        };

        state.reset_for_reopen();

        assert!(state.query.is_empty());
        assert!(state.results.is_empty());
        assert_eq!(state.selected, 0);
        assert!(!state.in_flight);
        assert!(state.focus_search);

        state.query = "tail".to_string();
        assert!(state.needs_search());
    }

    #[test]
    fn selection_wraps_across_all_results() {
        let mut state = SearchState {
            results: vec![item("1"), item("2"), item("3")],
            ..SearchState::default()
        };

        state.move_selection(1);
        assert_eq!(state.selected, 1);
        state.move_selection(2);
        assert_eq!(state.selected, 0);
        state.move_selection(-1);
        assert_eq!(state.selected, 2);
    }
}
