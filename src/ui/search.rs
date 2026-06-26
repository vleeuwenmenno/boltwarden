use crate::model::{BwItem, SyncStatus};
use egui::{Context, Ui};

pub const SEARCH_WIDTH: f32 = 673.0;
pub const SEARCH_HEIGHT: f32 = 72.0;
pub const SEARCH_HORIZONTAL_MARGIN: f32 = 20.0;
pub const SEARCH_TOP_MARGIN: f32 = 8.0;
pub const DROPDOWN_GAP: f32 = 14.0;
pub const DROPDOWN_ROW_HEIGHT: f32 = 62.0;
pub const DROPDOWN_MAX_ROWS: usize = 6;
const DROPDOWN_STATIC_HEIGHT: f32 = 23.0;
const SHORTCUT_BAR_HEIGHT: f32 = 34.0;
const SHORTCUT_BAR_BODY_HEIGHT: f32 = 24.0;
const DROPDOWN_MAX_STATUS_HEIGHT: f32 = 44.0;
const SETTINGS_PANEL_HEIGHT: f32 = 168.0;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShortcutKind {
    Search,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyCap {
    UpDown,
    Enter,
    Right,
    Left,
    Esc,
    Space,
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
    }

    pub fn should_show_dropdown(&self) -> bool {
        let has_query = !self.query.trim().is_empty();
        self.view == SearchView::Settings
            || self.settings_command_visible()
            || self.lock_command_visible()
            || (has_query
                && (self.in_flight
                    || self.error.is_some()
                    || self.warning.is_some()
                    || !self.results.is_empty()
                    || (!self.last_query.is_empty() && self.results.is_empty())))
    }

    pub fn dropdown_height(&self, show_keyboard_shortcuts: bool) -> f32 {
        let body_height = if self.view == SearchView::Settings {
            SETTINGS_PANEL_HEIGHT
        } else if self.display_entry_count() == 0 {
            50.0
        } else {
            result_rows_height(self.display_entry_count())
        };

        DROPDOWN_STATIC_HEIGHT
            + body_height
            + status_height(self)
            + shortcut_bar_height(show_keyboard_shortcuts)
    }

    #[cfg(test)]
    pub fn visible_result_rows_height(&self) -> f32 {
        if self.display_entry_count() == 0 {
            0.0
        } else {
            result_rows_height(self.display_entry_count())
        }
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

pub fn search_window_height(show_keyboard_shortcuts: bool) -> f32 {
    SEARCH_HEIGHT
        + DROPDOWN_GAP
        + DROPDOWN_STATIC_HEIGHT
        + result_rows_height(DROPDOWN_MAX_ROWS)
        + shortcut_bar_height(show_keyboard_shortcuts)
        + DROPDOWN_MAX_STATUS_HEIGHT
}

pub fn settings_command_matches(query: &str) -> bool {
    let query = query.trim();
    query.chars().count() >= 2 && "settings".starts_with(&query.to_ascii_lowercase())
}

pub fn lock_command_matches(query: &str) -> bool {
    let query = query.trim();
    query.chars().count() >= 2 && "lock".starts_with(&query.to_ascii_lowercase())
}

fn shortcut_bar_height(show_keyboard_shortcuts: bool) -> f32 {
    if show_keyboard_shortcuts {
        SHORTCUT_BAR_HEIGHT
    } else {
        0.0
    }
}

pub fn draw_search(
    _ctx: &Context,
    ui: &mut Ui,
    state: &mut SearchState,
    show_keyboard_shortcuts: bool,
    close_after_copy: bool,
    restore_recent_item: bool,
) -> Option<SearchAction> {
    let mut action = None;

    if state.view == SearchView::Settings && !state.settings_command_visible() {
        state.view = SearchView::Results;
        state.selected = 0;
    }

    ui.input_mut(|input| {
        match state.view {
            SearchView::Settings => {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Space) {
                    action = Some(SearchAction::SetKeyboardShortcuts(!show_keyboard_shortcuts));
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
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    || input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowRight)
                {
                    match state.open_selected_entry() {
                        OpenSelectedAction::OpenResult(idx) => {
                            action = Some(SearchAction::OpenResult(idx));
                        }
                        OpenSelectedAction::LockVault => {
                            action = Some(SearchAction::LockVault);
                        }
                        OpenSelectedAction::None => {}
                    }
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                    action = Some(SearchAction::Quit);
                }
            }
        }
    });

    let panel_width = ui.available_width();
    let capsule_width = (panel_width - SEARCH_HORIZONTAL_MARGIN * 2.0).max(260.0);
    trace_search_ui("search", state, format!("panel_width={panel_width:.1}"));
    ui.set_min_size(egui::vec2(panel_width, SEARCH_HEIGHT));
    ui.add_space(SEARCH_TOP_MARGIN);
    ui.horizontal(|ui| {
        ui.add_space(SEARCH_HORIZONTAL_MARGIN);
        let frame = egui::Frame::new()
            .fill(egui::Color32::from_rgb(22, 24, 30))
            .stroke(egui::Stroke::new(
                1.0,
                if ui.memory(|m| m.has_focus(egui::Id::new("vault-search-input"))) {
                    egui::Color32::from_rgb(96, 164, 255)
                } else {
                    egui::Color32::from_rgb(58, 64, 76)
                },
            ))
            .inner_margin(egui::Margin::symmetric(14, 8))
            .corner_radius(8.0);

        frame.show(ui, |ui| {
            ui.set_width(capsule_width - 28.0);
            ui.horizontal_centered(|ui| {
                ui.add_sized(
                    [24.0, 32.0],
                    egui::Label::new(
                        egui::RichText::new("🔎")
                            .size(18.0)
                            .color(egui::Color32::from_rgb(130, 140, 156)),
                    ),
                );

                let available_width = (ui.available_width() - 38.0).max(120.0);
                let mut search_field = TextEdit::singleline(&mut state.query)
                    .id(egui::Id::new("vault-search-input"))
                    .hint_text("Search vault...")
                    .font(egui::FontId::proportional(24.0))
                    .margin(egui::Margin::symmetric(4, 4))
                    .vertical_align(egui::Align::Center)
                    .desired_width(available_width)
                    .frame(false)
                    .interactive(true);

                if state.focus_search {
                    search_field = search_field.cursor_at_end(true);
                }

                let search_response = ui.add_sized([available_width, 36.0], search_field);

                if state.focus_search {
                    search_response.request_focus();
                    state.focus_search = false;
                }

                ui.allocate_ui_with_layout(
                    egui::vec2(30.0, 32.0),
                    egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if state.in_flight {
                            ui.spinner();
                        } else if !state.query.trim().is_empty() {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{}",
                                    state.results.len().min(99)
                                ))
                                .size(13.0)
                                .color(egui::Color32::from_rgb(150, 158, 170)),
                            );
                        }
                    },
                );
            });
        });
    });

    if show_keyboard_shortcuts && !state.should_show_dropdown() {
        draw_shortcut_bar_with_margins(ui, ShortcutKind::Search);
    }

    if state.should_show_dropdown() {
        ui.add_space(DROPDOWN_GAP);
        if let Some(dropdown_action) = draw_search_dropdown(
            ui,
            state,
            show_keyboard_shortcuts,
            close_after_copy,
            restore_recent_item,
        ) {
            action = Some(dropdown_action);
        }
    }

    action
}

pub fn draw_search_panel(
    ctx: &Context,
    ui: &mut Ui,
    state: &mut SearchState,
    show_keyboard_shortcuts: bool,
    close_after_copy: bool,
    restore_recent_item: bool,
) -> Option<SearchAction> {
    draw_search(
        ctx,
        ui,
        state,
        show_keyboard_shortcuts,
        close_after_copy,
        restore_recent_item,
    )
}

fn draw_search_dropdown(
    ui: &mut Ui,
    state: &mut SearchState,
    show_keyboard_shortcuts: bool,
    close_after_copy: bool,
    restore_recent_item: bool,
) -> Option<SearchAction> {
    let mut action = None;
    let panel_width = ui.available_width();
    let dropdown_width = (panel_width - SEARCH_HORIZONTAL_MARGIN * 2.0).max(260.0);
    let dropdown_height = state.dropdown_height(show_keyboard_shortcuts);
    trace_search_ui(
        "dropdown",
        state,
        format!("panel_width={panel_width:.1} dropdown_height={dropdown_height:.1}"),
    );
    ui.set_min_width(panel_width);
    ui.set_min_height(dropdown_height);

    let frame = egui::Frame::new()
        .fill(egui::Color32::from_rgb(18, 20, 26))
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(52, 58, 70)))
        .inner_margin(egui::Margin::symmetric(8, 8))
        .corner_radius(8.0)
        .shadow(egui::epaint::Shadow {
            offset: [0, 8],
            blur: 24,
            spread: 0,
            color: egui::Color32::from_black_alpha(96),
        });

    ui.allocate_ui_with_layout(
        egui::vec2(panel_width, dropdown_height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.add_space(7.0);
            ui.horizontal(|ui| {
                ui.add_space(SEARCH_HORIZONTAL_MARGIN);
                frame.show(ui, |ui| {
                    ui.set_width(dropdown_width - 16.0);
                    if state.view == SearchView::Settings {
                        if let Some(settings_action) = draw_settings_panel(
                            ui,
                            show_keyboard_shortcuts,
                            close_after_copy,
                            restore_recent_item,
                        ) {
                            action = Some(settings_action);
                        }
                    } else if state.in_flight && state.display_entry_count() == 0 {
                        empty_message(ui, "Searching...");
                    } else if state.display_entry_count() == 0 && !state.last_query.is_empty() {
                        empty_message(ui, "No results");
                    } else {
                        if let Some(row_action) = draw_visible_entries(ui, state) {
                            action = Some(row_action);
                        }
                    }

                    if let Some(e) = &state.error {
                        status_line(ui, egui::Color32::from_rgb(245, 110, 110), format!("⚠ {e}"));
                    }
                    if let Some(warning) = &state.warning {
                        status_line(
                            ui,
                            egui::Color32::from_rgb(232, 178, 82),
                            format!("⚠ {warning}"),
                        );
                    }
                    if show_keyboard_shortcuts {
                        let hints = if state.view == SearchView::Settings {
                            ShortcutKind::Settings
                        } else {
                            ShortcutKind::Search
                        };
                        draw_shortcut_bar(ui, hints);
                    }
                });
            });
        },
    );

    action
}

fn draw_visible_entries(ui: &mut Ui, state: &mut SearchState) -> Option<SearchAction> {
    let entry_count = state.display_entry_count();
    let row_block_height = result_rows_height(entry_count);
    let mut action = None;
    trace_search_ui(
        "rows",
        state,
        format!(
            "available_width={:.1} row_block_height={row_block_height:.1}",
            ui.available_width()
        ),
    );

    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), row_block_height),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.set_min_height(row_block_height);
            let first = visible_window_start(state.selected, entry_count);
            let last = (first + DROPDOWN_MAX_ROWS).min(entry_count);

            for i in first..last {
                let selected = i == state.selected;
                let Some(entry) = state.display_entry(i) else {
                    continue;
                };
                let resp = match entry {
                    DisplayEntry::SettingsCommand => draw_settings_command_row(ui, selected),
                    DisplayEntry::LockCommand => draw_lock_command_row(ui, selected),
                    DisplayEntry::VaultItem(idx) => {
                        draw_result_row(ui, &state.results[idx], selected)
                    }
                };

                if resp.clicked() {
                    state.selected = i;
                    match entry {
                        DisplayEntry::SettingsCommand => {
                            state.open_selected_entry();
                        }
                        DisplayEntry::LockCommand => {
                            action = Some(SearchAction::LockVault);
                        }
                        DisplayEntry::VaultItem(idx) => {
                            action = Some(SearchAction::OpenResult(idx));
                        }
                    }
                }

                if i + 1 < last {
                    ui.add_space(6.0);
                }
            }
        },
    );

    action
}

fn draw_settings_command_row(ui: &mut Ui, selected: bool) -> egui::Response {
    draw_command_row(ui, "⚙", "Settings", "Quick access preferences", selected)
}

fn draw_lock_command_row(ui: &mut Ui, selected: bool) -> egui::Response {
    draw_command_row(
        ui,
        "🔒",
        "Lock Vault",
        "Require master password again",
        selected,
    )
}

fn draw_command_row(
    ui: &mut Ui,
    icon: &str,
    title: &str,
    secondary: &str,
    selected: bool,
) -> egui::Response {
    let row_size = egui::vec2(ui.available_width(), DROPDOWN_ROW_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(row_size, egui::Sense::click());
    let bg = if selected {
        egui::Color32::from_rgb(38, 58, 86)
    } else if response.hovered() {
        egui::Color32::from_rgb(28, 32, 42)
    } else {
        egui::Color32::from_rgb(23, 26, 34)
    };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(92, 150, 226))
    } else if response.hovered() {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 56, 70))
    } else {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(34, 38, 48))
    };
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, bg);
    painter.rect_stroke(rect, 6.0, stroke, egui::StrokeKind::Inside);

    painter.text(
        egui::pos2(rect.left() + 18.0, rect.center().y),
        egui::Align2::CENTER_CENTER,
        icon,
        egui::FontId::proportional(18.0),
        egui::Color32::from_rgb(236, 240, 248),
    );
    painter.text(
        egui::pos2(rect.left() + 48.0, rect.top() + 13.0),
        egui::Align2::LEFT_TOP,
        title,
        egui::FontId::proportional(15.5),
        egui::Color32::from_rgb(235, 238, 244),
    );
    painter.text(
        egui::pos2(rect.left() + 48.0, rect.top() + 35.0),
        egui::Align2::LEFT_TOP,
        secondary,
        egui::FontId::proportional(12.0),
        egui::Color32::from_rgb(120, 130, 146),
    );

    response
}

fn draw_settings_panel(
    ui: &mut Ui,
    show_keyboard_shortcuts: bool,
    close_after_copy: bool,
    restore_recent_item: bool,
) -> Option<SearchAction> {
    let mut action = None;
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), SETTINGS_PANEL_HEIGHT),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("Settings")
                    .strong()
                    .color(egui::Color32::from_rgb(235, 238, 244)),
            );
            ui.add_space(10.0);

            let mut value = show_keyboard_shortcuts;
            let response = ui.checkbox(&mut value, "Show keyboard shortcuts");
            if response.changed() {
                action = Some(SearchAction::SetKeyboardShortcuts(value));
            }
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("Controls whether shortcut hint bars are displayed.")
                    .small()
                    .color(egui::Color32::from_rgb(126, 136, 152)),
            );
            ui.add_space(10.0);

            let mut close_value = close_after_copy;
            let response = ui.checkbox(&mut close_value, "Close after copying");
            if response.changed() {
                action = Some(SearchAction::SetCloseAfterCopy(close_value));
            }
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("Hides quick access after a value is copied.")
                    .small()
                    .color(egui::Color32::from_rgb(126, 136, 152)),
            );
            ui.add_space(10.0);

            let mut restore_value = restore_recent_item;
            let response = ui.checkbox(&mut restore_value, "Restore recent item");
            if response.changed() {
                action = Some(SearchAction::SetRestoreRecentItem(restore_value));
            }
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("Reopens the last item for 30 seconds after hiding.")
                    .small()
                    .color(egui::Color32::from_rgb(126, 136, 152)),
            );
        },
    );
    action
}

fn draw_result_row(ui: &mut Ui, item: &BwItem, selected: bool) -> egui::Response {
    let row_size = egui::vec2(ui.available_width(), DROPDOWN_ROW_HEIGHT);
    let (rect, response) = ui.allocate_exact_size(row_size, egui::Sense::click());
    let bg = if selected {
        egui::Color32::from_rgb(38, 58, 86)
    } else if response.hovered() {
        egui::Color32::from_rgb(28, 32, 42)
    } else {
        egui::Color32::from_rgb(23, 26, 34)
    };
    let stroke = if selected {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(92, 150, 226))
    } else if response.hovered() {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 56, 70))
    } else {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(34, 38, 48))
    };
    let painter = ui.painter();
    painter.rect_filled(rect, 6.0, bg);
    painter.rect_stroke(rect, 6.0, stroke, egui::StrokeKind::Inside);

    let icon_pos = egui::pos2(rect.left() + 18.0, rect.center().y);
    painter.text(
        icon_pos,
        egui::Align2::CENTER_CENTER,
        item_icon(&item.item_type),
        egui::FontId::proportional(18.0),
        egui::Color32::from_rgb(236, 240, 248),
    );

    let title_pos = egui::pos2(rect.left() + 48.0, rect.top() + 13.0);
    painter.text(
        title_pos,
        egui::Align2::LEFT_TOP,
        truncate_text(&item.name, 34),
        egui::FontId::proportional(15.5),
        egui::Color32::from_rgb(235, 238, 244),
    );

    if let Some(username) = &item.username {
        painter.text(
            egui::pos2(rect.left() + 248.0, rect.top() + 15.0),
            egui::Align2::LEFT_TOP,
            truncate_text(username, 36),
            egui::FontId::proportional(13.0),
            egui::Color32::from_rgb(152, 162, 178),
        );
    }

    let secondary = item.folder.as_deref().unwrap_or(&item.item_type);
    painter.text(
        egui::pos2(rect.left() + 48.0, rect.top() + 35.0),
        egui::Align2::LEFT_TOP,
        truncate_text(secondary, 56),
        egui::FontId::proportional(12.0),
        egui::Color32::from_rgb(120, 130, 146),
    );

    response
}

fn item_icon(item_type: &str) -> &'static str {
    match item_type {
        "login" => "🔑",
        "secureNote" => "📝",
        "card" => "💳",
        "identity" => "👤",
        _ => "📦",
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        truncated.push('…');
    }
    truncated
}

fn empty_message(ui: &mut Ui, text: &str) {
    ui.add_space(12.0);
    ui.horizontal_centered(|ui| {
        if text == "Searching..." {
            ui.spinner();
        }
        ui.label(
            egui::RichText::new(text)
                .italics()
                .color(egui::Color32::from_rgb(148, 156, 170)),
        );
    });
    ui.add_space(12.0);
}

fn status_line(ui: &mut Ui, color: egui::Color32, text: String) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(text).small().color(color));
}

fn draw_shortcut_bar_with_margins(ui: &mut Ui, kind: ShortcutKind) {
    ui.horizontal(|ui| {
        ui.add_space(SEARCH_HORIZONTAL_MARGIN);
        let width = (ui.available_width() - SEARCH_HORIZONTAL_MARGIN).max(260.0);
        ui.allocate_ui_with_layout(
            egui::vec2(width, SHORTCUT_BAR_HEIGHT),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                draw_shortcut_bar(ui, kind);
            },
        );
    });
}

fn draw_shortcut_bar(ui: &mut Ui, kind: ShortcutKind) {
    ui.add_space(8.0);
    let width = ui.available_width().max(0.0);
    if width <= 1.0 {
        return;
    }

    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(width, SHORTCUT_BAR_BODY_HEIGHT),
        egui::Sense::hover(),
    );
    let painter = ui.painter();

    painter.rect_filled(rect, 7.0, egui::Color32::from_rgb(15, 17, 22));
    painter.rect_stroke(
        rect,
        7.0,
        egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 44, 55)),
        egui::StrokeKind::Inside,
    );

    let hints: &[(&str, &[KeyCap])] = match kind {
        ShortcutKind::Search => &[
            ("Navigate", &[KeyCap::UpDown]),
            ("Open", &[KeyCap::Enter, KeyCap::Right]),
            ("Hide", &[KeyCap::Esc]),
        ],
        ShortcutKind::Settings => &[
            ("Toggle", &[KeyCap::Space]),
            ("Back", &[KeyCap::Esc, KeyCap::Left]),
        ],
    };

    let mut cursor = rect.left() + 10.0;
    let right_limit = rect.right() - 10.0;
    for (label, keys) in hints {
        let label_width = shortcut_label_width(label);
        let keys_width = keys
            .iter()
            .map(|key| keycap_size(*key).x)
            .sum::<f32>()
            + keys.len().saturating_sub(1) as f32 * 3.0;
        let hint_width = label_width + 7.0 + keys_width;
        if cursor + hint_width > right_limit {
            break;
        }

        painter.text(
            egui::pos2(cursor, rect.center().y),
            egui::Align2::LEFT_CENTER,
            *label,
            egui::FontId::proportional(11.0),
            egui::Color32::from_rgb(118, 128, 144),
        );
        cursor += label_width + 7.0;

        for (idx, key) in keys.iter().enumerate() {
            if idx > 0 {
                cursor += 3.0;
            }
            let size = keycap_size(*key);
            let key_rect = egui::Rect::from_min_size(
                egui::pos2(cursor, rect.center().y - size.y / 2.0),
                size,
            );
            paint_keycap(painter, key_rect, *key);
            cursor += size.x;
        }
        cursor += 14.0;
    }
}

fn shortcut_label_width(label: &str) -> f32 {
    label.chars().count() as f32 * 6.0
}

fn paint_keycap(painter: &egui::Painter, rect: egui::Rect, key: KeyCap) {
    let bg = egui::Color32::from_rgb(35, 40, 50);
    let stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(62, 70, 84));
    painter.rect_filled(rect, 5.0, bg);
    painter.rect_stroke(rect, 5.0, stroke, egui::StrokeKind::Inside);

    match key {
        KeyCap::Esc => {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Esc",
                egui::FontId::proportional(10.0),
                egui::Color32::from_rgb(202, 210, 222),
            );
        }
        KeyCap::Space => {
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Space",
                egui::FontId::proportional(10.0),
                egui::Color32::from_rgb(202, 210, 222),
            );
        }
        KeyCap::UpDown => {
            draw_arrow_icon(
                painter,
                rect.center() + egui::vec2(-3.5, 0.0),
                egui::vec2(0.0, -4.5),
            );
            draw_arrow_icon(
                painter,
                rect.center() + egui::vec2(3.5, 0.0),
                egui::vec2(0.0, 4.5),
            );
        }
        KeyCap::Enter => {
            let color = egui::Color32::from_rgb(202, 210, 222);
            let stroke = egui::Stroke::new(1.4, color);
            let left = rect.left() + 6.0;
            let top = rect.top() + 6.0;
            let mid_y = rect.center().y + 3.0;
            let right = rect.right() - 6.0;
            painter.line_segment([egui::pos2(right, top), egui::pos2(right, mid_y)], stroke);
            painter.line_segment([egui::pos2(right, mid_y), egui::pos2(left, mid_y)], stroke);
            painter.line_segment(
                [egui::pos2(left, mid_y), egui::pos2(left + 4.0, mid_y - 3.0)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(left, mid_y), egui::pos2(left + 4.0, mid_y + 3.0)],
                stroke,
            );
        }
        KeyCap::Right => {
            draw_arrow_icon(painter, rect.center(), egui::vec2(5.0, 0.0));
        }
        KeyCap::Left => {
            draw_arrow_icon(painter, rect.center(), egui::vec2(-5.0, 0.0));
        }
    };
}

fn keycap_size(key: KeyCap) -> egui::Vec2 {
    match key {
        KeyCap::Esc => egui::vec2(28.0, 20.0),
        KeyCap::Space => egui::vec2(42.0, 20.0),
        KeyCap::Enter => egui::vec2(26.0, 20.0),
        KeyCap::UpDown => egui::vec2(30.0, 20.0),
        KeyCap::Right | KeyCap::Left => egui::vec2(22.0, 20.0),
    }
}

fn draw_arrow_icon(painter: &egui::Painter, center: egui::Pos2, delta: egui::Vec2) {
    let color = egui::Color32::from_rgb(202, 210, 222);
    let stroke = egui::Stroke::new(1.5, color);
    let start = center - delta * 0.55;
    let end = center + delta * 0.55;
    painter.line_segment([start, end], stroke);

    let direction = delta.normalized();
    let perp = egui::vec2(-direction.y, direction.x);
    let back = end - direction * 4.0;
    painter.line_segment([end, back + perp * 3.0], stroke);
    painter.line_segment([end, back - perp * 3.0], stroke);
}

fn status_height(state: &SearchState) -> f32 {
    let mut rows = 0.0;
    if state.error.is_some() {
        rows += 22.0;
    }
    if state.warning.is_some() {
        rows += 22.0;
    }
    rows
}

fn result_rows_height(count: usize) -> f32 {
    let rows = count.min(DROPDOWN_MAX_ROWS);
    if rows == 0 {
        0.0
    } else {
        rows as f32 * DROPDOWN_ROW_HEIGHT + (rows - 1) as f32 * 6.0
    }
}

fn visible_window_start(selected: usize, count: usize) -> usize {
    if count <= DROPDOWN_MAX_ROWS || selected < DROPDOWN_MAX_ROWS {
        0
    } else {
        (selected + 1 - DROPDOWN_MAX_ROWS).min(count - DROPDOWN_MAX_ROWS)
    }
}

fn trace_search_ui(label: &str, state: &SearchState, extra: String) {
    if state.query.trim().is_empty() && state.results.is_empty() && !state.in_flight {
        return;
    }

    let line = format!(
        "pid={} label={} query_len={} results={} selected={} in_flight={} should_show={} height={:.1} {extra}",
        std::process::id(),
        label,
        state.query.chars().count(),
        state.results.len(),
        state.selected,
        state.in_flight,
        state.should_show_dropdown(),
        state.dropdown_height(true),
    );

    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let Ok(mut seen) = seen.lock() else {
        return;
    };
    if !seen.insert(line.clone()) {
        return;
    }
    drop(seen);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/bw-quick-access-ui.log")
    {
        let _ = std::io::Write::write_all(&mut file, format!("{timestamp} {line}\n").as_bytes());
    }
}

pub enum SearchAction {
    OpenResult(usize),
    SetKeyboardShortcuts(bool),
    SetCloseAfterCopy(bool),
    SetRestoreRecentItem(bool),
    LockVault,
    Quit,
}

use egui::TextEdit;

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
        }
    }

    #[test]
    fn dropdown_shows_while_search_is_in_flight() {
        let state = SearchState {
            query: "tail".to_string(),
            in_flight: true,
            ..SearchState::default()
        };

        assert!(state.should_show_dropdown());
    }

    #[test]
    fn dropdown_height_includes_multiple_uniform_rows() {
        let state = SearchState {
            query: "tail".to_string(),
            results: vec![item("1"), item("2"), item("3")],
            last_query: "tail".to_string(),
            ..SearchState::default()
        };

        assert_eq!(
            state.visible_result_rows_height(),
            DROPDOWN_ROW_HEIGHT * 3.0 + 6.0 * 2.0
        );
        assert!(state.dropdown_height(true) > state.visible_result_rows_height());
    }

    #[test]
    fn search_window_height_can_fit_full_dropdown() {
        let state = SearchState {
            query: "tail".to_string(),
            results: vec![
                item("1"),
                item("2"),
                item("3"),
                item("4"),
                item("5"),
                item("6"),
                item("7"),
            ],
            last_query: "tail".to_string(),
            warning: Some("warning".to_string()),
            error: Some("error".to_string()),
            ..SearchState::default()
        };

        assert!(
            search_window_height(true) >= SEARCH_HEIGHT + DROPDOWN_GAP + state.dropdown_height(true)
        );
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
    fn disabling_shortcuts_removes_shortcut_height_from_layout() {
        let state = SearchState {
            query: "tail".to_string(),
            results: vec![item("1"), item("2")],
            last_query: "tail".to_string(),
            ..SearchState::default()
        };

        assert_eq!(
            state.dropdown_height(true) - state.dropdown_height(false),
            SHORTCUT_BAR_HEIGHT
        );
        assert_eq!(
            search_window_height(true) - search_window_height(false),
            SHORTCUT_BAR_HEIGHT
        );
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
    fn visible_window_start_keeps_keyboard_selection_visible() {
        assert_eq!(visible_window_start(0, 9), 0);
        assert_eq!(visible_window_start(5, 9), 0);
        assert_eq!(visible_window_start(6, 9), 1);
        assert_eq!(visible_window_start(8, 9), 3);
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
