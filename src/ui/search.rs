use crate::config::{self, AppSettings, PasskeyVerification, StartList};
use crate::icons::IconCache;
use crate::model::{BwItem, ItemState, SshAgentStatus, SyncStatus};
use crate::ui::paired_browsers::{PairedBrowsersAction, PairedBrowsersState, draw_paired_browsers};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Context, RichText, Ui};

const SEARCH_INPUT_ID: &str = "vault-search-input";
const SSH_PATH_INPUT_ID: &str = "settings-ssh-socket-path";
const SETTINGS_ROWS: usize = 15;
const BROWSER_SETUP_ROW: usize = 14;
const PASSKEY_VERIFICATION_ROW: usize = 13;
const PAIRED_BROWSERS_ROW: usize = 12;
const DEFAULT_URI_MATCH_ROW: usize = 11;
const SCREEN_CAPTURE_ROW: usize = 5;
const START_LIST_ROW: usize = 3;
const IDLE_TIMEOUT_ROW: usize = 7;
/// Items shown in the "Recently edited/created" start lists.
const START_LIST_LIMIT: usize = 20;
const NOTICE_DURATION: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchView {
    Results,
    Settings,
    PairedBrowsers,
    BrowserSetup,
    Archived,
    Trash,
}

impl SearchView {
    /// Which items the view lists; `None` for the settings panel.
    pub fn item_state(self) -> Option<ItemState> {
        match self {
            Self::Results => Some(ItemState::Active),
            Self::Archived => Some(ItemState::Archived),
            Self::Trash => Some(ItemState::Deleted),
            Self::Settings | Self::PairedBrowsers | Self::BrowserSetup => None,
        }
    }

    fn is_item_list(self) -> bool {
        matches!(self, Self::Archived | Self::Trash)
    }
}

/// How the archived and trash lists are ordered. Tab cycles through the keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListSortKey {
    /// When the item was archived or trashed.
    StateChanged,
    Name,
    Modified,
}

impl ListSortKey {
    fn next(self) -> Self {
        match self {
            Self::StateChanged => Self::Name,
            Self::Name => Self::Modified,
            Self::Modified => Self::StateChanged,
        }
    }

    fn label(self, view: SearchView) -> &'static str {
        match (self, view) {
            (Self::StateChanged, SearchView::Trash) => "Date deleted",
            (Self::StateChanged, _) => "Date archived",
            (Self::Name, _) => "Name",
            (Self::Modified, _) => "Last modified",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListSort {
    pub key: ListSortKey,
    pub descending: bool,
}

impl Default for ListSort {
    /// Most recently archived or deleted first.
    fn default() -> Self {
        Self {
            key: ListSortKey::StateChanged,
            descending: true,
        }
    }
}

impl ListSort {
    fn apply(self, items: &mut [BwItem]) {
        items.sort_by(|a, b| {
            let name = |item: &BwItem| item.name.to_lowercase();
            let ordering = match self.key {
                ListSortKey::StateChanged => {
                    a.dates.state_changed_at.cmp(&b.dates.state_changed_at)
                }
                ListSortKey::Name => name(a).cmp(&name(b)),
                ListSortKey::Modified => a.dates.revision_date.cmp(&b.dates.revision_date),
            };
            let ordering = if self.descending {
                ordering.reverse()
            } else {
                ordering
            };
            // Ties (and items without a date) stay in name order.
            ordering.then_with(|| name(a).cmp(&name(b)))
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayEntry {
    SettingsCommand,
    PairedBrowsersCommand,
    LockCommand,
    ArchivedCommand,
    TrashCommand,
    NewItemCommand,
    WindowCommand,
    VaultItem(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenSelectedAction {
    None,
    OpenResult(usize),
    LockVault,
    NewItem,
    OpenWindow,
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
    pub syncing: bool,
    pub view: SearchView,
    /// Draft of the SSH socket path; `None` until the settings panel loads the saved value.
    pub ssh_agent_path_input: Option<String>,
    pub settings_selected: usize,
    pub capture_pending: bool,
    pub paired_browsers: PairedBrowsersState,
    pub browser_setup: crate::ui::browser_setup::BrowserSetupState,
    paired_browsers_return: SearchView,
    settings_scrolled_to: Option<usize>,
    /// Short success message for the footer, such as "Moved to trash".
    pub notice: Option<(String, std::time::Instant)>,
    /// Order of the archived and trash lists; the main search keeps relevance order.
    pub list_sort: ListSort,
    /// What the empty search shows, from the settings.
    pub start_list: StartList,
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
            syncing: false,
            view: SearchView::Results,
            ssh_agent_path_input: None,
            settings_selected: 0,
            capture_pending: false,
            paired_browsers: PairedBrowsersState::default(),
            browser_setup: Default::default(),
            paired_browsers_return: SearchView::Results,
            settings_scrolled_to: None,
            notice: None,
            list_sort: ListSort::default(),
            start_list: StartList::None,
            scrolled_to: None,
        }
    }
}

impl SearchState {
    /// Whether the empty search shows a start list (recently used, edited or created).
    pub fn showing_start_list(&self) -> bool {
        self.view == SearchView::Results
            && self.start_list != StartList::None
            && self.query.trim().is_empty()
    }

    pub fn reset_results_for_empty_query(&mut self) {
        if matches!(
            self.view,
            SearchView::PairedBrowsers | SearchView::BrowserSetup
        ) {
            return;
        }
        // A start list loads through a normal search; only drop the results of the query
        // that was just cleared.
        if self.showing_start_list() {
            if !self.last_query.is_empty() {
                self.results.clear();
                self.selected = 0;
            }
            return;
        }
        // The archived and trash lists show everything while the query is empty.
        if self.query.trim().is_empty() && !self.view.is_item_list() {
            self.results.clear();
            self.selected = 0;
            self.error = None;
            self.warning = None;

            self.view = SearchView::Results;
            if self.in_flight {
                self.in_flight = false;
            }
        }
    }

    pub fn needs_search(&self) -> bool {
        if self.view.item_state().is_none() {
            return false;
        }
        let query = self.query.trim();
        if query.is_empty()
            && !self.view.is_item_list()
            && !self.showing_start_list()
            && self.last_query != "\u{0}"
        {
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
        self.settings_scrolled_to = None;
        self.notice = None;
        self.paired_browsers.cancel_confirmation();
        self.scrolled_to = None;
        self.force_refresh();
        self.focus_search = true;
    }

    /// Takes a fresh result list, ordering it by the list sort in the archived and trash views.
    pub fn set_results(&mut self, mut items: Vec<BwItem>) {
        if self.view.is_item_list() {
            self.list_sort.apply(&mut items);
        } else if self.showing_start_list() {
            items = start_list_items(self.start_list, items, &config::load_item_usage());
        }
        self.results = items;
        self.selected = 0;
    }

    fn change_list_sort(&mut self, sort: ListSort) {
        if sort == self.list_sort {
            return;
        }
        self.list_sort = sort;
        let items = std::mem::take(&mut self.results);
        self.set_results(items);
        self.scrolled_to = None;
    }

    pub fn show_notice(&mut self, message: &str) {
        self.notice = Some((message.to_string(), std::time::Instant::now()));
    }

    fn current_notice(&self) -> Option<&str> {
        self.notice
            .as_ref()
            .filter(|(_, at)| at.elapsed() < NOTICE_DURATION)
            .map(|(message, _)| message.as_str())
    }

    /// Switches to the archived or trash list, which starts unfiltered.
    fn open_item_list(&mut self, view: SearchView) {
        self.view = view;
        self.query.clear();
        self.results.clear();
        self.selected = 0;
        self.error = None;
        self.scrolled_to = None;
        self.force_refresh();
        self.focus_search = true;
    }

    pub fn close_item_list(&mut self) {
        self.view = SearchView::Results;
        self.query.clear();
        self.results.clear();
        self.selected = 0;
        self.error = None;
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
                self.settings_scrolled_to = None;
                OpenSelectedAction::None
            }
            Some(DisplayEntry::PairedBrowsersCommand) => {
                self.open_paired_browsers();
                OpenSelectedAction::None
            }
            Some(DisplayEntry::LockCommand) => OpenSelectedAction::LockVault,
            Some(DisplayEntry::ArchivedCommand) => {
                self.open_item_list(SearchView::Archived);
                OpenSelectedAction::None
            }
            Some(DisplayEntry::TrashCommand) => {
                self.open_item_list(SearchView::Trash);
                OpenSelectedAction::None
            }
            Some(DisplayEntry::NewItemCommand) => {
                if self.offline() {
                    OpenSelectedAction::None
                } else {
                    OpenSelectedAction::NewItem
                }
            }
            Some(DisplayEntry::WindowCommand) => OpenSelectedAction::OpenWindow,
            Some(DisplayEntry::VaultItem(idx)) => OpenSelectedAction::OpenResult(idx),
            None => OpenSelectedAction::None,
        }
    }

    pub fn offline(&self) -> bool {
        self.sync_status.as_ref().is_some_and(|s| s.offline)
    }

    pub fn open_paired_browsers(&mut self) {
        if self.view != SearchView::PairedBrowsers {
            self.paired_browsers_return = self.view;
        }
        self.view = SearchView::PairedBrowsers;
        self.paired_browsers.cancel_confirmation();
        self.paired_browsers.loaded = false;
        self.paired_browsers.error = None;
        self.focus_search = false;
    }

    pub fn close_paired_browsers(&mut self) {
        self.paired_browsers.cancel_confirmation();
        self.view = self.paired_browsers_return;
        self.focus_search = true;
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

    /// Command rows shown above the vault items, in display order. The archived and
    /// trash lists only show items.
    fn visible_commands(&self) -> Vec<DisplayEntry> {
        if self.view.is_item_list() {
            return Vec::new();
        }
        [
            (
                settings_command_matches(&self.query),
                DisplayEntry::SettingsCommand,
            ),
            (
                paired_browsers_command_matches(&self.query),
                DisplayEntry::PairedBrowsersCommand,
            ),
            (lock_command_matches(&self.query), DisplayEntry::LockCommand),
            (
                archived_command_matches(&self.query),
                DisplayEntry::ArchivedCommand,
            ),
            (
                trash_command_matches(&self.query),
                DisplayEntry::TrashCommand,
            ),
            (
                new_item_command_matches(&self.query),
                DisplayEntry::NewItemCommand,
            ),
            (
                window_command_matches(&self.query),
                DisplayEntry::WindowCommand,
            ),
        ]
        .into_iter()
        .filter_map(|(visible, entry)| visible.then_some(entry))
        .collect()
    }

    fn display_entry_count(&self) -> usize {
        self.visible_commands().len() + self.results.len()
    }

    fn display_entry(&self, display_idx: usize) -> Option<DisplayEntry> {
        let commands = self.visible_commands();
        if let Some(command) = commands.get(display_idx) {
            return Some(*command);
        }
        let cursor = commands.len();
        let item_idx = display_idx.checked_sub(cursor)?;
        self.results
            .get(item_idx)
            .map(|_| DisplayEntry::VaultItem(item_idx))
    }
}

/// Picks and orders the items of a start list from all active items.
fn start_list_items(list: StartList, mut items: Vec<BwItem>, usage: &[String]) -> Vec<BwItem> {
    let newest_first = |items: &mut Vec<BwItem>, date: fn(&BwItem) -> Option<&String>| {
        items.retain(|item| date(item).is_some());
        items.sort_by(|a, b| date(b).cmp(&date(a)));
        items.truncate(START_LIST_LIMIT);
    };
    match list {
        StartList::None => items.clear(),
        StartList::RecentlyUsed => {
            // Usage ids of items that are gone or archived simply find no match.
            return usage
                .iter()
                .filter_map(|id| items.iter().position(|item| &item.id == id))
                .map(|idx| items[idx].clone())
                .collect();
        }
        StartList::RecentlyEdited => {
            newest_first(&mut items, |item| item.dates.revision_date.as_ref())
        }
        StartList::RecentlyCreated => {
            newest_first(&mut items, |item| item.dates.creation_date.as_ref())
        }
    }
    items
}

pub fn settings_command_matches(query: &str) -> bool {
    let query = query.trim();
    query.chars().count() >= 2 && "settings".starts_with(&query.to_ascii_lowercase())
}

pub fn paired_browsers_command_matches(query: &str) -> bool {
    command_matches(
        query,
        &["browsers", "paired browsers", "deauthorize browsers"],
    )
}

pub fn lock_command_matches(query: &str) -> bool {
    command_matches(query, &["lock"])
}

pub fn archived_command_matches(query: &str) -> bool {
    command_matches(query, &["archived items"])
}

pub fn new_item_command_matches(query: &str) -> bool {
    command_matches(query, &["new item", "create item", "add item"])
}

pub fn window_command_matches(query: &str) -> bool {
    command_matches(
        query,
        &["vault window", "open vault", "window", "browse vault"],
    )
}

pub fn trash_command_matches(query: &str) -> bool {
    command_matches(query, &["recently deleted", "deleted", "trash"])
}

fn command_matches(query: &str, names: &[&str]) -> bool {
    let query = query.trim().to_ascii_lowercase();
    query.chars().count() >= 2 && names.iter().any(|name| name.starts_with(&query))
}

pub fn draw_search(
    root: &mut egui::Ui,
    state: &mut SearchState,
    settings: &AppSettings,
    ssh_agent_status: &SshAgentStatus,
    icons: &mut IconCache,
) -> Option<SearchAction> {
    let ctx = &root.ctx().clone();
    let mut action = None;
    let t = theme();

    if state.view == SearchView::Settings && !state.settings_command_visible() {
        state.close_settings_panel();
    }
    // Keys are consumed before the search field is drawn so it does not also receive them.
    handle_keys(ctx, state, settings, &mut action);

    let status = if let Some(error) = &state.error {
        Some((error.as_str(), t.danger))
    } else if let Some(notice) = state.current_notice() {
        Some((notice, t.success))
    } else {
        state
            .warning
            .as_deref()
            .filter(|_| !state.offline())
            .map(|warning| (warning, t.warning))
    };
    {
        let hints: &[(&str, &str)] = match (settings.show_keyboard_shortcuts, state.view) {
            (false, _) => &[],
            (true, SearchView::Results) => &[
                ("↑↓", "Navigate"),
                ("⏎", "Open"),
                ("Shift+⏎", "Copy password"),
                ("Esc", "Hide"),
            ],
            (true, SearchView::PairedBrowsers) => &[
                ("↑↓", "Navigate"),
                ("⏎", "Revoke"),
                ("Ctrl+R", "Refresh"),
                ("Esc", "Back"),
            ],
            (true, SearchView::BrowserSetup) => {
                &[("↑↓", "Select"), ("Space", "Toggle"), ("Esc", "Back")]
            }
            (true, SearchView::Settings) => {
                &[("↑↓", "Select"), ("Space", "Toggle"), ("Esc", "Back")]
            }
            (true, SearchView::Archived | SearchView::Trash) => &[
                ("↑↓", "Navigate"),
                ("⏎", "Open"),
                ("Tab", "Sort by"),
                ("Ctrl+↑↓", "Order"),
                ("Esc", "Back"),
            ],
        };
        egui::Panel::bottom("footer")
            .frame(widgets::footer_frame())
            .show(root, |ui| {
                if matches!(
                    state.view,
                    SearchView::BrowserSetup | SearchView::PairedBrowsers
                ) {
                    widgets::footer(ui, hints, None);
                    return;
                }
                let sync_label = if state.syncing {
                    "Syncing…"
                } else if state.offline() {
                    "Offline"
                } else if state
                    .sync_status
                    .as_ref()
                    .and_then(|s| s.last_synced_unix)
                    .is_some()
                {
                    "Synced"
                } else {
                    "Sync"
                };
                let rect = widgets::footer(ui, hints, status.or(Some((sync_label, t.text_faint))));
                if status.is_none() {
                    if let Some(rect) = rect {
                        let response = ui.interact(
                            rect,
                            egui::Id::new("footer-sync"),
                            if state.syncing {
                                egui::Sense::hover()
                            } else {
                                egui::Sense::click()
                            },
                        );
                        response.widget_info(|| {
                            egui::WidgetInfo::labeled(
                                egui::WidgetType::Button,
                                !state.syncing,
                                "Sync vault",
                            )
                        });
                        let mut tooltip = state
                            .sync_status
                            .as_ref()
                            .filter(|s| s.offline)
                            .map(|s| s.offline_tooltip())
                            .unwrap_or_else(|| "Sync vault · Ctrl+R".to_string());
                        if let Some(at) =
                            state.sync_status.as_ref().and_then(|s| s.last_synced_unix)
                        {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let minutes = now.saturating_sub(at) / 60;
                            tooltip.push_str(&if minutes == 0 {
                                "\nLast synced less than a minute ago".into()
                            } else {
                                format!("\nLast synced {minutes} min ago")
                            });
                        }
                        if state.offline()
                            && let Some(warning) = &state.warning
                        {
                            tooltip.push_str(&format!("\n{warning}"));
                        }
                        if response.on_hover_text(tooltip).clicked() {
                            action = Some(SearchAction::Sync);
                        }
                    }
                }
            });
    }

    egui::Panel::top("header")
        .frame(widgets::header_frame())
        .show(root, |ui| draw_search_field(ui, state));

    egui::CentralPanel::default()
        .frame(widgets::body_frame())
        .show(root, |ui| {
            if state.view == SearchView::BrowserSetup {
                crate::ui::browser_setup::draw_browser_setup(ui, &mut state.browser_setup);
            } else if state.view == SearchView::PairedBrowsers {
                if let Some(browser_action) = draw_paired_browsers(ui, &mut state.paired_browsers) {
                    action = Some(SearchAction::PairedBrowsers(browser_action));
                }
            } else if state.view == SearchView::Settings {
                if let Some(settings_action) = draw_settings(ui, state, settings, ssh_agent_status)
                {
                    action = Some(settings_action);
                }
            } else if state.showing_start_list() && !state.results.is_empty() {
                ui.label(
                    RichText::new(state.start_list.label())
                        .size(t.small())
                        .color(t.text_muted),
                );
                ui.add_space(2.0);
                if let Some(row_action) = draw_results(ui, state, icons) {
                    action = Some(row_action);
                }
            } else if state.showing_start_list() && state.in_flight {
                widgets::empty_state(ui, "", "Loading…", true);
            } else if state.query.trim().is_empty() && !state.view.is_item_list() {
                let hint = if state.start_list == StartList::RecentlyUsed {
                    "Items you open show up here · type to search"
                } else {
                    "Type to search · commands: browsers, settings, lock, archived, deleted, new, window"
                };
                widgets::empty_state(ui, t.icon("\u{f002}", "🔎"), hint, false);
            } else if state.display_entry_count() == 0 {
                let empty_text = match state.view {
                    _ if !state.query.trim().is_empty() => "No matching items",
                    SearchView::Archived => "No archived items",
                    SearchView::Trash => "Trash is empty",
                    _ => "No matching items",
                };
                if state.in_flight || state.last_query.is_empty() || state.last_query == "\u{0}" {
                    widgets::empty_state(ui, "", "Searching…", true);
                } else {
                    widgets::empty_state(ui, t.icon("\u{f05e}", "∅"), empty_text, false);
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
        SearchView::BrowserSetup => {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                state.view = SearchView::Settings;
                state.focus_search = true;
            }
        }
        SearchView::PairedBrowsers => {
            if !state.paired_browsers.has_confirmation()
                && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
            {
                state.close_paired_browsers();
            }
        }
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
            if (input.consume_key(egui::Modifiers::NONE, egui::Key::Space)
                || input.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
                && (state.settings_selected != SCREEN_CAPTURE_ROW || !state.capture_pending)
            {
                *action = toggle_setting(state.settings_selected, settings);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
                || input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft)
            {
                state.close_settings_panel();
            }
        }
        SearchView::Results | SearchView::Archived | SearchView::Trash => {
            if state.view.is_item_list()
                && (input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
                    || (state.query.is_empty()
                        && input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowLeft)))
            {
                state.close_item_list();
                return;
            }
            if state.view.is_item_list() {
                let sort = state.list_sort;
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Tab) {
                    state.change_list_sort(ListSort {
                        key: sort.key.next(),
                        ..sort
                    });
                }
                if input.consume_key(egui::Modifiers::COMMAND, egui::Key::ArrowUp) {
                    state.change_list_sort(ListSort {
                        descending: false,
                        ..sort
                    });
                }
                if input.consume_key(egui::Modifiers::COMMAND, egui::Key::ArrowDown) {
                    state.change_list_sort(ListSort {
                        descending: true,
                        ..sort
                    });
                }
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                state.move_selection(1);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                state.move_selection(-1);
            }
            // Consume the modified shortcut first: egui's NONE also accepts Shift.
            if input.consume_key(egui::Modifiers::SHIFT, egui::Key::Enter) {
                if !state.in_flight {
                    if let Some(DisplayEntry::VaultItem(idx)) = state.display_entry(state.selected)
                    {
                        *action = Some(SearchAction::QuickCopy(idx));
                    }
                }
                return;
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
                    OpenSelectedAction::NewItem => *action = Some(SearchAction::NewItem),
                    OpenSelectedAction::OpenWindow => *action = Some(SearchAction::OpenWindow),
                    OpenSelectedAction::None => {}
                }
            }
        }
    });
}

fn search_cursor_at_end(ctx: &Context, query: &str) -> bool {
    egui::TextEdit::load_state(ctx, egui::Id::new(SEARCH_INPUT_ID))
        .and_then(|edit| edit.cursor.char_range())
        .is_none_or(|range| range.primary.index.0 >= query.chars().count())
}

fn draw_search_field(ui: &mut Ui, state: &mut SearchState) {
    let t = theme();
    ui.horizontal(|ui| {
        widgets::logo(ui, t.input() + 4.0);
        ui.add_space(6.0);
        if state.view == SearchView::BrowserSetup {
            ui.label(
                RichText::new("Browser setup")
                    .size(t.input())
                    .color(t.text_strong),
            );
            return;
        }
        if state.view == SearchView::PairedBrowsers {
            ui.label(
                RichText::new("Paired browsers")
                    .size(t.input())
                    .color(t.text_strong),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if state.paired_browsers.is_busy() {
                    ui.add(egui::Spinner::new().color(t.text_muted));
                } else {
                    ui.label(
                        RichText::new(state.paired_browsers.records.len().to_string())
                            .color(t.text_faint),
                    );
                }
            });
            return;
        }
        let chip = match state.view {
            SearchView::Archived => Some((t.icon("\u{f187}", "🗄"), "Archived")),
            SearchView::Trash => Some((t.icon("\u{f1f8}", "🗑"), "Recently deleted")),
            _ => None,
        };
        if let Some((icon, label)) = chip {
            egui::Frame::new()
                .fill(t.surface)
                .stroke(egui::Stroke::new(1.0_f32, t.border))
                .corner_radius(t.rounding)
                .inner_margin(egui::Margin::symmetric(8, 4))
                .show(ui, |ui| {
                    ui.label(RichText::new(format!("{icon} {label}")).color(t.accent));
                });
            ui.add_space(6.0);
        }
        // Room on the right for the count, plus the sort control in the item lists.
        let trailing = if state.view.is_item_list() {
            190.0
        } else {
            44.0
        };
        let mut field = egui::TextEdit::singleline(&mut state.query)
            .id(egui::Id::new(SEARCH_INPUT_ID))
            .font(t.font(t.input()))
            .text_color(t.text_strong)
            .hint_text(RichText::new("Search vault").color(t.text_faint))
            .frame(egui::Frame::NONE)
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
            } else if !state.query.trim().is_empty() || state.view.is_item_list() {
                ui.label(RichText::new(state.results.len().to_string()).color(t.text_faint));
            }
            if state.view.is_item_list() {
                draw_sort_control(ui, state);
            }
        });
    });
}

/// "Date archived ↓": clicking the name cycles the sort key, the arrow flips the order.
fn draw_sort_control(ui: &mut Ui, state: &mut SearchState) {
    let t = theme();
    let sort = state.list_sort;
    let arrow = if sort.descending {
        t.icon("\u{f175}", "↓")
    } else {
        t.icon("\u{f176}", "↑")
    };
    let order_hint = if sort.descending {
        "Newest / Z first (Ctrl+↑ for ascending)"
    } else {
        "Oldest / A first (Ctrl+↓ for descending)"
    };
    if ui
        .add(egui::Button::new(RichText::new(arrow).color(t.accent)).frame(false))
        .on_hover_text(order_hint)
        .clicked()
    {
        state.change_list_sort(ListSort {
            descending: !sort.descending,
            ..sort
        });
    }
    if ui
        .add(
            egui::Button::new(RichText::new(sort.key.label(state.view)).color(t.text_muted))
                .frame(false),
        )
        .on_hover_text("Sort by (Tab)")
        .clicked()
    {
        state.change_list_sort(ListSort {
            key: sort.key.next(),
            ..sort
        });
    }
}

fn draw_results(
    ui: &mut Ui,
    state: &mut SearchState,
    icons: &mut IconCache,
) -> Option<SearchAction> {
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
                    DisplayEntry::PairedBrowsersCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f0ac}", "◎"),
                        None,
                        "Paired browsers",
                        Some("View paired extensions and revoke access"),
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
                    DisplayEntry::ArchivedCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f187}", "🗄"),
                        None,
                        "Archived items",
                        Some("Items kept out of search and autofill"),
                        Some("command"),
                        selected,
                    ),
                    DisplayEntry::NewItemCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f067}", "+"),
                        None,
                        "New item",
                        Some(if state.offline() {
                            "Offline: editing needs a connection"
                        } else {
                            "Add a login or secure note to the vault"
                        }),
                        Some("command"),
                        selected,
                    ),
                    DisplayEntry::WindowCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f2d0}", "🗔"),
                        None,
                        "Open vault window",
                        Some("Browse folders, favorites and the action center"),
                        Some("command"),
                        selected,
                    ),
                    DisplayEntry::TrashCommand => widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f1f8}", "🗑"),
                        None,
                        "Recently deleted",
                        Some("Restore or permanently delete trashed items"),
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
                if matches!(entry, DisplayEntry::NewItemCommand) && state.offline() {
                    ui.painter()
                        .rect_filled(rect, 0.0, t.bg.gamma_multiply(0.65));
                }
                let label = match entry {
                    DisplayEntry::VaultItem(idx) => {
                        let item = &state.results[idx];
                        format!("{} {}", item.name, item.username.as_deref().unwrap_or(""))
                    }
                    DisplayEntry::SettingsCommand => "Settings".into(),
                    DisplayEntry::PairedBrowsersCommand => "Paired browsers".into(),
                    DisplayEntry::LockCommand => "Lock vault".into(),
                    DisplayEntry::ArchivedCommand => "Archived items".into(),
                    DisplayEntry::TrashCommand => "Recently deleted".into(),
                    DisplayEntry::NewItemCommand => "New item".into(),
                    DisplayEntry::WindowCommand => "Open vault window".into(),
                };
                response.widget_info(|| {
                    egui::WidgetInfo::selected(
                        egui::WidgetType::SelectableLabel,
                        ui.is_enabled(),
                        selected,
                        &label,
                    )
                });
                if scroll_to == Some(i) {
                    ui.scroll_to_rect(rect, None);
                }
                if response.clicked() {
                    state.selected = i;
                    match entry {
                        DisplayEntry::SettingsCommand
                        | DisplayEntry::PairedBrowsersCommand
                        | DisplayEntry::ArchivedCommand
                        | DisplayEntry::TrashCommand => {
                            state.open_selected_entry();
                        }
                        DisplayEntry::LockCommand => action = Some(SearchAction::LockVault),
                        DisplayEntry::NewItemCommand => {
                            if !state.offline() {
                                action = Some(SearchAction::NewItem);
                            }
                        }
                        DisplayEntry::WindowCommand => action = Some(SearchAction::OpenWindow),
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
        START_LIST_ROW => SearchAction::SetStartList(settings.start_list.next()),
        4 => SearchAction::SetShowWebsiteIcons(!settings.show_website_icons),
        SCREEN_CAPTURE_ROW if crate::screen_capture::available() => {
            SearchAction::SetObscureScreenCapture(!settings.obscure_screen_capture)
        }
        6 => SearchAction::SetLockOnSystemLock(!settings.lock_on_system_lock),
        IDLE_TIMEOUT_ROW => {
            SearchAction::SetLockAfterIdleTimeout(!settings.lock_after_idle_timeout)
        }
        8 => SearchAction::SetSshAgentEnabled(!settings.ssh_agent_enabled),
        9 => SearchAction::SetKeepOfflineCopy(!settings.keep_offline_copy),
        10 => SearchAction::SetBrowserIntegrationEnabled(!settings.browser_integration_enabled),
        DEFAULT_URI_MATCH_ROW => {
            SearchAction::SetDefaultUriMatch(match settings.default_uri_match {
                crate::uri_match::UriMatchType::Host => crate::uri_match::UriMatchType::Domain,
                crate::uri_match::UriMatchType::Domain => crate::uri_match::UriMatchType::Exact,
                crate::uri_match::UriMatchType::Exact => crate::uri_match::UriMatchType::Never,
                _ => crate::uri_match::UriMatchType::Host,
            })
        }
        PAIRED_BROWSERS_ROW => SearchAction::OpenPairedBrowsers,
        BROWSER_SETUP_ROW => SearchAction::OpenBrowserSetup,
        PASSKEY_VERIFICATION_ROW => {
            SearchAction::SetPasskeyVerification(settings.passkey_verification.next())
        }
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
    // The start list row (a choice, not a toggle) is drawn separately at START_LIST_ROW.
    let rows: [(bool, &str, &str); SETTINGS_ROWS - 5] = [
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
            settings.obscure_screen_capture && crate::screen_capture::available(),
            "Obscure in screen captures",
            if state.capture_pending {
                "Applying screen capture preference…"
            } else if crate::screen_capture::available() {
                "Hide this window in screenshots and screen sharing"
            } else {
                "Requires Hyprland; capture protection is unavailable here"
            },
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
        (
            settings.keep_offline_copy,
            "Keep offline copy",
            "Keep an encrypted copy for read-only access without a connection",
        ),
        (
            settings.browser_integration_enabled,
            "Enable browser integration",
            "Allow paired browser extensions to fill logins from this vault",
        ),
    ];

    egui::ScrollArea::vertical()
        .id_salt("settings-scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for (row_idx, (on, title, description)) in rows.iter().enumerate() {
                let idx = if row_idx >= START_LIST_ROW {
                    row_idx + 1
                } else {
                    row_idx
                };
                if idx == START_LIST_ROW + 1 {
                    let response = widgets::choice_row(
                        ui,
                        state.settings_selected == START_LIST_ROW,
                        "Start with",
                        "What the empty search shows",
                        settings.start_list.label(),
                    );
                    if state.settings_selected == START_LIST_ROW
                        && state.settings_scrolled_to != Some(START_LIST_ROW)
                    {
                        response.scroll_to_me(None);
                        state.settings_scrolled_to = Some(START_LIST_ROW);
                    }
                    if response.clicked() {
                        state.settings_selected = START_LIST_ROW;
                        action = toggle_setting(START_LIST_ROW, settings);
                    }
                }
                let enabled = idx != SCREEN_CAPTURE_ROW
                    || (crate::screen_capture::available() && !state.capture_pending);
                let response = ui
                    .add_enabled_ui(enabled, |ui| {
                        widgets::toggle_row(
                            ui,
                            state.settings_selected == idx,
                            *on,
                            title,
                            description,
                        )
                    })
                    .inner;
                if state.settings_selected == idx && state.settings_scrolled_to != Some(idx) {
                    response.scroll_to_me(None);
                    state.settings_scrolled_to = Some(idx);
                }
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

            let match_label = match settings.default_uri_match {
                crate::uri_match::UriMatchType::Host => "Exact host and port",
                crate::uri_match::UriMatchType::Domain => "Base domain",
                crate::uri_match::UriMatchType::Exact => "Exact URL",
                crate::uri_match::UriMatchType::Never => "Never",
                _ => "Custom",
            };
            let response = widgets::choice_row(
                ui,
                state.settings_selected == DEFAULT_URI_MATCH_ROW,
                "Default URI matching",
                "Applies only when an item has no explicit match rule",
                match_label,
            );
            if state.settings_selected == DEFAULT_URI_MATCH_ROW
                && state.settings_scrolled_to != Some(DEFAULT_URI_MATCH_ROW)
            {
                response.scroll_to_me(None);
                state.settings_scrolled_to = Some(DEFAULT_URI_MATCH_ROW);
            }
            if response.clicked() {
                state.settings_selected = DEFAULT_URI_MATCH_ROW;
                action = toggle_setting(DEFAULT_URI_MATCH_ROW, settings);
            }
            let response = widgets::choice_row(
                ui,
                state.settings_selected == PAIRED_BROWSERS_ROW,
                "Paired browsers",
                "View paired extensions and revoke access",
                "Manage",
            );
            if state.settings_selected == PAIRED_BROWSERS_ROW
                && state.settings_scrolled_to != Some(PAIRED_BROWSERS_ROW)
            {
                response.scroll_to_me(None);
                state.settings_scrolled_to = Some(PAIRED_BROWSERS_ROW);
            }
            if response.clicked() {
                state.settings_selected = PAIRED_BROWSERS_ROW;
                action = Some(SearchAction::OpenPairedBrowsers);
            }

            let response = widgets::choice_row(
                ui,
                state.settings_selected == PASSKEY_VERIFICATION_ROW,
                "Passkey verification",
                if settings.passkey_verification == PasskeyVerification::VaultUnlock {
                    "Reuse vault unlock; protected items still require a password"
                } else {
                    "Sites and protected items can still require verification"
                },
                settings.passkey_verification.label(),
            );
            if state.settings_selected == PASSKEY_VERIFICATION_ROW
                && state.settings_scrolled_to != Some(PASSKEY_VERIFICATION_ROW)
            {
                response.scroll_to_me(None);
                state.settings_scrolled_to = Some(PASSKEY_VERIFICATION_ROW);
            }
            if response.clicked() {
                state.settings_selected = PASSKEY_VERIFICATION_ROW;
                action = toggle_setting(PASSKEY_VERIFICATION_ROW, settings);
            }

            let response = widgets::choice_row(
                ui,
                state.settings_selected == BROWSER_SETUP_ROW,
                "Browser setup",
                "Choose installed or custom browsers for the extension",
                "Manage",
            );
            if state.settings_selected == BROWSER_SETUP_ROW
                && state.settings_scrolled_to != Some(BROWSER_SETUP_ROW)
            {
                response.scroll_to_me(None);
                state.settings_scrolled_to = Some(BROWSER_SETUP_ROW);
            }
            if response.clicked() {
                state.settings_selected = BROWSER_SETUP_ROW;
                action = Some(SearchAction::OpenBrowserSetup);
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
    Sync,
    QuickCopy(usize),
    OpenResult(usize),
    OpenWindow,
    SetKeepOfflineCopy(bool),
    SetKeyboardShortcuts(bool),
    SetCloseAfterCopy(bool),
    SetRestoreRecentItem(bool),
    SetShowWebsiteIcons(bool),
    SetObscureScreenCapture(bool),
    SetLockOnSystemLock(bool),
    SetLockAfterIdleTimeout(bool),
    SetIdleLockTimeoutMinutes(u64),
    SetSshAgentEnabled(bool),
    SetSshAgentSocketPath(String),
    SetStartList(StartList),
    SetBrowserIntegrationEnabled(bool),
    SetDefaultUriMatch(crate::uri_match::UriMatchType),
    SetPasskeyVerification(PasskeyVerification),
    OpenPairedBrowsers,
    OpenBrowserSetup,
    PairedBrowsers(PairedBrowsersAction),
    LockVault,
    NewItem,
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
            folder_id: None,
            favorite: false,
            item_type: "login".to_string(),
            icon_host: None,
            state: Default::default(),
            dates: Default::default(),
        }
    }

    #[test]
    fn empty_search_keeps_offline_status_and_refreshes_when_requested() {
        let mut state = SearchState {
            sync_status: Some(SyncStatus {
                offline: true,
                cache_synced_unix: Some(123),
                ..Default::default()
            }),
            ..Default::default()
        };
        state.reset_results_for_empty_query();
        assert!(state.offline());
        state.force_refresh();
        assert!(state.needs_search());
        state.mark_queried();
        assert!(!state.needs_search());
        state.query = "new".into();
        assert!(matches!(
            state.open_selected_entry(),
            OpenSelectedAction::None
        ));
    }

    #[test]
    fn settings_keyboard_scrolls_both_directions_and_wraps() {
        let ctx = Context::default();
        let mut state = SearchState {
            view: SearchView::Settings,
            ..Default::default()
        };
        let mut time = 0.0;
        let mut frame = |key: Option<egui::Key>| {
            let mut offset = 0.0;
            for tick in 0..20 {
                time += 0.05;
                let mut input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(680., 280.),
                    )),
                    time: Some(time),
                    ..Default::default()
                };
                if tick < 2
                    && let Some(key) = key
                {
                    input.events.push(egui::Event::Key {
                        key,
                        physical_key: None,
                        pressed: tick == 0,
                        repeat: false,
                        modifiers: egui::Modifiers::NONE,
                    });
                }
                ctx.run_ui(input, |root| {
                    handle_keys(root.ctx(), &mut state, &AppSettings::default(), &mut None);
                    egui::CentralPanel::default().show(root, |ui| {
                        let id = ui.make_persistent_id(egui::IdSalt::new("settings-scroll"));
                        draw_settings(
                            ui,
                            &mut state,
                            &AppSettings::default(),
                            &crate::ssh_agent::disabled_status(),
                        );
                        offset = egui::scroll_area::State::load(&ctx, id).unwrap().offset.y;
                    });
                })
                .textures_delta
                .clear();
            }
            (state.settings_selected, offset)
        };
        assert_eq!(frame(None), (0, 0.0));
        let (selected, bottom) = frame(Some(egui::Key::ArrowUp));
        assert_eq!(selected, SETTINGS_ROWS - 1);
        assert!(
            bottom > 200.,
            "last setting must scroll into view: {bottom}"
        );
        let (selected, top) = frame(Some(egui::Key::ArrowDown));
        assert_eq!(selected, 0);
        assert!(
            top < 1.,
            "wrapping to first setting must scroll back: {top}"
        );
        for _ in 0..SETTINGS_ROWS - 1 {
            frame(Some(egui::Key::ArrowDown));
        }
        let (_, offset) = frame(Some(egui::Key::ArrowUp));
        assert!(offset > 0.);
        for _ in 0..SETTINGS_ROWS - 2 {
            frame(Some(egui::Key::ArrowUp));
        }
        assert!(frame(None).1 < 1.);
    }

    #[test]
    fn browser_command_opens_management_without_searching_the_vault() {
        for query in ["br", "browsers", "paired", "deauth"] {
            assert!(paired_browsers_command_matches(query));
        }
        assert!(!paired_browsers_command_matches("b"));
        let mut state = SearchState {
            query: "browsers".into(),
            ..Default::default()
        };
        assert_eq!(state.open_selected_entry(), OpenSelectedAction::None);
        assert_eq!(state.view, SearchView::PairedBrowsers);
        assert!(!state.needs_search());
        state.query.clear();
        state.reset_results_for_empty_query();
        assert_eq!(state.view, SearchView::PairedBrowsers);
        state.close_paired_browsers();
        assert_eq!(state.view, SearchView::Results);
    }

    #[test]
    fn browser_management_returns_to_settings_and_remains_available_when_disabled() {
        let settings = AppSettings::default();
        assert!(!settings.browser_integration_enabled);
        assert!(matches!(
            toggle_setting(PAIRED_BROWSERS_ROW, &settings),
            Some(SearchAction::OpenPairedBrowsers)
        ));
        let mut state = SearchState {
            query: "settings".into(),
            view: SearchView::Settings,
            ..Default::default()
        };
        state.open_paired_browsers();
        state.close_paired_browsers();
        assert_eq!(state.view, SearchView::Settings);
        assert_eq!(state.query, "settings");
    }

    #[test]
    fn browser_setup_routes_panel_keys_and_returns_to_settings_without_searching() {
        let ctx = Context::default();
        let mut state = SearchState {
            query: "settings".into(),
            view: SearchView::BrowserSetup,
            settings_selected: BROWSER_SETUP_ROW,
            focus_search: false,
            ..Default::default()
        };
        assert!(!state.needs_search());
        let mut action = None;
        for key in [egui::Key::ArrowDown, egui::Key::Enter, egui::Key::Escape] {
            let input = egui::RawInput {
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            };
            ctx.run_ui(input, |ui| {
                handle_keys(ui.ctx(), &mut state, &AppSettings::default(), &mut action);
                if key == egui::Key::ArrowDown {
                    assert!(
                        ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, key)),
                        "Panel navigation must not change Settings selection"
                    );
                }
            })
            .textures_delta
            .clear();
            assert!(
                action.is_none(),
                "Browser setup keys must not trigger vault item actions"
            );
        }
        assert_eq!(state.view, SearchView::Settings);
        assert_eq!(state.settings_selected, BROWSER_SETUP_ROW);
        assert_eq!(state.query, "settings");
        assert!(state.focus_search);
        assert!(!state.needs_search());
    }

    #[test]
    fn passkey_verification_setting_cycles_after_existing_browser_rows() {
        let mut settings = AppSettings::default();
        assert_eq!(PASSKEY_VERIFICATION_ROW, PAIRED_BROWSERS_ROW + 1);
        assert_eq!(BROWSER_SETUP_ROW, SETTINGS_ROWS - 1);
        assert!(matches!(
            toggle_setting(BROWSER_SETUP_ROW, &settings),
            Some(SearchAction::OpenBrowserSetup)
        ));
        assert!(matches!(
            toggle_setting(PASSKEY_VERIFICATION_ROW, &settings),
            Some(SearchAction::SetPasskeyVerification(
                PasskeyVerification::WhenRequired
            ))
        ));
        settings.passkey_verification = PasskeyVerification::WhenRequired;
        assert!(matches!(
            toggle_setting(PASSKEY_VERIFICATION_ROW, &settings),
            Some(SearchAction::SetPasskeyVerification(
                PasskeyVerification::VaultUnlock
            ))
        ));
        settings.passkey_verification = PasskeyVerification::VaultUnlock;
        assert!(matches!(
            toggle_setting(PASSKEY_VERIFICATION_ROW, &settings),
            Some(SearchAction::SetPasskeyVerification(
                PasskeyVerification::Always
            ))
        ));
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

    #[test]
    fn window_command_opens_the_vault_window() {
        assert!(window_command_matches("win"));
        assert!(window_command_matches("vault w"));
        assert!(!window_command_matches("w"));
        let mut state = SearchState {
            query: "window".into(),
            ..SearchState::default()
        };

        assert_eq!(state.open_selected_entry(), OpenSelectedAction::OpenWindow);
    }

    #[test]
    fn new_item_command_opens_the_create_form() {
        assert!(new_item_command_matches("new"));
        assert!(new_item_command_matches("add"));
        assert!(!new_item_command_matches("n"));
        let mut state = SearchState {
            query: "new".into(),
            ..SearchState::default()
        };

        assert_eq!(state.open_selected_entry(), OpenSelectedAction::NewItem);
    }

    fn dated(id: &str, name: &str, changed: &str, revised: &str) -> BwItem {
        let mut item = item(id);
        item.name = name.into();
        item.dates.state_changed_at = Some(changed.into());
        item.dates.revision_date = Some(revised.into());
        item
    }

    fn names(state: &SearchState) -> Vec<&str> {
        state
            .results
            .iter()
            .map(|item| item.name.as_str())
            .collect()
    }

    #[test]
    fn item_lists_sort_newest_first_and_cycle_sort_keys() {
        let mut state = SearchState {
            view: SearchView::Archived,
            ..SearchState::default()
        };
        state.set_results(vec![
            dated("1", "Bravo", "2026-01-01", "2026-05-01"),
            dated("2", "alpha", "2026-03-01", "2026-02-01"),
            dated("3", "Charlie", "2026-02-01", "2026-04-01"),
        ]);
        assert_eq!(names(&state), ["alpha", "Charlie", "Bravo"]);

        state.change_list_sort(ListSort {
            descending: false,
            ..state.list_sort
        });
        assert_eq!(names(&state), ["Bravo", "Charlie", "alpha"]);

        state.change_list_sort(ListSort {
            key: state.list_sort.key.next(),
            ..state.list_sort
        });
        assert_eq!(state.list_sort.key, ListSortKey::Name);
        assert_eq!(names(&state), ["alpha", "Bravo", "Charlie"]);

        state.change_list_sort(ListSort {
            key: state.list_sort.key.next(),
            ..state.list_sort
        });
        assert_eq!(state.list_sort.key, ListSortKey::Modified);
        assert_eq!(names(&state), ["alpha", "Charlie", "Bravo"]);
    }

    fn with_dates(id: &str, revised: Option<&str>, created: Option<&str>) -> BwItem {
        let mut item = item(id);
        item.dates.revision_date = revised.map(Into::into);
        item.dates.creation_date = created.map(Into::into);
        item
    }

    #[test]
    fn start_lists_pick_recent_items() {
        let items = vec![
            with_dates("a", Some("2026-01-01"), Some("2020-01-01")),
            with_dates("b", Some("2026-03-01"), None),
            with_dates("c", Some("2026-02-01"), Some("2024-01-01")),
        ];
        let ids = |items: Vec<BwItem>| items.into_iter().map(|item| item.id).collect::<Vec<_>>();
        let usage = ["c".to_string(), "gone".to_string(), "a".to_string()];

        assert_eq!(
            ids(start_list_items(
                StartList::RecentlyUsed,
                items.clone(),
                &usage
            )),
            ["c", "a"]
        );
        assert_eq!(
            ids(start_list_items(
                StartList::RecentlyEdited,
                items.clone(),
                &[]
            )),
            ["b", "c", "a"]
        );
        assert_eq!(
            ids(start_list_items(
                StartList::RecentlyCreated,
                items.clone(),
                &[]
            )),
            ["c", "a"]
        );
        assert!(start_list_items(StartList::None, items, &[]).is_empty());
    }

    #[test]
    fn start_list_loads_on_empty_query_and_survives_reset() {
        let mut state = SearchState {
            start_list: StartList::RecentlyEdited,
            ..SearchState::default()
        };
        state.force_refresh();
        assert!(
            state.needs_search(),
            "the empty search loads the start list"
        );
        state.mark_queried();
        state.results = vec![item("1")];

        state.reset_results_for_empty_query();

        assert_eq!(state.results.len(), 1);
        state.start_list = StartList::None;
        state.reset_results_for_empty_query();
        assert!(state.results.is_empty());
    }

    #[test]
    fn main_search_keeps_relevance_order() {
        let mut state = SearchState::default();
        state.set_results(vec![
            dated("1", "Zulu", "2026-01-01", "2026-01-01"),
            dated("2", "Alpha", "2026-03-01", "2026-03-01"),
        ]);
        assert_eq!(names(&state), ["Zulu", "Alpha"]);
    }

    #[test]
    fn archived_and_trash_commands_match_their_names() {
        assert!(archived_command_matches("ar"));
        assert!(archived_command_matches("Archived"));
        assert!(!archived_command_matches("a"));
        assert!(trash_command_matches("tr"));
        assert!(trash_command_matches("dele"));
        assert!(trash_command_matches("recently"));
        assert!(!trash_command_matches("github"));
    }

    #[test]
    fn opening_trash_command_switches_to_unfiltered_trash_list() {
        let mut state = SearchState {
            query: "trash".into(),
            results: vec![item("1")],
            ..SearchState::default()
        };
        assert_eq!(state.display_entry(0), Some(DisplayEntry::TrashCommand));

        assert_eq!(state.open_selected_entry(), OpenSelectedAction::None);

        assert_eq!(state.view, SearchView::Trash);
        assert!(state.query.is_empty());
        assert!(state.results.is_empty());
        assert!(
            state.needs_search(),
            "the list loads even with an empty query"
        );
    }

    #[test]
    fn item_lists_show_only_items_and_keep_results_for_empty_query() {
        let mut state = SearchState {
            view: SearchView::Archived,
            query: "lock".into(),
            results: vec![item("1")],
            ..SearchState::default()
        };
        assert_eq!(state.display_entry(0), Some(DisplayEntry::VaultItem(0)));

        state.query.clear();
        state.reset_results_for_empty_query();
        assert_eq!(state.view, SearchView::Archived);
        assert_eq!(state.results.len(), 1);

        state.close_item_list();
        assert_eq!(state.view, SearchView::Results);
        assert!(state.results.is_empty());
    }
    #[test]
    fn search_results_expose_names_to_assistive_technology() {
        let ctx = Context::default();
        ctx.enable_accesskit();
        let mut state = SearchState::default();
        state.query = "Audit".into();
        let mut fixture = item("audit");
        fixture.name = "Audit example account".into();
        state.set_results(vec![fixture]);
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(680., 460.),
            )),
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ctx| {
            draw_search(
                ctx,
                &mut state,
                &AppSettings::default(),
                &crate::ssh_agent::disabled_status(),
                &mut IconCache::new(false),
            );
        });
        out.textures_delta.clear();
        let tree = out.platform_output.accesskit_update.unwrap();
        assert!(tree.nodes.iter().any(|(_, node)| {
            node.label()
                .is_some_and(|label| label.contains("Audit example account"))
        }));
    }

    #[test]
    fn shift_enter_copies_only_a_settled_vault_result() {
        let ctx = Context::default();
        let mut state = SearchState::default();
        state.query = "Audit".into();
        state.set_results(vec![item("audit")]);
        let mut action = None;
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::SHIFT,
            }],
            ..Default::default()
        };
        ctx.run_ui(input.clone(), |ctx| {
            handle_keys(ctx.ctx(), &mut state, &AppSettings::default(), &mut action)
        })
        .textures_delta
        .clear();
        assert!(matches!(action, Some(SearchAction::QuickCopy(0))));
        state.in_flight = true;
        action = None;
        ctx.run_ui(input, |ctx| {
            handle_keys(ctx.ctx(), &mut state, &AppSettings::default(), &mut action)
        })
        .textures_delta
        .clear();
        assert!(action.is_none());
    }
}
