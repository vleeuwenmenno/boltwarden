//! The vault window: a full, resizable browser next to the quick access popup. A sidebar
//! with favorites, the folder tree and the action center; the item list; and the item
//! view with editing. The daemon starts it as its own process (`boltwarden window`)
//! and it uses the same vault RPC as the popup.

use crate::app::PopupCommand;
use crate::backend::{AppBackend, BackendError};
use crate::config::{self, AppSettings};
use crate::icons::IconCache;
use crate::model::{
    BwItem, BwItemDetail, Folder, HealthReport, ItemAction, ItemDraft, ItemState, SyncStatus,
    TotpCode,
};
use crate::ui::auth::{AuthAction, AuthState, draw_auth};
use crate::ui::edit::{EditAction, EditState, draw_edit};
use crate::ui::summary::{SummaryAction, SummaryState, draw_summary};
use crate::ui::theme::theme;
use crate::ui::two_factor::{TwoFactorAction, TwoFactorState, draw_two_factor};
use crate::ui::vault::{
    self, DropTarget, FolderNode, ListOrder, Section, SidebarAction, SidebarCounts,
};
use crate::ui::widgets;
use eframe::egui;
use egui::{Context, RichText};
use std::collections::{HashMap, HashSet};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const WINDOW_SIZE: egui::Vec2 = egui::vec2(1180.0, 760.0);
const MIN_WINDOW_SIZE: egui::Vec2 = egui::vec2(860.0, 540.0);
/// Verified protected items are hidden again slightly before the daemon's grant expires.
const REPROMPT_TTL: Duration = Duration::from_secs(55);
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const SEARCH_DEBOUNCE: Duration = Duration::from_millis(150);
const NOTICE_DURATION: Duration = Duration::from_secs(3);
const SEARCH_INPUT_ID: &str = "vault-window-search";

pub fn options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(WINDOW_SIZE)
            .with_min_inner_size(MIN_WINDOW_SIZE)
            .with_title(crate::logo::APP_NAME)
            // Its own app id, so window rules for the popup (floating, centered, always
            // on top) don't apply. Demo mode escapes no_screen_share rules as in the popup.
            .with_app_id(if crate::demo::enabled() {
                "boltwarden-window-demo"
            } else {
                "boltwarden-window"
            })
            .with_active(true),
        ..Default::default()
    }
}

/// A folder being created, renamed or deleted, with the request's progress.
struct FolderEdit {
    kind: FolderEditKind,
    busy: bool,
    error: Option<String>,
}

enum FolderEditKind {
    Create {
        parent: Option<String>,
        name: String,
    },
    /// `name` starts as the full path, so a folder can be moved by renaming it.
    Rename {
        path: String,
        name: String,
    },
    Delete {
        path: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    Auth,
    TwoFactor,
    Vault,
}

enum Reply {
    Login(Result<(), BackendError>),
    TwoFactor(Result<(), BackendError>),
    Synced(Result<SyncStatus, BackendError>),
    /// The unfiltered active items, for the sidebar counts.
    AllItems(Result<Vec<BwItem>, BackendError>),
    Search {
        query: String,
        state: ItemState,
        result: Result<Vec<BwItem>, BackendError>,
        status: SyncStatus,
        warning: Option<String>,
        icons_url: Option<String>,
    },
    Folders(Result<Vec<Folder>, BackendError>),
    Health(Result<HealthReport, BackendError>),
    Detail {
        id: String,
        result: Result<BwItemDetail, BackendError>,
    },
    Totp {
        id: String,
        result: Result<TotpCode, BackendError>,
    },
    ItemAction {
        id: String,
        action: ItemAction,
        result: Result<(), BackendError>,
    },
    EditDraft {
        id: String,
        result: Result<ItemDraft, BackendError>,
    },
    Saved {
        id: String,
        result: Result<BwItemDetail, BackendError>,
    },
    Created(Result<BwItemDetail, BackendError>),
    /// A folder was created, renamed or deleted; `next` is the section to show then.
    FolderSaved {
        next: Option<Section>,
        result: Result<(), BackendError>,
    },
    /// An item was dropped on a folder or on Favorites.
    Moved {
        id: String,
        notice: String,
        result: Result<(), BackendError>,
    },
}

pub struct WindowApp {
    backend: AppBackend,
    commands: mpsc::Receiver<PopupCommand>,
    tx: mpsc::Sender<Reply>,
    rx: mpsc::Receiver<Reply>,
    settings: AppSettings,
    icons: IconCache,
    screen: Screen,
    auth_state: AuthState,
    two_factor_state: TwoFactorState,
    security_warning: Option<String>,

    section: Section,
    order: ListOrder,
    query: String,
    query_changed_at: Instant,
    /// The query and item state the current `results` answer.
    searched: Option<(String, ItemState)>,
    search_in_flight: bool,
    results: Vec<BwItem>,
    all_items: Vec<BwItem>,
    folders: Vec<Folder>,
    folder_tree: Vec<FolderNode>,
    folder_paths: HashMap<String, String>,
    collapsed: HashSet<String>,
    health: Option<HealthReport>,
    health_stale: bool,
    health_in_flight: bool,
    health_error: Option<String>,

    selected: Option<String>,
    scroll_to_selected: bool,
    summary_state: SummaryState,
    edit_state: Option<EditState>,
    reprompt_id: Option<String>,
    reprompt_password: String,
    reprompt_at: Option<Instant>,

    sync_in_flight: bool,
    last_sync_attempt: Instant,
    sync_status: Option<SyncStatus>,
    notice: Option<(String, Instant)>,
    error: Option<String>,
    warning: Option<String>,
    confirm_close: bool,
    focus_search: bool,
    folder_edit: Option<FolderEdit>,
}

impl WindowApp {
    pub fn new(backend: AppBackend, commands: mpsc::Receiver<PopupCommand>) -> Self {
        let mut settings = config::load_settings();
        if crate::demo::enabled() {
            settings.obscure_screen_capture = false;
        }
        if crate::screen_capture::available() && settings.obscure_screen_capture {
            // Same protection as the popup; a failure only shows as a warning there.
            std::thread::spawn(|| {
                let _ = crate::screen_capture::apply(true);
            });
        }
        Self::with_settings(backend, commands, settings)
    }

    fn with_settings(
        backend: AppBackend,
        commands: mpsc::Receiver<PopupCommand>,
        settings: AppSettings,
    ) -> Self {
        backend.revoke_item_grants();
        let (tx, rx) = mpsc::channel();
        let unlocked = backend.has_session();
        let mut app = Self {
            security_warning: backend.security_warning(),
            backend,
            commands,
            tx,
            rx,
            icons: IconCache::new(settings.show_website_icons),
            settings,
            screen: if unlocked {
                Screen::Vault
            } else {
                Screen::Auth
            },
            auth_state: AuthState::default(),
            two_factor_state: TwoFactorState::default(),
            section: Section::All,
            order: ListOrder::Name,
            query: String::new(),
            query_changed_at: Instant::now(),
            searched: None,
            search_in_flight: false,
            results: Vec::new(),
            all_items: Vec::new(),
            folders: Vec::new(),
            folder_tree: Vec::new(),
            folder_paths: HashMap::new(),
            collapsed: HashSet::new(),
            health: None,
            health_stale: true,
            health_in_flight: false,
            health_error: None,
            selected: None,
            scroll_to_selected: false,
            summary_state: SummaryState::default(),
            edit_state: None,
            reprompt_id: None,
            reprompt_password: String::new(),
            reprompt_at: None,
            sync_in_flight: false,
            last_sync_attempt: Instant::now(),
            sync_status: None,
            notice: None,
            error: None,
            warning: None,
            confirm_close: false,
            focus_search: true,
            folder_edit: None,
        };
        if crate::demo::starts_on_action_center() {
            app.section = Section::ActionCenter;
        }
        if unlocked {
            app.reload();
        }
        app
    }

    /// Fetches everything the window shows again, after unlocking, a sync or a change.
    fn reload(&mut self) {
        self.searched = None;
        self.health_stale = true;
        self.spawn(|backend| Reply::Folders(backend.folders()));
        self.spawn(|backend| {
            Reply::AllItems(
                backend
                    .list_items(ItemState::Active, "")
                    .map(|result| result.items),
            )
        });
        self.spawn_health();
    }

    fn spawn(&self, work: impl FnOnce(&AppBackend) -> Reply + Send + 'static) {
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(work(&backend));
        });
    }

    fn spawn_health(&mut self) {
        if self.health_in_flight {
            return;
        }
        self.health_in_flight = true;
        self.health_stale = false;
        self.spawn(|backend| Reply::Health(backend.health_report()));
    }

    fn spawn_search(&mut self) {
        let query = self.query.trim().to_string();
        let state = self.section.item_state();
        self.search_in_flight = true;
        self.searched = Some((query.clone(), state));
        self.spawn(move |backend| match backend.list_items(state, &query) {
            Ok(result) => Reply::Search {
                query,
                state,
                result: Ok(result.items),
                status: result.status,
                warning: result.warning,
                icons_url: result.icons_url,
            },
            Err(error) => Reply::Search {
                query,
                state,
                result: Err(error),
                status: SyncStatus::default(),
                warning: None,
                icons_url: None,
            },
        });
    }

    fn spawn_sync(&mut self) {
        if self.sync_in_flight {
            return;
        }
        self.sync_in_flight = true;
        self.last_sync_attempt = Instant::now();
        self.spawn(|backend| Reply::Synced(backend.sync()));
    }

    fn spawn_detail(&self, id: String) {
        self.spawn(move |backend| {
            let result = backend.get_item(&id);
            Reply::Detail { id, result }
        });
    }

    fn spawn_authorize(&mut self, id: String) {
        let mut password = std::mem::take(&mut self.reprompt_password);
        self.summary_state.in_flight = true;
        self.summary_state.error = None;
        self.spawn(move |backend| {
            let result = backend.authorize_item(&id, &password);
            password.zeroize();
            Reply::Detail { id, result }
        });
    }

    fn show_notice(&mut self, message: &str) {
        self.notice = Some((message.to_string(), Instant::now()));
    }

    /// Items of the current section and search, in display order.
    fn visible_items(&self) -> Vec<&BwItem> {
        visible_items(
            &self.results,
            &self.section,
            &self.folder_paths,
            self.health.as_ref(),
            &self.query,
            self.order,
        )
    }

    fn reset_locked(&mut self) {
        let (tx, rx) = mpsc::channel();
        self.tx = tx;
        self.rx = rx;
        self.screen = Screen::Auth;
        self.auth_state.password.zeroize();
        self.auth_state = AuthState::default();
        self.auth_state.notice =
            Some("Vault locked. Enter your master password to continue.".into());
        self.two_factor_state.token.zeroize();
        self.two_factor_state = TwoFactorState::default();
        self.clear_selection();
        self.results.clear();
        self.all_items.clear();
        self.folders.clear();
        self.folder_tree.clear();
        self.folder_paths.clear();
        self.health = None;
        self.health_in_flight = false;
        self.search_in_flight = false;
        self.sync_in_flight = false;
        self.searched = None;
        self.query.clear();
        self.confirm_close = false;
    }

    fn clear_selection(&mut self) {
        self.selected = None;
        self.summary_state = SummaryState::default();
        self.summary_state.detail_id = None;
        self.edit_state = None;
        self.reprompt_id = None;
        self.reprompt_password.zeroize();
        self.reprompt_at = None;
    }

    fn select(&mut self, id: &str) {
        if self.selected.as_deref() == Some(id) {
            return;
        }
        // Verifying one protected item must not keep the next one open.
        self.backend.revoke_item_grants();
        self.clear_selection();
        self.selected = Some(id.to_string());
        self.scroll_to_selected = true;
        self.summary_state.detail_id = Some(id.to_string());
        self.summary_state.in_flight = true;
        if self.settings.start_list == config::StartList::RecentlyUsed {
            let id = id.to_string();
            std::thread::spawn(move || {
                let _ = config::record_item_use(&id);
            });
        }
        self.spawn_detail(id.to_string());
    }

    fn move_selection(&mut self, delta: isize) {
        let ids = self
            .visible_items()
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return;
        }
        let next = match self
            .selected
            .as_ref()
            .and_then(|id| ids.iter().position(|other| other == id))
        {
            Some(idx) => (idx as isize + delta).clamp(0, ids.len() as isize - 1) as usize,
            None if delta < 0 => ids.len() - 1,
            None => 0,
        };
        self.select(&ids[next]);
    }

    fn set_section(&mut self, section: Section) {
        if section == self.section {
            return;
        }
        let state_changed = section.item_state() != self.section.item_state();
        self.section = section;
        if state_changed {
            self.results.clear();
            self.searched = None;
        }
        if matches!(self.section, Section::ActionCenter | Section::Health(_)) && self.health_stale {
            self.spawn_health();
        }
        // Keep the open item when it is still listed.
        let still_listed = self
            .selected
            .as_ref()
            .is_some_and(|id| self.visible_items().iter().any(|item| &item.id == id));
        if !still_listed {
            self.backend.revoke_item_grants();
            self.clear_selection();
        }
    }

    fn start_new_item(&mut self) {
        self.backend.revoke_item_grants();
        self.clear_selection();
        let mut edit = EditState::create();
        edit.folders = self.folders.clone();
        if let Some(draft) = edit.draft.as_mut() {
            match &self.section {
                Section::Folder(path) => {
                    draft.folder_id = self
                        .folder_paths
                        .iter()
                        .find(|(_, folder)| *folder == path)
                        .map(|(id, _)| id.clone());
                }
                Section::Favorites => draft.favorite = true,
                _ => {}
            }
        }
        // Stay clean until the user types, so cancelling needs no confirmation.
        if let Some(draft) = edit.draft.clone() {
            edit.set_draft(draft);
        }
        self.edit_state = Some(edit);
    }

    fn start_edit(&mut self) {
        let Some(id) = self.selected.clone() else {
            return;
        };
        self.summary_state.error = None;
        let mut edit = EditState::loading(id.clone());
        edit.folders = self.folders.clone();
        self.edit_state = Some(edit);
        self.spawn(move |backend| {
            let result = backend.edit_draft(&id);
            Reply::EditDraft { id, result }
        });
    }

    fn lock(&mut self) {
        match self.backend.lock_vault() {
            Ok(()) => self.reset_locked(),
            Err(error) => self.error = Some(format!("could not lock vault: {error}")),
        }
    }

    fn close_window(&mut self, ctx: &Context) {
        if self
            .edit_state
            .as_ref()
            .is_some_and(|edit| edit.saving || edit.is_dirty())
        {
            self.confirm_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            return;
        }
        self.exit_now();
    }

    fn exit_now(&mut self) -> ! {
        // process::exit skips Drop; wipe UI-owned plaintext first.
        self.auth_state.password.zeroize();
        self.two_factor_state.token.zeroize();
        self.reprompt_password.zeroize();
        self.summary_state = SummaryState::default();
        self.edit_state = None;
        self.backend.revoke_item_grants();
        std::process::exit(0);
    }

    // Runs every frame, also while eframe skips drawing a minimized window.
    fn process_background(&mut self, ctx: &Context) {
        while let Ok(command) = self.commands.try_recv() {
            match command {
                PopupCommand::VaultLocked => self.reset_locked(),
                PopupCommand::LockWarning => {
                    self.security_warning = self.backend.security_warning()
                }
                PopupCommand::Show => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                PopupCommand::Hide | PopupCommand::Toggle => self.close_window(ctx),
                PopupCommand::Quit => self.exit_now(),
                // SSH prompts belong to the popup.
                PopupCommand::SshApproval { .. } | PopupCommand::Unlock { .. } => {}
            }
        }
        self.poll_replies(ctx);
        if self
            .reprompt_at
            .is_some_and(|at| at.elapsed() >= REPROMPT_TTL)
        {
            self.reprompt_at = None;
            self.reprompt_id = self.summary_state.detail_id.clone();
            if let Some(detail) = &mut self.summary_state.detail {
                detail.zeroize();
            }
            self.summary_state.detail = None;
            self.summary_state.reveal_fields.clear();
            self.summary_state.error =
                Some("Verify again to continue. Your unsaved edits are preserved.".into());
        }
        if self.screen == Screen::Vault {
            let wanted = (self.query.trim().to_string(), self.section.item_state());
            if self.searched.as_ref() != Some(&wanted)
                && !self.search_in_flight
                && self.query_changed_at.elapsed() >= SEARCH_DEBOUNCE
            {
                self.spawn_search();
            }
            if self.last_sync_attempt.elapsed() >= SYNC_INTERVAL && self.edit_state.is_none() {
                self.spawn_sync();
            }
            if self.summary_state.needs_totp_refresh()
                && let Some(id) = self.summary_state.detail_id.clone()
            {
                self.summary_state.totp_in_flight = true;
                self.spawn(move |backend| {
                    let result = backend.get_totp(&id);
                    Reply::Totp { id, result }
                });
            }
        }
        self.schedule_repaint(ctx);
    }

    fn poll_replies(&mut self, ctx: &Context) {
        while let Ok(reply) = self.rx.try_recv() {
            match reply {
                Reply::Login(result) => {
                    self.auth_state.in_flight = false;
                    match result {
                        Ok(()) => self.unlocked(),
                        Err(BackendError::TwoFactorRequired(providers)) => {
                            self.two_factor_state.set_providers(providers);
                            self.auth_state.error = None;
                            self.screen = Screen::TwoFactor;
                        }
                        Err(error) => self.auth_state.error = Some(error.to_string()),
                    }
                }
                Reply::TwoFactor(result) => {
                    self.two_factor_state.in_flight = false;
                    match result {
                        Ok(()) => {
                            self.two_factor_state.token.zeroize();
                            self.two_factor_state.error = None;
                            self.unlocked();
                        }
                        Err(error) => {
                            self.two_factor_state.error = Some(error.to_string());
                            self.two_factor_state.token.zeroize();
                            self.two_factor_state.focus_token = true;
                        }
                    }
                }
                Reply::Synced(result) => {
                    self.sync_in_flight = false;
                    match result {
                        Ok(status) => {
                            self.sync_status = Some(status);
                            self.warning = None;
                            self.reload();
                            if self.edit_state.is_none()
                                && self.reprompt_id.is_none()
                                && let Some(id) = self.selected.clone()
                            {
                                self.spawn_detail(id);
                            }
                        }
                        Err(error) => {
                            self.warning =
                                Some(format!("Sync failed; showing cached items: {error}"))
                        }
                    }
                }
                Reply::AllItems(result) => match result {
                    Ok(items) => self.all_items = items,
                    Err(error) => self.error = Some(error.to_string()),
                },
                Reply::Search {
                    query,
                    state,
                    result,
                    status,
                    warning,
                    icons_url,
                } => {
                    self.search_in_flight = false;
                    self.icons.set_icons_url(icons_url);
                    if self.searched.as_ref() != Some(&(query, state)) {
                        continue;
                    }
                    match result {
                        Ok(items) => {
                            self.results = items;
                            self.sync_status = Some(status);
                            if warning.is_some() {
                                self.warning = warning;
                            }
                        }
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                Reply::Folders(result) => match result {
                    Ok(folders) => {
                        self.folder_tree = vault::folder_tree(&folders);
                        self.folder_paths = vault::folder_paths(&folders);
                        if let Some(edit) = self.edit_state.as_mut() {
                            edit.folders = folders.clone();
                        }
                        self.folders = folders;
                    }
                    Err(error) => self.error = Some(error.to_string()),
                },
                Reply::Health(result) => {
                    self.health_in_flight = false;
                    match result {
                        Ok(report) => {
                            self.health = Some(report);
                            self.health_error = None;
                        }
                        Err(error) => self.health_error = Some(error.to_string()),
                    }
                }
                Reply::Detail { id, result } => {
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.in_flight = false;
                    match result {
                        Ok(detail) => {
                            if self.reprompt_id.take().is_some() {
                                self.reprompt_at = Some(Instant::now());
                            }
                            self.summary_state.detail = Some(detail);
                            self.summary_state.error = None;
                            self.summary_state.selected_field = 0;
                            self.summary_state.reveal_fields.clear();
                        }
                        Err(error) => {
                            if let Some(detail) = &mut self.summary_state.detail {
                                detail.zeroize();
                            }
                            self.summary_state.detail = None;
                            if matches!(error, BackendError::RepromptRequired) {
                                self.reprompt_id = Some(id);
                            }
                            self.summary_state.error = Some(error.to_string());
                        }
                    }
                }
                Reply::Totp { id, result } => {
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.totp_in_flight = false;
                    self.summary_state.totp = result.ok();
                    self.summary_state.totp_fetched_at = Some(Instant::now());
                }
                Reply::ItemAction { id, action, result } => {
                    if self.summary_state.detail_id.as_deref() != Some(id.as_str()) {
                        continue;
                    }
                    self.summary_state.action_in_flight = false;
                    self.summary_state.confirm = None;
                    match result {
                        Ok(()) => {
                            self.show_notice(action.done_message());
                            self.reload();
                            if matches!(action, ItemAction::Favorite | ItemAction::Unfavorite) {
                                self.spawn_detail(id);
                            } else {
                                // The item moved to another list.
                                self.backend.revoke_item_grants();
                                self.clear_selection();
                            }
                        }
                        Err(error) => self.summary_state.error = Some(error.to_string()),
                    }
                }
                Reply::EditDraft { id, result } => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.id == id) else {
                        continue;
                    };
                    match result {
                        Ok(draft) => edit.set_draft(draft),
                        Err(error) => {
                            self.edit_state = None;
                            self.summary_state.error = Some(format!("could not edit: {error}"));
                        }
                    }
                }
                Reply::Saved { id, result } => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.id == id) else {
                        continue;
                    };
                    match result {
                        Ok(detail) => {
                            self.edit_state = None;
                            self.summary_state.detail = Some(detail);
                            self.summary_state.error = None;
                            self.summary_state.selected_field = 0;
                            self.summary_state.reveal_fields.clear();
                            self.summary_state.totp = None;
                            self.summary_state.totp_fetched_at = None;
                            self.show_notice("Saved");
                            self.reload();
                        }
                        Err(error) => {
                            edit.saving = false;
                            edit.error = Some(error.to_string());
                        }
                    }
                }
                Reply::FolderSaved { next, result } => match result {
                    Ok(()) => {
                        self.folder_edit = None;
                        self.reload();
                        if let Some(section) = next {
                            self.set_section(section);
                        }
                    }
                    Err(error) => {
                        // A rename or delete may have gone through in part.
                        self.reload();
                        if let Some(edit) = self.folder_edit.as_mut() {
                            edit.busy = false;
                            edit.error = Some(error.to_string());
                        }
                    }
                },
                Reply::Moved { id, notice, result } => match result {
                    Ok(()) => {
                        self.show_notice(&notice);
                        self.reload();
                        if self.selected.as_deref() == Some(id.as_str())
                            && self.reprompt_id.is_none()
                        {
                            self.spawn_detail(id);
                        }
                    }
                    Err(error) => self.error = Some(format!("could not move item: {error}")),
                },
                Reply::Created(result) => {
                    let Some(edit) = self.edit_state.as_mut().filter(|edit| edit.creating) else {
                        continue;
                    };
                    match result {
                        Ok(detail) => {
                            self.edit_state = None;
                            self.selected = Some(detail.id.clone());
                            self.scroll_to_selected = true;
                            self.summary_state = SummaryState::default();
                            self.summary_state.detail_id = Some(detail.id.clone());
                            self.summary_state.detail = Some(detail);
                            self.show_notice("Item created");
                            self.reload();
                        }
                        Err(error) => {
                            edit.saving = false;
                            edit.error = Some(error.to_string());
                        }
                    }
                }
            }
            ctx.request_repaint();
        }
    }

    fn unlocked(&mut self) {
        self.auth_state.password.zeroize();
        self.auth_state.error = None;
        self.auth_state.notice = None;
        self.screen = Screen::Vault;
        self.focus_search = true;
        self.reload();
    }

    fn schedule_repaint(&self, ctx: &Context) {
        if let Some(after) = self.summary_state.repaint_after() {
            ctx.request_repaint_after(after);
        }
        let busy = self.sync_in_flight
            || self.search_in_flight
            || self.health_in_flight
            || self.summary_state.in_flight
            || self.summary_state.totp_in_flight
            || self.summary_state.action_in_flight
            || self.auth_state.in_flight
            || self.two_factor_state.in_flight
            || self
                .edit_state
                .as_ref()
                .is_some_and(|edit| edit.saving || edit.draft.is_none());
        // Background replies arrive over a channel, which does not wake egui.
        ctx.request_repaint_after(if busy {
            Duration::from_millis(50)
        } else {
            Duration::from_millis(250)
        });
    }
}

impl eframe::App for WindowApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme().bg.to_normalized_gamma_f32()
    }

    fn logic(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.process_background(ctx);
    }

    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.close_window(ctx);
        }
        self.icons.poll(ctx);
        if let Some(warning) = &self.security_warning {
            egui::Panel::top("vault-security-warning").show(root, |ui| {
                ui.colored_label(theme().warning, warning);
            });
        }
        if self.confirm_close {
            self.draw_confirm_close(ctx);
        }
        match self.screen {
            Screen::Auth => self.update_auth(root),
            Screen::TwoFactor => self.update_two_factor(root),
            Screen::Vault => self.update_vault(root),
        }
        self.icons.start_queued(ctx);
    }
}

impl WindowApp {
    fn draw_confirm_close(&mut self, ctx: &Context) {
        let busy = self.edit_state.as_ref().is_some_and(|edit| edit.saving);
        let dialog = widgets::ConfirmDialog {
            title: "Close and discard changes?",
            body: if busy {
                "Wait for the save to finish before closing."
            } else {
                "Unsaved edits will be lost."
            },
            confirm_label: "Discard and close",
            danger: true,
            key: widgets::ConfirmKey::None,
            busy,
            error: None,
        };
        match widgets::confirm_dialog(ctx, &dialog) {
            Some(true) => {
                self.edit_state = None;
                self.exit_now();
            }
            Some(false) => self.confirm_close = false,
            None => {}
        }
    }

    /// The login screens keep the popup's size, centered in the window.
    fn centered(root: &mut egui::Ui, draw: impl FnOnce(&mut egui::Ui)) {
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(theme().bg))
            .show(root, |ui| {
                let area = ui.max_rect();
                let rect = egui::Rect::from_center_size(
                    area.center(),
                    widgets::WINDOW_SIZE.min(area.size()),
                );
                ui.scope_builder(egui::UiBuilder::new().max_rect(rect), draw);
            });
    }

    fn update_auth(&mut self, root: &mut egui::Ui) {
        let mut action = None;
        Self::centered(root, |ui| action = draw_auth(ui, &mut self.auth_state));
        match action {
            Some(AuthAction::Login) => {
                self.auth_state.in_flight = true;
                self.auth_state.error = None;
                let server_url = self.auth_state.server_url.trim().to_string();
                let email = self.auth_state.email.trim().to_string();
                let mut password = self.auth_state.password.clone();
                let remember = self.auth_state.remember;
                self.spawn(move |backend| {
                    let result = backend.login(&server_url, &email, &password, remember);
                    password.zeroize();
                    Reply::Login(result)
                });
            }
            Some(AuthAction::ForgetUser) => match self.backend.clear_saved_session() {
                Ok(()) => {
                    let _ = config::clear_recent_item();
                    let _ = config::clear_item_usage();
                    self.auth_state.reset_to_full_login();
                }
                Err(error) => {
                    self.auth_state.error = Some(format!("could not forget saved user: {error}"));
                    self.auth_state.confirm_forget = false;
                }
            },
            None => {}
        }
    }

    fn update_two_factor(&mut self, root: &mut egui::Ui) {
        let mut action = None;
        Self::centered(root, |ui| {
            action = draw_two_factor(ui, &mut self.two_factor_state)
        });
        match action {
            Some(TwoFactorAction::Verify) => {
                self.two_factor_state.in_flight = true;
                self.two_factor_state.error = None;
                let provider = self.two_factor_state.selected_provider;
                let token = zeroize::Zeroizing::new(self.two_factor_state.token.clone());
                let remember = self.two_factor_state.remember;
                self.spawn(move |backend| {
                    Reply::TwoFactor(match provider {
                        Some(provider) => backend.complete_two_factor(provider, &token, remember),
                        None => Err(BackendError::Message("missing two factor provider".into())),
                    })
                });
            }
            Some(TwoFactorAction::Back) => {
                self.two_factor_state.token.zeroize();
                self.two_factor_state.error = None;
                self.auth_state.focus_password = true;
                self.screen = Screen::Auth;
            }
            None => {}
        }
    }

    fn update_vault(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        let editing = self.edit_state.is_some();
        if self.folder_edit.is_some() {
            self.draw_folder_dialog(ctx);
        }
        vault::draw_drag_preview(ctx);
        let dialog_open = self.confirm_close
            || self.summary_state.confirm.is_some()
            || self.folder_edit.is_some();
        self.handle_keys(ctx, editing || dialog_open);

        egui::Panel::top("vault-toolbar")
            .frame(
                egui::Frame::new()
                    .fill(theme().bg)
                    .inner_margin(egui::Margin::symmetric(14, 10)),
            )
            .show(root, |ui| self.draw_toolbar(ui, editing));
        egui::Panel::bottom("vault-statusbar")
            .frame(widgets::footer_frame())
            .show(root, |ui| self.draw_statusbar(ui));

        let t = theme();
        egui::Panel::left("vault-sidebar")
            .resizable(true)
            .default_size(230.0)
            .min_size(180.0)
            .max_size(360.0)
            .frame(
                egui::Frame::new()
                    .fill(t.surface)
                    .inner_margin(egui::Margin::symmetric(8, 10)),
            )
            .show(root, |ui| {
                ui.add_enabled_ui(!editing, |ui| {
                    let counts = SidebarCounts::new(
                        &self.all_items,
                        &self.folder_paths,
                        &self.folder_tree,
                        self.health.as_ref(),
                    );
                    if let Some(action) = vault::draw_sidebar(
                        ui,
                        &self.section,
                        &self.folder_tree,
                        &mut self.collapsed,
                        &counts,
                    ) {
                        self.sidebar_action(action);
                    }
                });
            });

        if self.section == Section::ActionCenter {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(t.bg)
                        .inner_margin(egui::Margin::symmetric(20, 12)),
                )
                .show(root, |ui| {
                    if let Some(check) = vault::draw_action_center(
                        ui,
                        self.health.as_ref(),
                        self.health_in_flight,
                        self.health_error.as_deref(),
                    ) {
                        self.set_section(Section::Health(check));
                    }
                });
            return;
        }

        egui::Panel::left("vault-list")
            .resizable(true)
            .default_size(330.0)
            .min_size(240.0)
            .max_size(520.0)
            .frame(
                egui::Frame::new()
                    .fill(t.bg)
                    .inner_margin(egui::Margin::symmetric(8, 10)),
            )
            .show(root, |ui| {
                ui.add_enabled_ui(!editing, |ui| self.draw_list(ui));
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(t.bg))
            .show(root, |ui| {
                // A thin rule between the list and the item.
                ui.painter().vline(
                    ui.max_rect().left(),
                    ui.max_rect().y_range(),
                    egui::Stroke::new(1.0_f32, t.separator),
                );
                self.draw_detail(ui);
            });
    }

    fn sidebar_action(&mut self, action: SidebarAction) {
        let kind = match action {
            SidebarAction::Open(section) => return self.set_section(section),
            SidebarAction::Drop { item_id, target } => return self.move_dropped(item_id, target),
            SidebarAction::NewFolder { parent } => FolderEditKind::Create {
                parent,
                name: String::new(),
            },
            SidebarAction::RenameFolder(path) => FolderEditKind::Rename {
                name: path.clone(),
                path,
            },
            SidebarAction::DeleteFolder(path) => FolderEditKind::Delete { path },
        };
        self.folder_edit = Some(FolderEdit {
            kind,
            busy: false,
            error: None,
        });
    }

    /// Moves a dropped item into a folder, out of all folders, or into Favorites.
    fn move_dropped(&mut self, id: String, target: DropTarget) {
        let Some(item) = self.all_items.iter().find(|item| item.id == id) else {
            return;
        };
        let current = item
            .folder_id
            .as_ref()
            .and_then(|folder| self.folder_paths.get(folder));
        match target {
            DropTarget::Favorites => {
                if item.favorite {
                    return;
                }
                self.spawn(move |backend| Reply::Moved {
                    result: backend.apply_action(&id, ItemAction::Favorite),
                    notice: ItemAction::Favorite.done_message().into(),
                    id,
                });
            }
            DropTarget::NoFolder => {
                if current.is_none() {
                    return;
                }
                self.spawn(move |backend| Reply::Moved {
                    result: backend.move_item(&id, None),
                    notice: "Moved out of its folder".into(),
                    id,
                });
            }
            DropTarget::Folder(path) => {
                if current == Some(&path) {
                    return;
                }
                let folder_id = self
                    .folder_paths
                    .iter()
                    .find(|(_, folder)| **folder == path)
                    .map(|(id, _)| id.clone());
                let notice = format!("Moved to {}", path.rsplit('/').next().unwrap_or(&path));
                self.spawn(move |backend| {
                    // A parent shown only because of its subfolders is created first.
                    let result = match folder_id {
                        Some(folder_id) => backend.move_item(&id, Some(&folder_id)),
                        None => backend
                            .create_folder(&path)
                            .and_then(|folder| backend.move_item(&id, Some(&folder.id))),
                    };
                    Reply::Moved { id, notice, result }
                });
            }
        }
    }

    fn draw_folder_dialog(&mut self, ctx: &Context) {
        let Some(edit) = self.folder_edit.as_mut() else {
            return;
        };
        let busy = edit.busy;
        let error = edit.error.clone();
        match &mut edit.kind {
            FolderEditKind::Create { parent, name } => {
                let hint = match parent {
                    Some(parent) => format!("Creates a subfolder of {parent}."),
                    None => "Use / to nest it, for example Work/Servers.".into(),
                };
                match vault::folder_name_dialog(
                    ctx,
                    "New folder",
                    &hint,
                    name,
                    busy,
                    error.as_deref(),
                ) {
                    Some(true) => {
                        let full = match parent {
                            Some(parent) => format!("{parent}/{}", name.trim()),
                            None => name.trim().to_string(),
                        };
                        let full = match crate::bw::validate_folder_name(&full) {
                            Ok(full) => full,
                            Err(e) => {
                                edit.error = Some(e.to_string());
                                return;
                            }
                        };
                        edit.busy = true;
                        edit.error = None;
                        self.spawn(move |backend| Reply::FolderSaved {
                            result: backend.create_folder(&full).map(|_| ()),
                            next: Some(Section::Folder(full)),
                        });
                    }
                    Some(false) => self.folder_edit = None,
                    None => {}
                }
            }
            FolderEditKind::Rename { path, name } => {
                let hint = "Subfolders are renamed with it. Change the part before a / to \
                            move the folder.";
                match vault::folder_name_dialog(
                    ctx,
                    "Rename folder",
                    hint,
                    name,
                    busy,
                    error.as_deref(),
                ) {
                    Some(true) => {
                        let new_path = match crate::bw::validate_folder_name(name) {
                            Ok(new_path) => new_path,
                            Err(e) => {
                                edit.error = Some(e.to_string());
                                return;
                            }
                        };
                        if new_path == *path {
                            self.folder_edit = None;
                            return;
                        }
                        if vault::in_folder(&new_path, path) {
                            edit.error = Some("A folder can't move into itself".into());
                            return;
                        }
                        let renames = vault::folder_renames(&self.folders, path, &new_path);
                        edit.busy = true;
                        edit.error = None;
                        // Follow the open folder to its new name.
                        let next = match &self.section {
                            Section::Folder(open) if vault::in_folder(open, path) => Some(
                                Section::Folder(format!("{new_path}{}", &open[path.len()..])),
                            ),
                            _ => None,
                        };
                        self.spawn(move |backend| Reply::FolderSaved {
                            result: backend.rename_folders(&renames),
                            next,
                        });
                    }
                    Some(false) => self.folder_edit = None,
                    None => {}
                }
            }
            FolderEditKind::Delete { path } => {
                let items = SidebarCounts::new(
                    &self.all_items,
                    &self.folder_paths,
                    &self.folder_tree,
                    None,
                )
                .folders
                .get(path.as_str())
                .copied()
                .unwrap_or(0);
                let ids = vault::folder_subtree(&self.folders, path);
                let subfolders = ids.len().saturating_sub(1);
                let mut body = format!("\"{path}\"");
                if subfolders > 0 {
                    body.push_str(&format!(
                        " and its {subfolders} subfolder{}",
                        if subfolders == 1 { "" } else { "s" }
                    ));
                }
                body.push_str(if items == 0 {
                    " will be deleted."
                } else {
                    " will be deleted. "
                });
                if items > 0 {
                    body.push_str(&format!(
                        "The {items} item{} inside stay in your vault without a folder.",
                        if items == 1 { "" } else { "s" }
                    ));
                }
                let dialog = widgets::ConfirmDialog {
                    title: "Delete folder?",
                    body: &body,
                    confirm_label: "Delete folder",
                    danger: true,
                    key: widgets::ConfirmKey::CtrlEnter,
                    busy,
                    error: error.as_deref(),
                };
                match widgets::confirm_dialog(ctx, &dialog) {
                    Some(true) => {
                        edit.busy = true;
                        edit.error = None;
                        let next = matches!(&self.section, Section::Folder(open) if vault::in_folder(open, path))
                            .then_some(Section::All);
                        self.spawn(move |backend| Reply::FolderSaved {
                            result: backend.delete_folders(&ids),
                            next,
                        });
                    }
                    Some(false) => self.folder_edit = None,
                    None => {
                        // Only Ctrl+Enter confirms; a plain Enter must not reach the item.
                        ctx.input_mut(|input| {
                            input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                        });
                    }
                }
            }
        }
    }

    fn handle_keys(&mut self, ctx: &Context, blocked: bool) {
        if blocked {
            return;
        }
        let search_id = egui::Id::new(SEARCH_INPUT_ID);
        let focused = ctx.memory(|m| m.focused());
        let navigable = focused.is_none() || focused == Some(search_id);
        let mut moves = 0isize;
        let (mut new_item, mut sync, mut lock, mut find) = (false, false, false, false);
        ctx.input_mut(|input| {
            find = input.consume_key(egui::Modifiers::COMMAND, egui::Key::F);
            new_item = input.consume_key(egui::Modifiers::COMMAND, egui::Key::N);
            sync = input.consume_key(egui::Modifiers::COMMAND, egui::Key::R);
            lock = input.consume_key(egui::Modifiers::COMMAND, egui::Key::L);
            if navigable {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    moves += 1;
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    moves -= 1;
                }
            }
            if focused == Some(search_id)
                && !self.query.is_empty()
                && input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
            {
                self.query.clear();
                self.query_changed_at = Instant::now();
            }
        });
        if find {
            self.focus_search = true;
        }
        if new_item {
            self.start_new_item();
        }
        if sync {
            self.spawn_sync();
        }
        if lock {
            self.lock();
            return;
        }
        if moves != 0 && self.section != Section::ActionCenter {
            self.move_selection(moves);
            // Leave the search box so the item's own keys (E, F, Enter…) work.
            ctx.memory_mut(|m| m.surrender_focus(search_id));
        }
    }

    fn draw_toolbar(&mut self, ui: &mut egui::Ui, editing: bool) {
        let t = theme();
        let mut new_item = false;
        let mut lock = false;
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add(
                    egui::Button::new(
                        RichText::new(t.icon("\u{f023}", "🔒"))
                            .size(t.body())
                            .color(t.text_muted),
                    )
                    .frame(false)
                    .min_size(egui::vec2(32.0, 32.0)),
                )
                .on_hover_text("Lock vault (Ctrl+L)")
                .clicked()
            {
                lock = true;
            }
            let label = format!("{}  New item", t.icon("\u{f067}", "+"));
            new_item = widgets::button(ui, &label, true, !editing)
                .on_hover_text("Ctrl+N")
                .clicked();
            ui.add_space(8.0);
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                widgets::logo(ui, t.title() + 4.0);
                ui.label(
                    RichText::new(crate::logo::APP_NAME)
                        .size(t.body())
                        .strong()
                        .color(t.text_strong),
                );
                ui.add_space(24.0);
                ui.label(
                    RichText::new(t.icon("\u{f002}", "🔎"))
                        .size(t.body())
                        .color(t.text_muted),
                );
                let response = ui
                    .add_enabled_ui(!editing, |ui| {
                        widgets::text_input(
                            ui,
                            egui::Id::new(SEARCH_INPUT_ID),
                            &mut self.query,
                            "Search vault (Ctrl+F)",
                            false,
                            t.body(),
                        )
                    })
                    .inner;
                if response.changed() {
                    self.query_changed_at = Instant::now();
                    // Searching lists items, so leave the action center.
                    if self.section == Section::ActionCenter {
                        self.set_section(Section::All);
                    }
                }
                if self.focus_search && !editing {
                    response.request_focus();
                    self.focus_search = false;
                }
            });
        });
        if new_item {
            self.start_new_item();
        }
        if lock {
            self.lock();
        }
    }

    fn draw_statusbar(&mut self, ui: &mut egui::Ui) {
        let t = theme();
        let notice = self
            .notice
            .as_ref()
            .filter(|(_, at)| at.elapsed() < NOTICE_DURATION)
            .map(|(text, _)| (text.clone(), t.success));
        let status = self
            .error
            .clone()
            .map(|error| (error, t.danger))
            .or(notice)
            .or_else(|| self.warning.clone().map(|warning| (warning, t.warning)));
        let hints: &[(&str, &str)] = if self.settings.show_keyboard_shortcuts {
            &[
                ("↑↓", "Items"),
                ("Ctrl+F", "Search"),
                ("Ctrl+N", "New"),
                ("Ctrl+R", "Sync"),
                ("Ctrl+L", "Lock"),
            ]
        } else {
            &[]
        };
        let sync_label = if self.sync_in_flight {
            "Syncing…".to_string()
        } else {
            match self.sync_status.as_ref().and_then(|s| s.last_synced_unix) {
                Some(at) => {
                    let minutes = unix_now().saturating_sub(at) / 60;
                    if minutes == 0 {
                        "Synced just now".into()
                    } else {
                        format!("Synced {minutes} min ago")
                    }
                }
                None => "Sync".into(),
            }
        };
        let shown = status
            .as_ref()
            .map(|(text, color)| (text.as_str(), *color))
            .or(Some((sync_label.as_str(), t.text_faint)));
        let rect = widgets::footer(ui, hints, shown);
        if status.is_none()
            && let Some(rect) = rect
        {
            let response = ui.interact(rect, egui::Id::new("vault-sync"), egui::Sense::click());
            if response
                .on_hover_text("Sync vault · Ctrl+R")
                .on_hover_cursor(egui::CursorIcon::PointingHand)
                .clicked()
            {
                self.spawn_sync();
            }
        } else if self.error.is_some()
            && let Some(rect) = rect
            && ui
                .interact(rect, egui::Id::new("vault-error"), egui::Sense::click())
                .on_hover_text("Click to dismiss")
                .clicked()
        {
            self.error = None;
        }
    }

    fn draw_list(&mut self, ui: &mut egui::Ui) {
        let title = self.section.title();
        let mut order = self.order;
        let clicked = {
            let items = visible_items(
                &self.results,
                &self.section,
                &self.folder_paths,
                self.health.as_ref(),
                &self.query,
                order,
            );
            let selected = self
                .selected
                .as_ref()
                .and_then(|id| items.iter().position(|item| &item.id == id));
            vault::draw_list_header(ui, &title, items.len(), &mut order);
            ui.add_space(6.0);
            if self.search_in_flight && items.is_empty() {
                widgets::empty_state(ui, "", "Loading…", true);
                None
            } else {
                vault::draw_item_list(
                    ui,
                    &items,
                    selected,
                    self.scroll_to_selected,
                    &mut self.icons,
                )
                .map(|idx| items[idx].id.clone())
            }
        };
        self.order = order;
        self.scroll_to_selected = false;
        if let Some(id) = clicked {
            self.select(&id);
        }
    }

    fn draw_detail(&mut self, ui: &mut egui::Ui) {
        let t = theme();
        let shortcuts = self.settings.show_keyboard_shortcuts;

        if let Some(edit) = self.edit_state.as_mut() {
            match draw_edit(ui, edit, shortcuts) {
                Some(EditAction::Save(draft)) => {
                    edit.saving = true;
                    edit.error = None;
                    if edit.creating {
                        self.spawn(move |backend| {
                            let draft = zeroize::Zeroizing::new(draft);
                            Reply::Created(backend.create_item(&draft))
                        });
                    } else {
                        let id = edit.id.clone();
                        self.spawn(move |backend| {
                            let draft = zeroize::Zeroizing::new(draft);
                            let result = backend.save_item(&id, &draft);
                            Reply::Saved { id, result }
                        });
                    }
                }
                Some(EditAction::Cancel) => self.edit_state = None,
                None => {}
            }
            return;
        }

        if let Some(id) = self.reprompt_id.clone() {
            self.draw_reprompt(ui, id);
            return;
        }

        if self.selected.is_none() {
            let text = if self.visible_items().is_empty() {
                "Nothing here yet"
            } else {
                "Select an item to see its details"
            };
            widgets::empty_state(ui, t.icon("\u{f023}", "🔒"), text, false);
            return;
        }

        let copy_id = self.summary_state.detail_id.clone().unwrap_or_default();
        let copy_version = self
            .summary_state
            .detail
            .as_ref()
            .map(|detail| detail.copy_version());
        let backend = self.backend.clone();
        let action = draw_summary(
            ui,
            &mut self.summary_state,
            shortcuts,
            true,
            &mut self.icons,
            &mut |index| backend.copy_field(&copy_id, index, copy_version.ok_or("No item open")?),
        );
        match action {
            Some(SummaryAction::Edit) => self.start_edit(),
            Some(SummaryAction::Item(action)) => {
                if let Some(id) = self.summary_state.detail_id.clone() {
                    self.summary_state.error = None;
                    self.summary_state.action_in_flight = true;
                    self.spawn(move |backend| {
                        let result = backend.apply_action(&id, action);
                        Reply::ItemAction { id, action, result }
                    });
                }
            }
            Some(SummaryAction::Back) => {
                self.backend.revoke_item_grants();
                self.clear_selection();
            }
            Some(SummaryAction::Copied) | None => {}
        }
    }

    fn draw_reprompt(&mut self, ui: &mut egui::Ui, id: String) {
        let t = theme();
        let ctx = &ui.ctx().clone();
        let mut verify = false;
        egui::Frame::new()
            .inner_margin(egui::Margin::same(24))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(format!(
                        "{}  Verify master password",
                        t.icon("\u{f023}", "🔒")
                    ))
                    .size(t.title())
                    .color(t.text_strong),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "This item requires your master password before it can be viewed or \
                         edited.",
                    )
                    .color(t.text_muted),
                );
                ui.add_space(10.0);
                ui.set_max_width(420.0);
                let input_id = egui::Id::new("vault-window-reprompt");
                let response = widgets::text_input(
                    ui,
                    input_id,
                    &mut self.reprompt_password,
                    "Master password",
                    true,
                    t.body(),
                );
                if !ctx.memory(|m| m.has_focus(input_id)) && !self.summary_state.in_flight {
                    response.request_focus();
                }
                if let Some(error) = &self.summary_state.error {
                    ui.add_space(6.0);
                    widgets::error_line(ui, error);
                }
                ui.add_space(10.0);
                let ready = !self.summary_state.in_flight && !self.reprompt_password.is_empty();
                verify = widgets::button(ui, "Verify", true, ready).clicked()
                    || (ready && ctx.input(|i| i.key_pressed(egui::Key::Enter)));
            });
        if verify {
            self.spawn_authorize(id);
        }
    }
}

fn visible_items<'a>(
    results: &'a [BwItem],
    section: &Section,
    folder_paths: &HashMap<String, String>,
    health: Option<&HealthReport>,
    query: &str,
    order: ListOrder,
) -> Vec<&'a BwItem> {
    let mut items = results
        .iter()
        .filter(|item| section.contains(item, folder_paths, health))
        .collect::<Vec<_>>();
    // A search keeps the daemon's relevance order.
    if query.trim().is_empty() {
        order.sort(&mut items);
    }
    items
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
