//! The vault window's settings: a category sidebar with icon tiles, and one page per
//! category with its settings grouped under headings in a centered column. Rows, keyboard
//! selection and actions are shared with quick access's compact list in `ui::search`.
use crate::config::{AppSettings, PasskeyVerification, StartList};
use crate::model::SshAgentStatus;
use crate::ui::search::{
    self, BROWSER_SETUP_ROW, DEFAULT_URI_MATCH_ROW, IDLE_TIMEOUT_ROW, PAIRED_BROWSERS_ROW,
    PASSKEY_VERIFICATION_ROW, SCREEN_CAPTURE_ROW, SETTING_TEXT, SHORTCUT_ROW, START_AT_LOGIN_ROW,
    START_LIST_ROW, SearchAction, SearchState, SettingsGroup,
};
use crate::ui::{theme::theme, widgets};
use crate::uri_match::UriMatchType;
use egui::{Color32, Painter, Pos2, RichText, Ui};

const PAGE_WIDTH: f32 = 640.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Group(SettingsGroup),
    About,
}

pub enum SidebarAction {
    Back,
    Select(Category),
}

const CATEGORIES: &[(Category, &str, Icon)] = &[
    (
        Category::Group(SettingsGroup::General),
        "General",
        Icon::Gear,
    ),
    (
        Category::Group(SettingsGroup::Security),
        "Security",
        Icon::Lock,
    ),
    (
        Category::Group(SettingsGroup::Browser),
        "Browser",
        Icon::Globe,
    ),
    (
        Category::Group(SettingsGroup::Ssh),
        "SSH agent",
        Icon::Terminal,
    ),
    (Category::About, "About", Icon::Info),
];

pub fn title(category: Category) -> &'static str {
    CATEGORIES
        .iter()
        .find(|(entry, ..)| *entry == category)
        .map_or("Settings", |(_, label, _)| label)
}

pub fn draw_sidebar(ui: &mut Ui, current: Category) -> Option<SidebarAction> {
    let t = theme();
    let mut action = None;
    if ui
        .add(
            egui::Button::new(
                RichText::new(format!("{}  Vault", t.icon("\u{f104}", "‹"))).color(t.accent),
            )
            .frame(false),
        )
        .on_hover_text("Back to the vault (Esc)")
        .clicked()
    {
        action = Some(SidebarAction::Back);
    }
    ui.add_space(10.0);
    for (index, (category, label, icon)) in CATEGORIES.iter().enumerate() {
        if *category == Category::About {
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);
        } else if index > 0 {
            ui.add_space(2.0);
        }
        if category_row(ui, *category == current, label, *icon).clicked() {
            action = Some(SidebarAction::Select(*category));
        }
    }
    action
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Icon {
    Gear,
    Lock,
    Globe,
    Terminal,
    Info,
}

impl Icon {
    fn tile(self) -> Color32 {
        let t = theme();
        match self {
            Self::Gear | Self::Info => t.text_muted,
            Self::Lock => t.warning,
            Self::Globe => t.accent,
            Self::Terminal => t.success,
        }
    }
}

fn category_row(ui: &mut Ui, selected: bool, label: &str, icon: Icon) -> egui::Response {
    let t = theme();
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 38.0), egui::Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::SelectableLabel, true, selected, label)
    });
    let painter = ui.painter_at(rect);
    if selected {
        painter.rect_filled(rect, t.rounding, t.selected_bg);
    } else if response.hovered() {
        painter.rect_filled(rect, t.rounding, t.hover);
    }
    let tile = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 22.0, rect.center().y),
        egui::vec2(24.0, 24.0),
    );
    painter.rect_filled(tile, t.rounding.min(6) as f32, icon.tile());
    paint_icon(&painter, icon, tile.center(), t.bg);
    painter.text(
        egui::pos2(rect.left() + 44.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        label,
        t.font(t.body()),
        if selected { t.selected_text } else { t.text },
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Small line icons, drawn so they look the same with or without icon fonts.
fn paint_icon(painter: &Painter, icon: Icon, center: Pos2, color: Color32) {
    let stroke = egui::Stroke::new(1.6_f32, color);
    match icon {
        Icon::Gear => {
            painter.circle_stroke(center, 4.2, stroke);
            for step in 0..8 {
                let angle = step as f32 * std::f32::consts::FRAC_PI_4;
                let direction = egui::vec2(angle.cos(), angle.sin());
                painter.line_segment([center + direction * 5.6, center + direction * 8.0], stroke);
            }
        }
        Icon::Lock => {
            let body =
                egui::Rect::from_center_size(center + egui::vec2(0.0, 2.5), egui::vec2(11.0, 8.0));
            painter.rect_filled(body, 1.5, color);
            let top = center + egui::vec2(0.0, -2.0);
            let points: Vec<Pos2> = (0..=12)
                .map(|step| {
                    let angle = std::f32::consts::PI * (1.0 + step as f32 / 12.0);
                    top + egui::vec2(angle.cos() * 3.6, angle.sin() * 3.6)
                })
                .collect();
            painter.add(egui::Shape::line(points, stroke));
            painter.line_segment(
                [top + egui::vec2(-3.6, 0.0), top + egui::vec2(-3.6, 1.5)],
                stroke,
            );
            painter.line_segment(
                [top + egui::vec2(3.6, 0.0), top + egui::vec2(3.6, 1.5)],
                stroke,
            );
        }
        Icon::Globe => {
            painter.circle_stroke(center, 7.0, stroke);
            painter.line_segment(
                [
                    center + egui::vec2(-7.0, 0.0),
                    center + egui::vec2(7.0, 0.0),
                ],
                stroke,
            );
            let meridian: Vec<Pos2> = (0..=16)
                .map(|step| {
                    let angle = std::f32::consts::TAU * step as f32 / 16.0;
                    center + egui::vec2(angle.cos() * 3.0, angle.sin() * 7.0)
                })
                .collect();
            painter.add(egui::Shape::closed_line(meridian, stroke));
        }
        Icon::Terminal => {
            painter.line_segment(
                [
                    center + egui::vec2(-6.0, -4.0),
                    center + egui::vec2(-1.5, 0.0),
                ],
                stroke,
            );
            painter.line_segment(
                [
                    center + egui::vec2(-1.5, 0.0),
                    center + egui::vec2(-6.0, 4.0),
                ],
                stroke,
            );
            painter.line_segment(
                [center + egui::vec2(0.5, 4.5), center + egui::vec2(6.5, 4.5)],
                stroke,
            );
        }
        Icon::Info => {
            painter.circle_filled(center + egui::vec2(0.0, -4.5), 1.4, color);
            painter.line_segment(
                [
                    center + egui::vec2(0.0, -1.5),
                    center + egui::vec2(0.0, 5.5),
                ],
                egui::Stroke::new(2.2_f32, color),
            );
        }
    }
}

/// Lays out `add_contents` in the page column, centered once the window is wider.
pub fn column(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui)) {
    let width = ui.available_width().min(PAGE_WIDTH);
    let margin = ((ui.available_width() - width) / 2.0).max(0.0);
    ui.horizontal_top(|ui| {
        ui.add_space(margin);
        ui.vertical(|ui| {
            ui.set_width(width);
            add_contents(ui);
        });
    });
}

/// A scrolling page column.
fn page(ui: &mut Ui, id: &str, add_contents: impl FnOnce(&mut Ui)) {
    egui::ScrollArea::vertical()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| column(ui, add_contents));
}

pub fn heading(ui: &mut Ui, text: &str) {
    let t = theme();
    ui.add_space(4.0);
    ui.label(RichText::new(text).size(t.title()).color(t.text_strong));
}

/// A sub-page's back link and title. Returns whether the back link was clicked.
pub fn subpage_header(ui: &mut Ui, back: &str, title: &str, enabled: bool) -> bool {
    let t = theme();
    let clicked = ui
        .add_enabled(
            enabled,
            egui::Button::new(
                RichText::new(format!("{}  {back}", t.icon("\u{f104}", "‹"))).color(t.accent),
            )
            .frame(false),
        )
        .on_hover_text("Back (Esc)")
        .clicked();
    heading(ui, title);
    clicked
}

fn section(ui: &mut Ui, text: &str) {
    let t = theme();
    ui.add_space(18.0);
    ui.label(RichText::new(text).strong().color(t.text_strong));
    ui.add_space(4.0);
}

/// One settings category. About is drawn by the caller, which owns the licenses view.
pub fn draw_page(
    ui: &mut Ui,
    group: SettingsGroup,
    state: &mut SearchState,
    settings: &AppSettings,
    ssh_agent_status: &SshAgentStatus,
) -> Option<SearchAction> {
    let mut action = None;
    page(ui, "settings-page", |ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        heading(ui, title(Category::Group(group)));
        let mut take = |next: Option<SearchAction>| {
            if next.is_some() {
                action = next;
            }
        };
        match group {
            SettingsGroup::General => {
                if search::row_supported(START_AT_LOGIN_ROW) {
                    section(ui, "Startup");
                    take(switch(
                        ui,
                        state,
                        settings,
                        START_AT_LOGIN_ROW,
                        settings.start_at_login,
                        true,
                        None,
                    ));
                }
                section(ui, "Quick access");
                take(switch(
                    ui,
                    state,
                    settings,
                    1,
                    settings.close_after_copy,
                    true,
                    None,
                ));
                take(switch(
                    ui,
                    state,
                    settings,
                    2,
                    settings.restore_recent_item,
                    true,
                    None,
                ));
                take(choice(
                    ui,
                    state,
                    START_LIST_ROW,
                    settings.start_list,
                    &[
                        StartList::None,
                        StartList::RecentlyUsed,
                        StartList::RecentlyEdited,
                        StartList::RecentlyCreated,
                    ]
                    .map(|list| (list, list.label())),
                    SearchAction::SetStartList,
                ));
                section(ui, "Keyboard shortcuts");
                let response = state
                    .shortcut_setup
                    .draw_row(ui, state.settings_selected == SHORTCUT_ROW);
                focus(state, SHORTCUT_ROW, &response);
                if response.clicked() {
                    state.settings_selected = SHORTCUT_ROW;
                    state.shortcut_setup.activate();
                }
                take(switch(
                    ui,
                    state,
                    settings,
                    0,
                    settings.show_keyboard_shortcuts,
                    true,
                    None,
                ));
                section(ui, "Display");
                take(switch(
                    ui,
                    state,
                    settings,
                    4,
                    settings.show_website_icons,
                    true,
                    None,
                ));
            }
            SettingsGroup::Security => {
                section(ui, "Locking");
                take(switch(
                    ui,
                    state,
                    settings,
                    6,
                    settings.lock_on_system_lock,
                    true,
                    None,
                ));
                take(switch(
                    ui,
                    state,
                    settings,
                    IDLE_TIMEOUT_ROW,
                    settings.lock_after_idle_timeout,
                    true,
                    None,
                ));
                take(search::draw_idle_timeout(ui, settings));
                section(ui, "Offline access");
                take(switch(
                    ui,
                    state,
                    settings,
                    9,
                    settings.keep_offline_copy,
                    true,
                    None,
                ));
                section(ui, "Privacy");
                let available = crate::screen_capture::available();
                take(switch(
                    ui,
                    state,
                    settings,
                    SCREEN_CAPTURE_ROW,
                    settings.obscure_screen_capture && available,
                    available && !state.capture_pending,
                    Some(if state.capture_pending {
                        "Applying screen capture preference…"
                    } else if available {
                        "Hide this window in screenshots and screen sharing"
                    } else {
                        "Capture protection is unavailable on this desktop"
                    }),
                ));
            }
            SettingsGroup::Browser => {
                section(ui, "Browser integration");
                take(switch(
                    ui,
                    state,
                    settings,
                    10,
                    settings.browser_integration_enabled,
                    true,
                    None,
                ));
                section(ui, "Filling");
                take(choice(
                    ui,
                    state,
                    DEFAULT_URI_MATCH_ROW,
                    settings.default_uri_match,
                    &[
                        (UriMatchType::Host, "Exact host and port"),
                        (UriMatchType::Domain, "Base domain"),
                        (UriMatchType::Exact, "Exact URL"),
                        (UriMatchType::Never, "Never"),
                    ],
                    SearchAction::SetDefaultUriMatch,
                ));
                take(choice(
                    ui,
                    state,
                    PASSKEY_VERIFICATION_ROW,
                    settings.passkey_verification,
                    &[
                        PasskeyVerification::Always,
                        PasskeyVerification::WhenRequired,
                        PasskeyVerification::VaultUnlock,
                    ]
                    .map(|verification| (verification, verification.label())),
                    SearchAction::SetPasskeyVerification,
                ));
                section(ui, "Browsers");
                take(link(
                    ui,
                    state,
                    PAIRED_BROWSERS_ROW,
                    SearchAction::OpenPairedBrowsers,
                ));
                take(link(
                    ui,
                    state,
                    BROWSER_SETUP_ROW,
                    SearchAction::OpenBrowserSetup,
                ));
            }
            SettingsGroup::Ssh => {
                section(ui, "SSH agent");
                take(switch(
                    ui,
                    state,
                    settings,
                    8,
                    settings.ssh_agent_enabled,
                    !cfg!(windows),
                    cfg!(windows).then_some(
                        "Unavailable in the Windows preview; SSH items remain accessible",
                    ),
                ));
                take(search::draw_ssh_socket_path(
                    ui,
                    state,
                    settings,
                    ssh_agent_status,
                ));
                if !cfg!(windows)
                    && settings.ssh_agent_enabled
                    && let Ok(socket) =
                        crate::config::expand_ssh_agent_socket_path(&settings.ssh_agent_socket_path)
                {
                    section(ui, "Use with SSH");
                    ui.label(
                        RichText::new(
                            "Add the first snippet to ~/.ssh/config so every ssh command, \
                             including apps not started from a terminal, uses Boltwarden's keys. \
                             The shell lines cover only programs started from that shell.",
                        )
                        .size(theme().small())
                        .color(theme().text_muted),
                    );
                    ui.add_space(6.0);
                    for (label, code) in ssh_snippets(&socket) {
                        widgets::code_block(ui, label, &code);
                    }
                }
            }
        }
    });
    action
}

/// Scrolls a row into view once when keyboard selection reaches it.
fn focus(state: &mut SearchState, row: usize, response: &egui::Response) {
    if state.settings_selected == row && state.settings_scrolled_to != Some(row) {
        response.scroll_to_me(None);
        state.settings_scrolled_to = Some(row);
    }
}

fn switch(
    ui: &mut Ui,
    state: &mut SearchState,
    settings: &AppSettings,
    row: usize,
    on: bool,
    enabled: bool,
    description: Option<&str>,
) -> Option<SearchAction> {
    let (title, default_description) = SETTING_TEXT[row];
    let response = ui
        .add_enabled_ui(enabled, |ui| {
            widgets::toggle_row(
                ui,
                state.settings_selected == row,
                on,
                title,
                description.unwrap_or(default_description),
            )
        })
        .inner;
    focus(state, row, &response);
    if !response.clicked() {
        return None;
    }
    state.settings_selected = row;
    search::toggle_setting(row, settings)
}

/// A setting with a few values, chosen from a dropdown. Space on the row still cycles them.
fn choice<T: Copy + PartialEq>(
    ui: &mut Ui,
    state: &mut SearchState,
    row: usize,
    current: T,
    options: &[(T, &str)],
    action: fn(T) -> SearchAction,
) -> Option<SearchAction> {
    let t = theme();
    let (title, description) = SETTING_TEXT[row];
    let selected = state.settings_selected == row;
    let (rect, response) = widgets::row(ui, selected, widgets::ROW_HEIGHT + 4.0);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::ComboBox, ui.is_enabled(), title)
    });
    let painter = ui.painter_at(rect);
    let left = rect.left() + 54.0;
    painter.text(
        egui::pos2(left, rect.top() + 7.0),
        egui::Align2::LEFT_TOP,
        title,
        t.font(t.body()),
        if selected {
            t.selected_text
        } else {
            t.text_strong
        },
    );
    painter.text(
        egui::pos2(left, rect.bottom() - 7.0),
        egui::Align2::LEFT_BOTTOM,
        description,
        t.font(t.small()),
        t.text_muted,
    );
    let mut chosen = current;
    let label = options
        .iter()
        .find(|(value, _)| *value == current)
        .map_or("Custom", |(_, label)| label);
    let combo_rect = egui::Rect::from_min_max(
        egui::pos2(rect.right() - 230.0, rect.top()),
        egui::pos2(rect.right() - 12.0, rect.bottom()),
    );
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(combo_rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
        |ui| {
            egui::ComboBox::from_id_salt(("settings-choice", row))
                .selected_text(label)
                .width(180.0)
                .show_ui(ui, |ui| {
                    for (value, label) in options {
                        ui.selectable_value(&mut chosen, *value, *label);
                    }
                });
        },
    );
    focus(state, row, &response);
    if response.clicked() {
        state.settings_selected = row;
    }
    if chosen != current {
        state.settings_selected = row;
        return Some(action(chosen));
    }
    None
}

/// A row that opens another page.
fn link(
    ui: &mut Ui,
    state: &mut SearchState,
    row: usize,
    open: SearchAction,
) -> Option<SearchAction> {
    let (title, description) = SETTING_TEXT[row];
    let response = widgets::choice_row(
        ui,
        state.settings_selected == row,
        title,
        description,
        "Manage",
    );
    focus(state, row, &response);
    response.clicked().then(|| {
        state.settings_selected = row;
        open
    })
}

/// Configuration that points SSH clients at the agent socket.
fn ssh_snippets(socket: &std::path::Path) -> [(&'static str, String); 3] {
    let path = socket.display().to_string();
    let config_path = path.replace('\\', "\\\\").replace('"', "\\\"");
    let shell_path = format!("'{}'", path.replace('\'', "'\\''"));
    [
        (
            "~/.ssh/config",
            format!("Host *\n    IdentityAgent \"{config_path}\""),
        ),
        ("bash or zsh", format!("export SSH_AUTH_SOCK={shell_path}")),
        ("fish", format!("set -gx SSH_AUTH_SOCK {shell_path}")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_snippets_quote_the_socket_path_for_each_format() {
        let [config, posix, fish] =
            ssh_snippets(std::path::Path::new("/Users/me/My Keys/it's.sock"));
        assert_eq!(
            config.1,
            "Host *\n    IdentityAgent \"/Users/me/My Keys/it's.sock\""
        );
        assert_eq!(
            posix.1,
            "export SSH_AUTH_SOCK='/Users/me/My Keys/it'\\''s.sock'"
        );
        assert_eq!(
            fish.1,
            "set -gx SSH_AUTH_SOCK '/Users/me/My Keys/it'\\''s.sock'"
        );
    }
}
