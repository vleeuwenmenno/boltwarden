//! Building blocks of the vault window: the sidebar with the folder tree, the item list
//! and the action center.

use crate::icons::IconCache;
use crate::model::{BwItem, Folder, HealthCheck, HealthReport, ItemState};
use crate::ui::theme::theme;
use crate::ui::widgets;
use egui::{Color32, RichText, Ui};
use std::collections::{HashMap, HashSet};

const SIDEBAR_ROW_HEIGHT: f32 = 32.0;
const LIST_ROW_HEIGHT: f32 = 52.0;
const FOLDER_INDENT: f32 = 16.0;
const CARD_MIN_WIDTH: f32 = 270.0;
const CARD_HEIGHT: f32 = 196.0;
const CARD_GAP: f32 = 12.0;

/// What the item list shows, picked in the sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Section {
    All,
    Favorites,
    /// A folder by its full path, including its subfolders.
    Folder(String),
    NoFolder,
    ActionCenter,
    /// The items one action center check found.
    Health(HealthCheck),
    Archived,
    Trash,
}

impl Section {
    pub fn item_state(&self) -> ItemState {
        match self {
            Self::Archived => ItemState::Archived,
            Self::Trash => ItemState::Deleted,
            _ => ItemState::Active,
        }
    }

    pub fn title(&self) -> String {
        match self {
            Self::All => "All items".into(),
            Self::Favorites => "Favorites".into(),
            Self::Folder(path) => path.rsplit('/').next().unwrap_or(path).to_string(),
            Self::NoFolder => "No folder".into(),
            Self::ActionCenter => "Action center".into(),
            Self::Health(check) => check.title().into(),
            Self::Archived => "Archived".into(),
            Self::Trash => "Recently deleted".into(),
        }
    }

    /// Whether `item` belongs in this section. `paths` maps folder ids to folder paths.
    pub fn contains(
        &self,
        item: &BwItem,
        paths: &HashMap<String, String>,
        report: Option<&HealthReport>,
    ) -> bool {
        match self {
            Self::All | Self::Archived | Self::Trash => true,
            Self::Favorites => item.favorite,
            Self::Folder(path) => item_path(item, paths).is_some_and(|p| in_folder(p, path)),
            Self::NoFolder => item_path(item, paths).is_none(),
            Self::ActionCenter => false,
            Self::Health(check) => {
                report.is_some_and(|report| report.items(*check).contains(&item.id))
            }
        }
    }
}

fn item_path<'a>(item: &BwItem, paths: &'a HashMap<String, String>) -> Option<&'a str> {
    item.folder_id
        .as_ref()
        .and_then(|id| paths.get(id))
        .map(String::as_str)
}

/// Whether a folder path is `folder` itself or one of its subfolders.
pub fn in_folder(path: &str, folder: &str) -> bool {
    path == folder
        || path
            .strip_prefix(folder)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// One level of the folder tree. Bitwarden has no real nesting: "Work/Servers" is a
/// folder named with a slash. A parent that doesn't exist as a folder still gets a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderNode {
    pub name: String,
    pub path: String,
    pub children: Vec<FolderNode>,
}

pub fn folder_tree(folders: &[Folder]) -> Vec<FolderNode> {
    let mut roots: Vec<FolderNode> = Vec::new();
    let mut names = folders
        .iter()
        .map(|folder| folder.name.trim_matches('/'))
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    names.sort_by_key(|name| name.to_lowercase());
    for name in names {
        let mut level = &mut roots;
        let mut path = String::new();
        for part in name.split('/').filter(|part| !part.is_empty()) {
            if !path.is_empty() {
                path.push('/');
            }
            path.push_str(part);
            let idx = match level.iter().position(|node| node.name == part) {
                Some(idx) => idx,
                None => {
                    level.push(FolderNode {
                        name: part.to_string(),
                        path: path.clone(),
                        children: Vec::new(),
                    });
                    level.len() - 1
                }
            };
            level = &mut level[idx].children;
        }
    }
    roots
}

/// Folder id to its path, with stray slashes trimmed the same way as in the tree.
pub fn folder_paths(folders: &[Folder]) -> HashMap<String, String> {
    folders
        .iter()
        .map(|folder| (folder.id.clone(), folder.name.trim_matches('/').to_string()))
        .collect()
}

/// Item counts shown next to the sidebar entries.
#[derive(Debug, Default)]
pub struct SidebarCounts {
    pub all: usize,
    pub favorites: usize,
    pub no_folder: usize,
    /// Items with at least one risk, once the action center has run.
    pub risks: Option<usize>,
    /// Per folder path, including subfolders.
    pub folders: HashMap<String, usize>,
}

impl SidebarCounts {
    pub fn new(
        items: &[BwItem],
        paths: &HashMap<String, String>,
        tree: &[FolderNode],
        report: Option<&HealthReport>,
    ) -> Self {
        let mut counts = Self {
            all: items.len(),
            favorites: items.iter().filter(|item| item.favorite).count(),
            risks: report.map(|report| {
                report
                    .findings
                    .iter()
                    .filter(|(check, _)| check.is_risk())
                    .flat_map(|(_, ids)| ids)
                    .collect::<HashSet<_>>()
                    .len()
            }),
            ..Self::default()
        };
        fn walk(node: &FolderNode, out: &mut Vec<String>) {
            out.push(node.path.clone());
            node.children.iter().for_each(|child| walk(child, out));
        }
        let mut all_paths = Vec::new();
        tree.iter().for_each(|node| walk(node, &mut all_paths));
        for item in items {
            match item_path(item, paths) {
                Some(path) => {
                    for folder in all_paths.iter().filter(|folder| in_folder(path, folder)) {
                        *counts.folders.entry(folder.clone()).or_default() += 1;
                    }
                }
                None => counts.no_folder += 1,
            }
        }
        counts
    }
}

/// What is carried while an item is dragged from the list onto the sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraggedItem {
    pub id: String,
    pub name: String,
}

/// Where a dragged item was dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropTarget {
    /// A folder by path. The folder may only exist as the parent of other folders.
    Folder(String),
    NoFolder,
    Favorites,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidebarAction {
    Open(Section),
    Drop {
        item_id: String,
        target: DropTarget,
    },
    /// Create a folder, inside `parent` when given.
    NewFolder {
        parent: Option<String>,
    },
    RenameFolder(String),
    DeleteFolder(String),
}

pub fn draw_sidebar(
    ui: &mut Ui,
    section: &Section,
    tree: &[FolderNode],
    collapsed: &mut HashSet<String>,
    counts: &SidebarCounts,
) -> Option<SidebarAction> {
    let t = theme();
    let mut action = None;
    egui::ScrollArea::vertical()
        .id_salt("vault-sidebar")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::All,
                t.icon("\u{f0c9}", "☰"),
                Some(counts.all),
                None,
            ) {
                action = Some(picked);
            }
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::Favorites,
                t.icon("\u{f005}", "★"),
                Some(counts.favorites),
                Some(DropTarget::Favorites),
            ) {
                action = Some(picked);
            }
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::ActionCenter,
                t.icon("\u{f132}", "🛡"),
                counts.risks.filter(|risks| *risks > 0),
                None,
            ) {
                action = Some(picked);
            }

            if heading(ui, "FOLDERS", Some("New folder")) {
                action = Some(SidebarAction::NewFolder { parent: None });
            }
            for node in tree {
                if let Some(picked) = folder_rows(ui, node, 0, section, collapsed, counts) {
                    action = Some(picked);
                }
            }
            // Always shown: it is where items go when dragged out of their folder.
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::NoFolder,
                t.icon("\u{f114}", "📁"),
                Some(counts.no_folder),
                Some(DropTarget::NoFolder),
            ) {
                action = Some(picked);
            }

            heading(ui, "MORE", None);
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::Archived,
                t.icon("\u{f187}", "🗄"),
                None,
                None,
            ) {
                action = Some(picked);
            }
            if let Some(picked) = section_entry(
                ui,
                section,
                Section::Trash,
                t.icon("\u{f1f8}", "🗑"),
                None,
                None,
            ) {
                action = Some(picked);
            }
        });
    action
}

fn section_entry(
    ui: &mut Ui,
    current: &Section,
    target: Section,
    icon: &str,
    count: Option<usize>,
    drop: Option<DropTarget>,
) -> Option<SidebarAction> {
    let label = target.title();
    let response = sidebar_row(ui, current == &target, 0, None, icon, &label, count);
    if let Some(drop) = drop
        && let Some(item) = accept_drop(ui, &response)
    {
        return Some(SidebarAction::Drop {
            item_id: item.id.clone(),
            target: drop,
        });
    }
    response.clicked().then_some(SidebarAction::Open(target))
}

/// A section heading, with a "+" button when `add` names what it adds. Returns
/// whether the button was clicked.
fn heading(ui: &mut Ui, text: &str, add: Option<&str>) -> bool {
    let t = theme();
    let mut clicked = false;
    ui.add_space(12.0);
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(RichText::new(text).size(t.small()).color(t.text_faint));
        if let Some(tooltip) = add {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(4.0);
                clicked = ui
                    .add(
                        egui::Button::new(
                            RichText::new(t.icon("\u{f067}", "+"))
                                .size(t.small())
                                .color(t.text_muted),
                        )
                        .frame(false),
                    )
                    .on_hover_text(tooltip)
                    .clicked();
            });
        }
    });
    ui.add_space(2.0);
    clicked
}

/// Highlights a sidebar row while an item hovers over it; returns the item dropped on it.
fn accept_drop(ui: &Ui, response: &egui::Response) -> Option<std::sync::Arc<DraggedItem>> {
    let t = theme();
    response.dnd_hover_payload::<DraggedItem>()?;
    ui.painter().rect_stroke(
        response.rect,
        t.rounding as f32,
        egui::Stroke::new(2.0_f32, t.accent),
        egui::StrokeKind::Inside,
    );
    response.dnd_release_payload::<DraggedItem>()
}

fn folder_rows(
    ui: &mut Ui,
    node: &FolderNode,
    depth: usize,
    section: &Section,
    collapsed: &mut HashSet<String>,
    counts: &SidebarCounts,
) -> Option<SidebarAction> {
    let t = theme();
    let is_collapsed = collapsed.contains(&node.path);
    let expander = (!node.children.is_empty()).then_some(!is_collapsed);
    let selected = matches!(section, Section::Folder(path) if *path == node.path);
    let icon = if node.children.is_empty() || is_collapsed {
        t.icon("\u{f07b}", "📁")
    } else {
        t.icon("\u{f07c}", "📂")
    };
    let response = sidebar_row(
        ui,
        selected,
        depth,
        expander,
        icon,
        &node.name,
        counts.folders.get(&node.path).copied(),
    );
    let mut picked = None;
    // The chevron toggles the subtree; the rest of the row opens the folder.
    let on_chevron = response.interact_pointer_pos().is_some_and(|pos| {
        pos.x < response.rect.left() + 10.0 + depth as f32 * FOLDER_INDENT + 18.0
    });
    if let Some(item) = accept_drop(ui, &response) {
        picked = Some(SidebarAction::Drop {
            item_id: item.id.clone(),
            target: DropTarget::Folder(node.path.clone()),
        });
    } else if response.clicked() {
        if expander.is_some() && on_chevron {
            if !collapsed.remove(&node.path) {
                collapsed.insert(node.path.clone());
            }
        } else {
            picked = Some(SidebarAction::Open(Section::Folder(node.path.clone())));
        }
    }
    response.context_menu(|ui| {
        let mut item = |ui: &mut Ui, label: &str, action: SidebarAction| {
            if ui.button(label).clicked() {
                picked = Some(action);
                ui.close();
            }
        };
        item(
            ui,
            "New subfolder…",
            SidebarAction::NewFolder {
                parent: Some(node.path.clone()),
            },
        );
        item(
            ui,
            "Rename…",
            SidebarAction::RenameFolder(node.path.clone()),
        );
        item(
            ui,
            "Delete…",
            SidebarAction::DeleteFolder(node.path.clone()),
        );
    });
    if !is_collapsed {
        for child in &node.children {
            if let Some(action) = folder_rows(ui, child, depth + 1, section, collapsed, counts) {
                picked = Some(action);
            }
        }
    }
    picked
}

/// A sidebar entry. `expander` is `Some(expanded)` for folders with subfolders.
fn sidebar_row(
    ui: &mut Ui,
    selected: bool,
    depth: usize,
    expander: Option<bool>,
    icon: &str,
    label: &str,
    count: Option<usize>,
) -> egui::Response {
    let t = theme();
    let (rect, response) = widgets::row(ui, selected, SIDEBAR_ROW_HEIGHT);
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::SelectableLabel,
            ui.is_enabled(),
            selected,
            label,
        )
    });
    let painter = ui.painter_at(rect);
    let mut x = rect.left() + 10.0 + depth as f32 * FOLDER_INDENT;
    let color = if selected {
        t.selected_text
    } else {
        t.text_muted
    };
    if let Some(expanded) = expander {
        painter.text(
            egui::pos2(x + 5.0, rect.center().y),
            egui::Align2::CENTER_CENTER,
            if expanded {
                t.icon("\u{f107}", "▾")
            } else {
                t.icon("\u{f105}", "▸")
            },
            t.font(t.small()),
            t.text_faint,
        );
    }
    if depth > 0 || expander.is_some() {
        x += 14.0;
    }
    painter.text(
        egui::pos2(x + 8.0, rect.center().y),
        egui::Align2::CENTER_CENTER,
        icon,
        t.font(t.body()),
        color,
    );
    let count_width = count
        .map(|count| {
            let galley = painter.layout_no_wrap(count.to_string(), t.font(t.small()), t.text_faint);
            let width = galley.size().x;
            painter.galley(
                egui::pos2(
                    rect.right() - 10.0 - width,
                    rect.center().y - galley.size().y / 2.0,
                ),
                galley,
                t.text_faint,
            );
            width + 16.0
        })
        .unwrap_or(10.0);
    let text_left = x + 24.0;
    let mut job = egui::text::LayoutJob::single_section(
        label.to_string(),
        egui::TextFormat::simple(
            t.font(t.body()),
            if selected {
                t.selected_text
            } else {
                t.text_strong
            },
        ),
    );
    job.wrap = egui::text::TextWrapping::truncate_at_width(
        (rect.right() - count_width - text_left).max(20.0),
    );
    let galley = painter.layout_job(job);
    painter.galley(
        egui::pos2(text_left, rect.center().y - galley.size().y / 2.0),
        galley,
        t.text_strong,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// How the item list is ordered while no search is typed. A search keeps relevance order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOrder {
    Name,
    Modified,
    Created,
}

impl ListOrder {
    const ALL: [Self; 3] = [Self::Name, Self::Modified, Self::Created];

    fn label(self) -> &'static str {
        match self {
            Self::Name => "Name",
            Self::Modified => "Last edited",
            Self::Created => "Date created",
        }
    }

    pub fn sort(self, items: &mut [&BwItem]) {
        let name = |item: &BwItem| item.name.to_lowercase();
        items.sort_by(|a, b| {
            match self {
                Self::Name => std::cmp::Ordering::Equal,
                Self::Modified => b.dates.revision_date.cmp(&a.dates.revision_date),
                Self::Created => b.dates.creation_date.cmp(&a.dates.creation_date),
            }
            .then_with(|| name(a).cmp(&name(b)))
        });
    }
}

/// The list's header: section name, item count and the order picker.
pub fn draw_list_header(ui: &mut Ui, title: &str, count: usize, order: &mut ListOrder) {
    let t = theme();
    ui.horizontal(|ui| {
        ui.add(
            egui::Label::new(RichText::new(title).size(t.title()).color(t.text_strong)).truncate(),
        );
        ui.label(RichText::new(count.to_string()).color(t.text_faint));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            egui::ComboBox::from_id_salt("vault-list-order")
                .width(110.0)
                .selected_text(RichText::new(order.label()).color(t.text_muted))
                .show_ui(ui, |ui| {
                    for option in ListOrder::ALL {
                        ui.selectable_value(order, option, option.label());
                    }
                });
        });
    });
}

/// Returns the index of a clicked row.
pub fn draw_item_list(
    ui: &mut Ui,
    items: &[&BwItem],
    selected: Option<usize>,
    scroll_to_selected: bool,
    icons: &mut IconCache,
) -> Option<usize> {
    let t = theme();
    let mut clicked = None;
    if let Some(host) = selected
        .and_then(|idx| items.get(idx))
        .and_then(|item| item.icon_host.as_deref())
    {
        icons.get(host);
    }
    egui::ScrollArea::vertical()
        .id_salt("vault-items")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            for (idx, item) in items.iter().enumerate() {
                let is_selected = selected == Some(idx);
                let (rect, response) = widgets::row(ui, is_selected, LIST_ROW_HEIGHT);
                // Rows drag onto sidebar folders; a click without moving still selects.
                let response = response.interact(egui::Sense::drag());
                response.dnd_set_drag_payload(DraggedItem {
                    id: item.id.clone(),
                    name: item.name.clone(),
                });
                response.widget_info(|| {
                    egui::WidgetInfo::selected(
                        egui::WidgetType::SelectableLabel,
                        true,
                        is_selected,
                        &item.name,
                    )
                });
                if is_selected && scroll_to_selected {
                    ui.scroll_to_rect(rect, None);
                }
                if !ui.is_rect_visible(rect) {
                    continue;
                }
                let image = item.icon_host.as_deref().and_then(|host| icons.get(host));
                paint_item_row(ui, rect, item, image.as_ref(), is_selected);
                if response.clicked() {
                    clicked = Some(idx);
                }
            }
            if items.is_empty() {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("No items").color(t.text_muted));
                });
            }
        });
    clicked
}

fn paint_item_row(
    ui: &Ui,
    rect: egui::Rect,
    item: &BwItem,
    image: Option<&egui::TextureHandle>,
    selected: bool,
) {
    let t = theme();
    let painter = ui.painter_at(rect);
    let tile = egui::Rect::from_center_size(
        egui::pos2(rect.left() + 26.0, rect.center().y),
        egui::vec2(32.0, 32.0),
    );
    painter.rect_filled(tile, t.rounding.min(8) as f32, t.surface);
    match image {
        Some(texture) => {
            painter.image(
                texture.id(),
                egui::Rect::from_center_size(tile.center(), egui::vec2(22.0, 22.0)),
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                Color32::WHITE,
            );
        }
        None => {
            painter.text(
                tile.center(),
                egui::Align2::CENTER_CENTER,
                t.item_icon(&item.item_type),
                t.font(t.body()),
                t.text_muted,
            );
        }
    }

    let left = tile.right() + 12.0;
    let mut right = rect.right() - 10.0;
    if item.favorite {
        painter.text(
            egui::pos2(right, rect.center().y),
            egui::Align2::RIGHT_CENTER,
            t.icon("\u{f005}", "★"),
            t.font(t.small()),
            t.warning,
        );
        right -= 20.0;
    }
    let max_width = (right - left).max(40.0);
    let line = |text: &str, size: f32, color: Color32| {
        let mut job = egui::text::LayoutJob::single_section(
            text.to_string(),
            egui::TextFormat::simple(t.font(size), color),
        );
        job.wrap = egui::text::TextWrapping::truncate_at_width(max_width);
        painter.layout_job(job)
    };
    let title = line(
        &item.name,
        t.body(),
        if selected {
            t.selected_text
        } else {
            t.text_strong
        },
    );
    let secondary = item
        .username
        .as_deref()
        .filter(|username| !username.is_empty())
        .or(item.folder.as_deref())
        .unwrap_or("—");
    let subtitle = line(secondary, t.small(), t.text_muted);
    let total = title.size().y + 2.0 + subtitle.size().y;
    let top = rect.center().y - total / 2.0;
    let title_height = title.size().y;
    painter.galley(egui::pos2(left, top), title, t.text_strong);
    painter.galley(
        egui::pos2(left, top + title_height + 2.0),
        subtitle,
        t.text_muted,
    );
}

/// Follows the pointer with the name of the item being dragged.
pub fn draw_drag_preview(ctx: &egui::Context) {
    let t = theme();
    let (Some(item), Some(pointer)) = (
        egui::DragAndDrop::payload::<DraggedItem>(ctx),
        ctx.pointer_interact_pos(),
    ) else {
        return;
    };
    egui::Area::new(egui::Id::new("vault-drag-preview"))
        .order(egui::Order::Tooltip)
        .fixed_pos(pointer + egui::vec2(14.0, 10.0))
        .interactable(false)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(t.selected_bg)
                .stroke(egui::Stroke::new(1.0_f32, t.accent))
                .corner_radius(t.rounding)
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("{}  {}", t.icon("\u{f07b}", "📁"), item.name))
                            .color(t.selected_text),
                    );
                });
        });
    ctx.set_cursor_icon(egui::CursorIcon::Grabbing);
}

/// A modal asking for a folder name. `Some(true)` saves, `Some(false)` cancels.
pub fn folder_name_dialog(
    ctx: &egui::Context,
    title: &str,
    hint: &str,
    name: &mut String,
    busy: bool,
    error: Option<&str>,
) -> Option<bool> {
    let t = theme();
    let mut result = None;
    let input_id = egui::Id::new("vault-folder-name");
    if !busy {
        ctx.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                result = Some(false);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Enter) {
                result = Some(true);
            }
        });
    }
    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .title_bar(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .frame(
            egui::Frame::window(&ctx.global_style())
                .fill(t.bg)
                .stroke(egui::Stroke::new(1.0_f32, t.accent))
                .inner_margin(egui::Margin::same(16)),
        )
        .show(ctx, |ui| {
            ui.set_width(380.0);
            ui.label(RichText::new(title).size(t.title()).color(t.text_strong));
            ui.add_space(4.0);
            ui.label(RichText::new(hint).size(t.small()).color(t.text_muted));
            ui.add_space(8.0);
            let response = ui
                .add_enabled_ui(!busy, |ui| {
                    widgets::text_input(ui, input_id, name, "Folder name", false, t.body())
                })
                .inner;
            if !busy && !ui.memory(|m| m.has_focus(input_id)) {
                response.request_focus();
            }
            if let Some(error) = error {
                ui.add_space(6.0);
                widgets::error_line(ui, error);
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if widgets::button(ui, "Cancel", false, !busy).clicked() {
                    result = Some(false);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if widgets::button(ui, "Save", true, !busy && !name.trim().is_empty()).clicked()
                    {
                        result = Some(true);
                    }
                    if busy {
                        ui.add(egui::Spinner::new().color(t.text_muted));
                    }
                });
            });
        });
    result
}

/// New full names for renaming the folder at `path` to `new_path`: the folder itself,
/// when it exists, and every subfolder, since nesting is only a name prefix.
pub fn folder_renames(folders: &[Folder], path: &str, new_path: &str) -> Vec<(String, String)> {
    folders
        .iter()
        .filter_map(|folder| {
            let name = folder.name.trim_matches('/');
            in_folder(name, path).then(|| {
                (
                    folder.id.clone(),
                    format!("{new_path}{}", &name[path.len()..]),
                )
            })
        })
        .collect()
}

/// Ids of the folder at `path` and all its subfolders.
pub fn folder_subtree(folders: &[Folder], path: &str) -> Vec<String> {
    folders
        .iter()
        .filter(|folder| in_folder(folder.name.trim_matches('/'), path))
        .map(|folder| folder.id.clone())
        .collect()
}

/// The action center. Returns the check whose items should be listed.
pub fn draw_action_center(
    ui: &mut Ui,
    report: Option<&HealthReport>,
    loading: bool,
    error: Option<&str>,
) -> Option<HealthCheck> {
    let t = theme();
    let mut picked = None;
    egui::ScrollArea::vertical()
        .id_salt("vault-action-center")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add_space(8.0);
            let Some(report) = report else {
                match error {
                    Some(error) => widgets::error_line(ui, error),
                    None if loading => widgets::empty_state(ui, "", "Checking your vault…", true),
                    None => {}
                }
                return;
            };

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - 200.0).max(240.0));
                    ui.label(
                        RichText::new(format!("{}  Action center", t.icon("\u{f132}", "🛡")))
                            .size(t.title() + 4.0)
                            .color(t.text_strong),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new(
                            "Problems and suggestions for the logins in your vault. The score \
                             is the share of passwords that are strong, unique and only sent \
                             over https.",
                        )
                        .color(t.text_muted),
                    );
                    if loading {
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().color(t.text_muted));
                            ui.label(RichText::new("Updating…").color(t.text_faint));
                        });
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    draw_score_gauge(ui, report);
                });
            });
            ui.add_space(12.0);
            draw_strength(ui, report);
            ui.add_space(CARD_GAP);

            let width = ui.available_width();
            let columns = (((width + CARD_GAP) / (CARD_MIN_WIDTH + CARD_GAP)) as usize).max(1);
            let card_width = (width - CARD_GAP * (columns - 1) as f32) / columns as f32;
            for row in HealthCheck::ALL.chunks(columns) {
                let (row_rect, _) =
                    ui.allocate_exact_size(egui::vec2(width, CARD_HEIGHT), egui::Sense::hover());
                for (col, check) in row.iter().enumerate() {
                    let rect = egui::Rect::from_min_size(
                        row_rect.min + egui::vec2(col as f32 * (card_width + CARD_GAP), 0.0),
                        egui::vec2(card_width, CARD_HEIGHT),
                    );
                    let count = report.items(*check).len();
                    let unavailable = matches!(
                        check,
                        HealthCheck::TwoFactorAvailable | HealthCheck::PasskeysAvailable
                    ) && report.directory_error.is_some();
                    if draw_card(ui, rect, *check, count, unavailable) {
                        picked = Some(*check);
                    }
                }
                ui.add_space(CARD_GAP);
            }
            if let Some(error) = &report.directory_error {
                ui.label(
                    RichText::new(format!(
                        "Two-factor and passkey suggestions are unavailable: {error}"
                    ))
                    .size(t.small())
                    .color(t.text_faint),
                );
            } else {
                ui.label(
                    RichText::new(
                        "Two-factor and passkey suggestions use the public lists from \
                         2fa.directory, downloaded whole so no vault data is sent.",
                    )
                    .size(t.small())
                    .color(t.text_faint),
                );
            }
            ui.add_space(8.0);
        });
    picked
}

/// Score band with its status color and label. Status always travels with a label.
fn score_band(score: u8) -> (&'static str, Color32) {
    let t = theme();
    match score {
        90.. => ("Excellent", t.success),
        75..=89 => ("Good", t.success),
        50..=74 => ("Fair", t.warning),
        _ => ("Poor", t.danger),
    }
}

fn draw_score_gauge(ui: &mut Ui, report: &HealthReport) {
    let t = theme();
    let size = egui::vec2(180.0, 132.0);
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let center = egui::pos2(rect.center().x, rect.top() + 82.0);
    let radius = 70.0;
    // A 240° arc opening downward, filled clockwise from the lower left.
    let start = 150f32.to_radians();
    let sweep = 240f32.to_radians();
    let arc = |from: f32, to: f32| {
        let steps = 48;
        (0..=steps)
            .map(|i| {
                let angle = from + (to - from) * i as f32 / steps as f32;
                center + radius * egui::vec2(angle.cos(), angle.sin())
            })
            .collect::<Vec<_>>()
    };
    let (label, color) = score_band(report.score);
    painter.line(
        arc(start, start + sweep),
        egui::Stroke::new(10.0, t.separator),
    );
    let filled = sweep * f32::from(report.score) / 100.0;
    if filled > 0.0 {
        painter.line(arc(start, start + filled), egui::Stroke::new(10.0, color));
    }
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        report.score.to_string(),
        t.font(t.title() * 2.0),
        t.text_strong,
    );
    painter.text(
        center + egui::vec2(0.0, t.title() + 8.0),
        egui::Align2::CENTER_CENTER,
        label.to_uppercase(),
        t.font(t.small()),
        t.text_muted,
    );
    response.on_hover_text(format!(
        "{}% of {} passwords have no problems",
        report.score, report.passwords
    ));
}

/// Stacked bar of how many passwords got each strength score, weakest first.
fn draw_strength(ui: &mut Ui, report: &HealthReport) {
    let t = theme();
    let buckets = [
        ("Very weak", t.danger),
        ("Weak", mix(t.danger, t.warning, 0.5)),
        ("Fair", t.warning),
        ("Good", mix(t.warning, t.success, 0.6)),
        ("Strong", t.success),
    ];
    card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new("Password strength")
                .size(t.body())
                .color(t.text_strong),
        );
        ui.add_space(8.0);
        let (bar, _) =
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 12.0), egui::Sense::hover());
        let total = report.strength.iter().sum::<usize>();
        if total == 0 {
            ui.painter().rect_filled(bar, 4.0, t.separator);
        } else {
            let mut x = bar.left();
            for (idx, count) in report.strength.iter().enumerate() {
                if *count == 0 {
                    continue;
                }
                let width = bar.width() * *count as f32 / total as f32;
                // A 2px gap in the card color separates the segments.
                let segment = egui::Rect::from_min_max(
                    egui::pos2(x, bar.top()),
                    egui::pos2((x + width - 2.0).max(x + 1.0), bar.bottom()),
                );
                ui.painter().rect_filled(segment, 4.0, buckets[idx].1);
                let response = ui.interact(
                    segment,
                    ui.id().with(("strength", idx)),
                    egui::Sense::hover(),
                );
                response.on_hover_text(format!(
                    "{}: {count} password{}",
                    buckets[idx].0,
                    if *count == 1 { "" } else { "s" }
                ));
                x += width;
            }
        }
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            for (idx, (label, color)) in buckets.iter().enumerate() {
                let (swatch, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().rect_filled(swatch, 2.0, *color);
                ui.label(
                    RichText::new(format!("{label} {}", report.strength[idx]))
                        .size(t.small())
                        .color(t.text_muted),
                );
                ui.add_space(8.0);
            }
        });
    });
}

fn card_frame() -> egui::Frame {
    let t = theme();
    egui::Frame::new()
        .fill(t.surface)
        .stroke(egui::Stroke::new(1.0_f32, t.separator))
        .corner_radius(t.rounding)
        .inner_margin(egui::Margin::same(14))
}

fn check_icon(check: HealthCheck) -> &'static str {
    let t = theme();
    match check {
        HealthCheck::ReusedPasswords => t.icon("\u{f01e}", "🔁"),
        HealthCheck::WeakPasswords => t.icon("\u{f071}", "⚠"),
        HealthCheck::UnsecuredWebsites => t.icon("\u{f09c}", "🔓"),
        HealthCheck::Duplicates => t.icon("\u{f0c5}", "📄"),
        HealthCheck::Expiring => t.icon("\u{f017}", "⏰"),
        HealthCheck::TwoFactorAvailable => t.icon("\u{f10b}", "📱"),
        HealthCheck::PasskeysAvailable => t.icon("\u{f084}", "🔑"),
    }
}

/// One check as a card; returns whether "Show items" was clicked.
fn draw_card(
    ui: &mut Ui,
    rect: egui::Rect,
    check: HealthCheck,
    count: usize,
    unavailable: bool,
) -> bool {
    let t = theme();
    let mut clicked = false;
    ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
        card_frame().show(ui, |ui| {
            ui.set_min_size(rect.size() - egui::vec2(28.0, 28.0));
            ui.horizontal(|ui| {
                let number = if unavailable {
                    "–".to_string()
                } else {
                    count.to_string()
                };
                ui.label(
                    RichText::new(number)
                        .size(t.title() * 1.8)
                        .color(t.text_strong),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                    ui.label(
                        RichText::new(check_icon(check))
                            .size(t.title())
                            .color(t.text_faint),
                    );
                });
            });
            ui.horizontal(|ui| {
                // Risks that were found carry a status icon, never color alone.
                if check.is_risk() && count > 0 {
                    ui.label(RichText::new(t.icon("\u{f071}", "⚠")).color(t.warning));
                    ui.add_space(2.0);
                }
                ui.label(
                    RichText::new(check.title())
                        .size(t.body())
                        .color(t.text_strong),
                );
            });
            ui.label(
                RichText::new(check.description())
                    .size(t.small())
                    .color(t.text_muted),
            );
            // Pin the link to the bottom edge, below a rule, like the rest of the cards.
            let link_height = 30.0;
            let space = ui.available_height() - link_height;
            if space > 0.0 {
                ui.add_space(space);
            }
            ui.separator();
            {
                let text = format!("Show items  {}", t.icon("\u{f061}", "→"));
                let response = ui.add_enabled(
                    count > 0,
                    egui::Button::new(RichText::new(text).color(if count > 0 {
                        t.accent
                    } else {
                        t.text_faint
                    }))
                    .frame(false),
                );
                clicked = response.clicked();
            }
        });
    });
    clicked
}

fn mix(a: Color32, b: Color32, amount: f32) -> Color32 {
    let lerp = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * amount).round() as u8;
    Color32::from_rgb(lerp(a.r(), b.r()), lerp(a.g(), b.g()), lerp(a.b(), b.b()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: &str, name: &str) -> Folder {
        Folder {
            id: id.into(),
            name: name.into(),
        }
    }

    #[test]
    fn builds_nested_folder_tree_with_implicit_parents() {
        let tree = folder_tree(&[
            folder("1", "Work/Servers"),
            folder("2", "Personal"),
            folder("3", "Work"),
            folder("4", "Homelab/Media/Movies"),
        ]);
        let names = tree
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(names, ["Homelab", "Personal", "Work"]);
        assert_eq!(tree[0].children[0].children[0].path, "Homelab/Media/Movies");
        assert_eq!(tree[2].children[0].path, "Work/Servers");
    }

    fn list_item(id: &str, folder_id: Option<&str>) -> BwItem {
        BwItem {
            id: id.into(),
            name: id.into(),
            username: None,
            folder: None,
            folder_id: folder_id.map(Into::into),
            favorite: false,
            item_type: "login".into(),
            icon_host: None,
            state: ItemState::Active,
            dates: Default::default(),
        }
    }

    /// Runs one frame of the sidebar next to the list; returns the sidebar's action and
    /// where each text was painted.
    fn frame(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        items: &[BwItem],
        folders: &[Folder],
    ) -> (Option<SidebarAction>, Vec<(String, egui::Pos2)>) {
        let tree = folder_tree(folders);
        let paths = folder_paths(folders);
        let counts = SidebarCounts::new(items, &paths, &tree, None);
        let refs = items.iter().collect::<Vec<_>>();
        let mut collapsed = HashSet::new();
        let mut icons = IconCache::new(false);
        let mut action = None;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800., 600.),
            )),
            events,
            ..Default::default()
        };
        let mut out = ctx.run_ui(input, |ui| {
            ui.horizontal_top(|ui| {
                let column = egui::Layout::top_down(egui::Align::Min);
                ui.allocate_ui_with_layout(egui::vec2(230., 580.), column, |ui| {
                    action = draw_sidebar(ui, &Section::All, &tree, &mut collapsed, &counts);
                });
                ui.allocate_ui_with_layout(egui::vec2(330., 580.), column, |ui| {
                    draw_item_list(ui, &refs, None, false, &mut icons);
                });
            });
        });
        out.textures_delta.clear();
        let texts = out
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((text.galley.job.text.clone(), text.pos)),
                _ => None,
            })
            .collect();
        (action, texts)
    }

    #[test]
    fn dragging_an_item_onto_a_folder_moves_it() {
        let ctx = egui::Context::default();
        let folders = [folder("w", "Work"), folder("p", "Personal")];
        let items = [list_item("GitHub", Some("p"))];
        frame(&ctx, Vec::new(), &items, &folders);
        let (_, texts) = frame(&ctx, Vec::new(), &items, &folders);
        let find = |label: &str| {
            texts
                .iter()
                .find(|(text, _)| text == label)
                .map(|(_, pos)| *pos + egui::vec2(4.0, 6.0))
                .unwrap_or_else(|| panic!("{label} not drawn"))
        };
        let (from, to) = (find("GitHub"), find("Work"));
        let button = |pos, pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        let steps = [
            vec![egui::Event::PointerMoved(from)],
            vec![button(from, true)],
            vec![egui::Event::PointerMoved(from + egui::vec2(20.0, 0.0))],
            vec![egui::Event::PointerMoved(to)],
            vec![egui::Event::PointerMoved(to)],
            vec![button(to, false)],
        ];
        let mut dropped = None;
        for events in steps {
            if let (Some(action), _) = frame(&ctx, events, &items, &folders) {
                dropped = Some(action);
            }
        }
        assert_eq!(
            dropped,
            Some(SidebarAction::Drop {
                item_id: "GitHub".into(),
                target: DropTarget::Folder("Work".into()),
            })
        );
    }

    #[test]
    fn renaming_a_folder_renames_its_subfolders() {
        let folders = [
            folder("1", "Work"),
            folder("2", "Work/Servers"),
            folder("3", "Workshop"),
            folder("4", "Home/Work"),
        ];
        assert_eq!(
            folder_renames(&folders, "Work", "Jobs/Acme"),
            [
                ("1".to_string(), "Jobs/Acme".to_string()),
                ("2".to_string(), "Jobs/Acme/Servers".to_string()),
            ]
        );
        assert_eq!(folder_subtree(&folders, "Work"), ["1", "2"]);
        // A parent that is only implied by its subfolders still renames them.
        assert_eq!(
            folder_renames(&[folder("5", "Media/Movies")], "Media", "Video"),
            [("5".to_string(), "Video/Movies".to_string())]
        );
    }

    #[test]
    fn folder_sections_include_subfolders_only() {
        assert!(in_folder("Work", "Work"));
        assert!(in_folder("Work/Servers", "Work"));
        assert!(!in_folder("Workshop", "Work"));
        assert!(!in_folder("Work", "Work/Servers"));
    }

    #[test]
    fn counts_items_per_folder_subtree() {
        let folders = [folder("w", "Work"), folder("s", "Work/Servers")];
        let item = |id: &str, folder_id: Option<&str>, favorite: bool| BwItem {
            id: id.into(),
            name: id.into(),
            username: None,
            folder: None,
            folder_id: folder_id.map(Into::into),
            favorite,
            item_type: "login".into(),
            icon_host: None,
            state: ItemState::Active,
            dates: Default::default(),
        };
        let items = [
            item("a", Some("w"), true),
            item("b", Some("s"), false),
            item("c", None, false),
        ];
        let tree = folder_tree(&folders);
        let counts = SidebarCounts::new(&items, &folder_paths(&folders), &tree, None);
        assert_eq!(counts.all, 3);
        assert_eq!(counts.favorites, 1);
        assert_eq!(counts.no_folder, 1);
        assert_eq!(counts.folders["Work"], 2);
        assert_eq!(counts.folders["Work/Servers"], 1);
    }
}
