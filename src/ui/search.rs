use crate::model::{BwItem, SyncStatus};
use egui::{Context, Ui};

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

    pub fn move_selection(&mut self, delta: i32) {
        if self.results.is_empty() {
            return;
        }
        let len = self.results.len() as i32;
        self.selected = ((self.selected as i32 + delta + len) % len) as usize;
    }
}

pub fn draw_search(
    _ctx: &Context,
    ui: &mut Ui,
    state: &mut SearchState,
) -> Option<SearchAction> {
    let mut action = None;
    ui.input(|i| {
        for event in &i.events {
            let egui::Event::Key { key, pressed, .. } = event else {
                continue;
            };
            if !pressed {
                continue;
            }
            match key {
                egui::Key::ArrowDown => state.move_selection(1),
                egui::Key::ArrowUp => state.move_selection(-1),
                egui::Key::Enter | egui::Key::ArrowRight if !state.results.is_empty() => {
                    action = Some(SearchAction::Open(state.selected));
                }
                egui::Key::Escape => action = Some(SearchAction::Quit),
                _ => {}
            }
        }
    });

    let mut search_field = TextEdit::singleline(&mut state.query)
        .hint_text("Search vault...")
        .font(egui::FontId::proportional(22.0))
        .margin(egui::Margin::symmetric(8, 4))
        .vertical_align(egui::Align::Center)
        .desired_width(f32::INFINITY)
        .interactive(true);

    if state.focus_search {
        search_field = search_field.cursor_at_end(true);
    }

    let search_response = ui.add_sized(
        [ui.available_width(), 42.0],
        search_field,
    );

    if state.focus_search {
        search_response.request_focus();
        state.focus_search = false;
    }

    ui.add_space(8.0);

    if state.in_flight {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Searching...");
        });
    } else if state.query.trim().is_empty() && state.results.is_empty() {
        ui.add_space(2.0);
    } else if state.results.is_empty() && !state.last_query.is_empty() {
        ui.label(
            egui::RichText::new("No results")
                .italics()
                .color(egui::Color32::from_rgb(120, 120, 120)),
        );
    } else {
        egui::ScrollArea::vertical()
            .auto_shrink([false, true])
            .show(ui, |ui| {
                let mut open_idx: Option<usize> = None;
                for (i, item) in state.results.iter().enumerate() {
                    let selected = i == state.selected;
                    let bg = if selected {
                        egui::Color32::from_rgb(60, 90, 140)
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    let frame = egui::Frame::new()
                        .fill(bg)
                        .inner_margin(egui::Margin::symmetric(8, 6))
                        .corner_radius(4.0);

                    let resp = frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let icon = match item.item_type.as_str() {
                                    "login" => "🔑",
                                    "secureNote" => "📝",
                                    "card" => "💳",
                                    "identity" => "👤",
                                    _ => "📦",
                                };
                                ui.label(icon);
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(&item.name).strong(),
                                        );
                                        if let Some(u) = &item.username {
                                            ui.label(
                                                egui::RichText::new(format!("— {u}"))
                                                    .color(egui::Color32::from_rgb(
                                                        150, 150, 150,
                                                    ))
                                                    .small(),
                                            );
                                        }
                                    });
                                    if let Some(folder) = &item.folder {
                                        ui.label(
                                            egui::RichText::new(folder)
                                                .color(egui::Color32::from_rgb(120, 120, 120))
                                                .small(),
                                        );
                                    }
                                });
                            });
                        })
                        .response;

                    if resp.clicked() {
                        open_idx = Some(i);
                    }
                }
                if let Some(idx) = open_idx {
                    action = Some(SearchAction::Open(idx));
                }
            });
    }

    if let Some(e) = &state.error {
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠ {e}"));
    }
    if let Some(warning) = &state.warning {
        ui.colored_label(
            egui::Color32::from_rgb(220, 170, 70),
            format!("⚠ {warning}"),
        );
    }
    if let Some(status) = &state.sync_status {
        ui.label(
            egui::RichText::new(format!(
                "Vault: {} from server, {} decrypted, {} skipped",
                status.server_ciphers, status.decrypted_items, status.skipped_items
            ))
            .small()
            .color(egui::Color32::from_rgb(120, 120, 120)),
        );
        if let Some(error) = &status.first_error {
            ui.colored_label(
                egui::Color32::from_rgb(180, 130, 70),
                egui::RichText::new(format!("First skipped item: {error}")).small(),
            );
        }
    }

    action
}

pub enum SearchAction {
    Open(usize),
    Quit,
}

use egui::TextEdit;
