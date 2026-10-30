//! A deliberately persistent, local-only view. It owns a zeroizing snapshot so item
//! navigation, reprompt expiry and vault idle locking do not dismiss the window.
use crate::ui::theme::theme;
use egui::{Align2, Context, RichText};
use std::sync::mpsc;
use unicode_segmentation::UnicodeSegmentation;
use zeroize::Zeroizing;

pub struct LargePassword {
    title: String,
    value: Zeroizing<String>,
    capture: Option<(bool, mpsc::Receiver<Result<(), String>>)>,
    capture_applied: Option<bool>,
    capture_error: Option<String>,
}

impl LargePassword {
    pub fn new(item: &str, label: &str, value: &str) -> Self {
        Self {
            title: format!("{item} · {label}"),
            value: Zeroizing::new(value.to_owned()),
            capture: None,
            capture_applied: None,
            capture_error: None,
        }
    }

    /// Returns true only on an explicit close action. There is no expiry timer.
    pub fn show(&mut self, ctx: &Context, obscure: bool) -> bool {
        let mut closed = false;
        ctx.show_viewport_immediate(
            egui::ViewportId::from_hash_of("large-password"),
            egui::ViewportBuilder::default()
                .with_title("Large password — Boltwarden")
                .with_app_id(if crate::demo::enabled() {
                    "boltwarden-window-demo"
                } else {
                    "boltwarden-window"
                })
                .with_inner_size([1000.0, 600.0])
                .with_min_inner_size([360.0, 260.0])
                .with_active(true),
            |root, _class| {
                let ctx = root.ctx().clone();
                closed |= ctx.input(|input| input.viewport().close_requested())
                    || ctx.input_mut(|input| {
                        input.consume_key(egui::Modifiers::NONE, egui::Key::Escape)
                    });
                let ready = self.prepare_capture(&ctx, obscure);
                egui::CentralPanel::default().show(root, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(&self.title);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            closed |= ui.button("Close").clicked();
                        });
                    });
                    ui.label(
                        RichText::new("Stays visible until you close this window.")
                            .small()
                            .color(theme().text_muted),
                    );
                    ui.add_space(12.0);
                    if ready {
                        draw_characters(ui, &self.value);
                    } else if let Some(error) = &self.capture_error {
                        ui.colored_label(
                            theme().danger,
                            format!("Could not protect this window: {error}"),
                        );
                        if ui.button("Retry").clicked() {
                            self.capture_error = None;
                        }
                    } else {
                        ui.spinner();
                    }
                });
            },
        );
        closed
    }

    // A native child window needs the same capture policy as its parent. Wait for
    // confirmation before painting secrets; the worker starts after it is mapped.
    fn prepare_capture(&mut self, ctx: &Context, obscure: bool) -> bool {
        if !crate::screen_capture::available() {
            return true;
        }
        if let Some((requested, rx)) = &self.capture {
            match rx.try_recv() {
                Ok(result) => {
                    let requested = *requested;
                    self.capture = None;
                    match result {
                        Ok(()) => self.capture_applied = Some(requested),
                        Err(error) => self.capture_error = Some(error),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.capture = None;
                    self.capture_error = Some("Capture protection worker stopped".into());
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if self.capture_applied == Some(obscure) {
            return true;
        }
        if self.capture.is_none() && self.capture_error.is_none() {
            let (tx, rx) = mpsc::channel();
            self.capture = Some((obscure, rx));
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                #[cfg(target_os = "linux")]
                let result = crate::screen_capture::apply_to_password_window(obscure);
                #[cfg(not(target_os = "linux"))]
                let result = crate::screen_capture::apply(obscure);
                let _ = tx.send(result);
                ctx.request_repaint();
            });
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(50));
        false
    }
}

fn draw_characters(ui: &mut egui::Ui, value: &str) {
    let count = value.graphemes(true).count();
    if count == 0 {
        ui.label("Empty password");
        return;
    }
    let t = theme();
    let width = ui.available_width().max(1.0);
    let columns = ((width / 88.0).floor() as usize).max(1).min(count);
    let rows = count.div_ceil(columns);
    let cell_width = width / columns as f32;
    let cell_height = (ui.available_height() / rows as f32).max(120.0);
    let font_size = (cell_width * 0.8).min((cell_height - 32.0) * 0.8).max(20.0);
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(width, cell_height * rows as f32),
                egui::Sense::hover(),
            );
            for (index, character) in value.graphemes(true).enumerate() {
                let cell = egui::Rect::from_min_size(
                    rect.min
                        + egui::vec2(
                            (index % columns) as f32 * cell_width,
                            (index / columns) as f32 * cell_height,
                        ),
                    egui::vec2(cell_width, cell_height),
                );
                if !ui.is_rect_visible(cell) {
                    continue;
                }
                let painter = ui.painter_at(cell);
                painter.rect_filled(cell, 0.0, if index % 2 == 0 { t.bg } else { t.surface });
                let text = match character {
                    " " => "␣".to_owned(),
                    "\t" => "⇥".to_owned(),
                    "\n" => "↵".to_owned(),
                    "\r" => "␍".to_owned(),
                    c if c.chars().any(char::is_control) => c.escape_debug().to_string(),
                    c => c.to_string(),
                };
                painter.text(
                    cell.center() - egui::vec2(0.0, 12.0),
                    Align2::CENTER_CENTER,
                    &text,
                    t.mono(if text.graphemes(true).count() > 1 {
                        font_size / 4.0
                    } else {
                        font_size
                    }),
                    t.text_strong,
                );
                painter.text(
                    egui::pos2(cell.center().x, cell.bottom() - 10.0),
                    Align2::CENTER_BOTTOM,
                    (index + 1).to_string(),
                    t.mono(14.0),
                    t.text_muted,
                );
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_shapes(shape: &egui::epaint::Shape, texts: &mut Vec<String>) {
        match shape {
            egui::epaint::Shape::Text(text) => texts.push(text.galley.job.text.clone()),
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    text_shapes(shape, texts);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn boxes_preserve_unicode_graphemes_and_number_positions() {
        let ctx = Context::default();
        let output = ctx.run_ui(Default::default(), |ui| {
            egui::CentralPanel::default().show(ui, |ui| draw_characters(ui, "Ae\u{301}👩‍💻 "));
        });
        let mut texts = Vec::new();
        for shape in &output.shapes {
            text_shapes(&shape.shape, &mut texts);
        }
        for expected in ["A", "e\u{301}", "👩‍💻", "␣", "1", "2", "3", "4"] {
            assert!(
                texts.iter().any(|text| text == expected),
                "missing {expected:?}: {texts:?}"
            );
        }
        assert!(!texts.iter().any(|text| text == "5"));
        output.drop_without_applying_deltas();
    }

    #[test]
    fn snapshot_is_independent_of_source_changes() {
        let mut source = Zeroizing::new("synthetic-password".to_owned());
        let view = LargePassword::new("Test", "Password", &source);
        source.clear();
        assert_eq!(&*view.value, "synthetic-password");
    }

    #[test]
    fn stays_open_until_explicit_escape() {
        let ctx = Context::default();
        let mut view = LargePassword::new("Demo", "Password", "Test");
        view.capture_applied = Some(false);
        for time in [0.0, 3600.0] {
            let input = egui::RawInput {
                time: Some(time),
                focused: false,
                ..Default::default()
            };
            ctx.run_ui(input, |_| assert!(!view.show(&ctx, false)))
                .drop_without_applying_deltas();
        }
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..Default::default()
        };
        let mut closed = false;
        ctx.run_ui(input, |_| closed |= view.show(&ctx, false))
            .drop_without_applying_deltas();
        assert!(closed);
    }

    #[test]
    fn empty_and_long_passwords_render_in_narrow_windows() {
        for value in [String::new(), "a".repeat(10000)] {
            let ctx = Context::default();
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(360.0, 260.0),
                )),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| {
                egui::CentralPanel::default().show(ui, |ui| draw_characters(ui, &value));
            });
            // Only visible cells are painted, even for pathological lengths.
            assert!(output.shapes.len() < 200);
            output.drop_without_applying_deltas();
        }
    }
}
