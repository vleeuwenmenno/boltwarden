use egui::Ui;

pub fn draw_footer(ui: &mut Ui, hints: &[(&str, &str)]) {
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 12.0;
        for (key, label) in hints {
            ui.label(
                egui::RichText::new(*key)
                    .monospace()
                    .color(egui::Color32::from_rgb(180, 180, 180)),
            );
            ui.label(
                egui::RichText::new(*label)
                    .small()
                    .color(egui::Color32::from_rgb(120, 120, 120)),
            );
        }
    });
}
