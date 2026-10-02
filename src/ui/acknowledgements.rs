//! Offline license information, embedded in the executable during release builds.

const PROJECT_LICENSE: &str = include_str!("../../LICENSE");
const THIRD_PARTY_NOTICES: &str =
    include_str!(concat!(env!("OUT_DIR"), "/third_party_notices.txt"));
const NOTICE_SEPARATOR: &str =
    "\n========================================================================\n";

pub fn draw(ui: &mut egui::Ui) {
    egui::ScrollArea::vertical()
        .id_salt("licenses-and-acknowledgements")
        .show(ui, |ui| {
            ui.heading("Boltwarden");
            draw_versions(ui);
            ui.label("Created by Menno van Leeuwen.");
            ui.hyperlink_to(
                "Project and source code",
                "https://github.com/vleeuwenmenno/boltwarden",
            );
            ui.add_space(12.0);
            egui::CollapsingHeader::new("Project license — MIT with Commons Clause")
                .id_salt("project-license")
                .show(ui, |ui| {
                    ui.add(egui::Label::new(PROJECT_LICENSE).selectable(true));
                });

            ui.add_space(12.0);
            ui.heading("Acknowledgements");
            ui.label("Thank you to the maintainers and contributors of the libraries that make Boltwarden possible.");
            ui.label("Boltwarden is an independent client for Bitwarden and Vaultwarden. It is not affiliated with or endorsed by those projects.");
            ui.add_space(12.0);
            ui.heading("Third-party licenses");
            if THIRD_PARTY_NOTICES.is_empty() {
                ui.label("Third-party notices were not embedded in this development build. Official release packages include them.");
                ui.label("To include them when building from source, run make release.");
                return;
            }

            let mut sections = THIRD_PARTY_NOTICES.split(NOTICE_SEPARATOR);
            ui.label(sections.next().unwrap_or_default().trim());
            let search_id = ui.make_persistent_id("license-search");
            let mut search = ui.data_mut(|data| data.get_temp::<String>(search_id)).unwrap_or_default();
            ui.add(egui::TextEdit::singleline(&mut search).hint_text("Find a dependency"));
            let query = search.trim().to_lowercase();
            ui.data_mut(|data| data.insert_temp(search_id, search));
            let mut matched = false;
            for (index, section) in sections.enumerate() {
                let title = section.lines().next().unwrap_or("Dependency");
                if !title.to_lowercase().contains(&query) {
                    continue;
                }
                matched = true;
                egui::CollapsingHeader::new(title)
                    .id_salt(("dependency-license", index))
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(section).selectable(true));
                    });
            }
            if !matched {
                ui.label("No matching dependencies.");
            }
        });
}

/// Shared version summary for settings and the quick-access version command.
pub fn draw_versions(ui: &mut egui::Ui) {
    ui.label(format!("Desktop version: {}", crate::version::APP));
    ui.label(format!("Browser integration API: v{}", crate::version::BROWSER_API))
        .on_hover_text("Protocol used between Boltwarden and its browser extensions; not the connected Bitwarden or Vaultwarden server version.");
}
