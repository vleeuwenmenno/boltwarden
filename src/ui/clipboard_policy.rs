//! Preserve explicit-copy behavior when egui reports settled text selections.

/// Labels and text editors must not export revealed vault content to the Linux
/// PRIMARY selection, which is outside our explicit clipboard expiry lifecycle.
pub fn install(ctx: &egui::Context) {
    ctx.add_plugin(ExplicitCopyOnly);
}

struct ExplicitCopyOnly;

impl egui::Plugin for ExplicitCopyOnly {
    fn debug_name(&self) -> &'static str {
        "boltwarden_explicit_copy_only"
    }

    fn output_hook(&mut self, _ctx: &egui::Context, output: &mut egui::FullOutput) {
        // Run after all end-pass selection processing, just before the backend.
        output
            .platform_output
            .commands
            .retain(|command| !matches!(command, egui::OutputCommand::TextSelectionSettled(_)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_selection_commands_are_filtered_after_end_pass() {
        struct LateSelection;
        impl egui::Plugin for LateSelection {
            fn debug_name(&self) -> &'static str {
                "late_selection"
            }
            fn on_end_pass(&mut self, ui: &mut egui::Ui) {
                ui.ctx().send_cmd(egui::OutputCommand::TextSelectionSettled(
                    "synthetic-label-secret".to_owned(),
                ));
            }
        }
        let ctx = egui::Context::default();
        install(&ctx);
        ctx.add_plugin(LateSelection);
        let output = ctx.run_ui(Default::default(), |_| {});
        assert!(
            !output
                .platform_output
                .commands
                .iter()
                .any(|command| { matches!(command, egui::OutputCommand::TextSelectionSettled(_)) })
        );
        output.drop_without_applying_deltas();
    }

    fn selected_editor_output(protected: bool) -> egui::FullOutput {
        let ctx = egui::Context::default();
        if protected {
            install(&ctx);
        }
        let id = egui::Id::unique("revealed-secret");
        let mut text = "synthetic-secret".to_owned();
        let draw = |ui: &mut egui::Ui, text: &mut String| {
            egui::TextEdit::singleline(text)
                .id(id)
                .password(false)
                .show(ui)
        };
        ctx.run_ui(Default::default(), |ui| {
            draw(ui, &mut text);
        })
        .drop_without_applying_deltas();
        let mut state = egui::text_edit::TextEditState::load(&ctx, id).unwrap();
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::two(
                egui::text::CCursor::new(0),
                egui::text::CCursor::new(text.chars().count()),
            )));
        state.store(&ctx, id);
        ctx.memory_mut(|memory| memory.request_focus(id));
        ctx.run_ui(Default::default(), |ui| {
            draw(ui, &mut text);
            ui.ctx().copy_text("explicit-copy".to_owned());
        })
    }

    #[test]
    fn revealed_text_selection_does_not_export_to_primary() {
        let baseline = selected_editor_output(false);
        assert!(baseline.platform_output.commands.iter().any(|command| {
            matches!(command, egui::OutputCommand::TextSelectionSettled(text) if text == "synthetic-secret")
        }));
        baseline.drop_without_applying_deltas();

        let protected = selected_editor_output(true);
        assert!(
            !protected
                .platform_output
                .commands
                .iter()
                .any(|command| { matches!(command, egui::OutputCommand::TextSelectionSettled(_)) })
        );
        assert!(protected.platform_output.commands.iter().any(|command| {
            matches!(command, egui::OutputCommand::CopyText(text) if text == "explicit-copy")
        }));
        protected.drop_without_applying_deltas();
    }
}
