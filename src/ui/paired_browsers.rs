//! Shared paired-browser management for quick access and the full vault window.

use crate::browser::PairingRecord;
use crate::ui::{theme::theme, widgets};
use egui::{RichText, Ui};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairedBrowsersAction {
    Refresh,
    Revoke(String),
}

#[derive(Default)]
pub struct PairedBrowsersState {
    pub records: Vec<PairingRecord>,
    pub loading: bool,
    pub loaded: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    confirmation: Option<PairingRecord>,
    revoking: Option<String>,
    selected: Option<String>,
    scrolled_to: Option<String>,
}

impl PairedBrowsersState {
    pub fn is_busy(&self) -> bool {
        self.loading || self.revoking.is_some()
    }

    pub fn has_confirmation(&self) -> bool {
        self.confirmation.is_some()
    }

    /// Starts an automatic or initial lookup. A Refresh action returned by the
    /// panel has already called this method and can be dispatched directly.
    pub fn begin_refresh(&mut self) -> bool {
        if self.is_busy() || self.has_confirmation() {
            return false;
        }
        self.loading = true;
        self.error = None;
        true
    }

    pub fn finish_refresh(&mut self, result: Result<Vec<PairingRecord>, String>) {
        if !self.loading {
            return;
        }
        self.loading = false;
        match result {
            Ok(mut records) => {
                records.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then_with(|| a.id.cmp(&b.id))
                });
                self.records = records;
                if !self
                    .records
                    .iter()
                    .any(|record| Some(&record.id) == self.selected.as_ref())
                {
                    self.selected = None;
                    self.scrolled_to = None;
                }
                self.loaded = true;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// Applies only the currently pending revoke, so a delayed reply cannot
    /// remove a different browser or dismiss a newer confirmation.
    pub fn finish_revoke(&mut self, id: &str, result: Result<(), String>) {
        if self.revoking.as_deref() != Some(id) {
            return;
        }
        self.revoking = None;
        match result {
            Ok(()) => {
                self.records.retain(|record| record.id != id);
                self.cancel_confirmation();
                self.error = None;
                self.notice = Some("Browser access revoked. Pair it again to reconnect.".into());
            }
            Err(error) => {
                self.error = Some(error);
            }
        }
    }

    /// Clears the dialog when leaving this view without pretending an already
    /// dispatched worker has finished.
    pub fn cancel_confirmation(&mut self) {
        self.confirmation = None;
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn request_revoke(&mut self, id: &str) {
        if self.is_busy() || self.has_confirmation() {
            return;
        }
        if let Some(record) = self.records.iter().find(|record| record.id == id) {
            self.confirmation = Some(record.clone());
            self.selected = Some(record.id.clone());
            self.error = None;
            self.notice = None;
        }
    }

    fn confirm_revoke(&mut self) -> Option<PairedBrowsersAction> {
        if self.is_busy() {
            return None;
        }
        let id = self.confirmation.as_ref()?.id.clone();
        if !self.records.iter().any(|record| record.id == id) {
            self.cancel_confirmation();
            return None;
        }
        self.revoking = Some(id.clone());
        self.error = None;
        Some(PairedBrowsersAction::Revoke(id))
    }

    fn selected_index(&self) -> usize {
        self.records
            .iter()
            .position(|record| Some(&record.id) == self.selected.as_ref())
            .unwrap_or(0)
    }

    fn move_selection(&mut self, amount: isize) {
        if self.records.is_empty() {
            return;
        }
        let index = (self.selected_index() as isize + amount)
            .rem_euclid(self.records.len() as isize) as usize;
        self.selected = Some(self.records[index].id.clone());
    }
}

/// Returns actions after marking them busy. Controllers finish each action with
/// finish_refresh/finish_revoke. Arrow keys, Enter and Ctrl+R belong to this panel;
/// outer handlers must leave confirmation keys for the shared dialog.
pub fn draw_paired_browsers(
    ui: &mut Ui,
    state: &mut PairedBrowsersState,
) -> Option<PairedBrowsersAction> {
    let t = theme();
    let mut action = None;
    if !state.is_busy() && !state.has_confirmation() {
        ui.input_mut(|input| {
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                state.move_selection(1);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                state.move_selection(-1);
            }
            if input.consume_key(egui::Modifiers::NONE, egui::Key::Enter) {
                if let Some(record) = state.records.get(state.selected_index()) {
                    let id = record.id.clone();
                    state.request_revoke(&id);
                }
            }
            if input.consume_key(egui::Modifiers::COMMAND, egui::Key::R) && state.begin_refresh() {
                action = Some(PairedBrowsersAction::Refresh);
            }
        });
    }
    if let Some(error) = state.error.as_deref().filter(|_| !state.has_confirmation()) {
        widgets::error_line(ui, error);
        ui.add_space(4.0);
    }
    if let Some(notice) = &state.notice {
        ui.label(RichText::new(notice).size(t.small()).color(t.success));
        ui.add_space(4.0);
    }

    let selected = state.selected_index();
    let mut revoke = None;
    egui::ScrollArea::vertical()
        .id_salt("paired-browsers-list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            if state.records.is_empty() {
                if state.loading {
                    widgets::empty_state(ui, "", "Loading paired browsers…", true);
                } else if state.loaded && state.error.is_none() {
                    widgets::empty_state(
                        ui,
                        t.icon("\u{f26c}", "◎"),
                        "No paired browsers · open the extension to pair",
                        false,
                    );
                } else if state.error.is_none() {
                    widgets::empty_state(ui, "", "Refresh to load paired browsers", false);
                }
            }
            ui.add_enabled_ui(!state.is_busy() && !state.has_confirmation(), |ui| {
                for (index, record) in state.records.iter().enumerate() {
                    let (rect, response) = widgets::row(ui, index == selected, widgets::ROW_HEIGHT);
                    widgets::paint_row_content(
                        ui,
                        rect,
                        t.icon("\u{f26c}", "◎"),
                        None,
                        label(record),
                        Some(&short_fingerprint(&record.fingerprint)),
                        Some("Revoke"),
                        index == selected,
                    );
                    response.widget_info(|| {
                        egui::WidgetInfo::selected(
                            egui::WidgetType::SelectableLabel,
                            ui.is_enabled(),
                            index == selected,
                            format!(
                                "{} · {} · Revoke browser access",
                                label(record),
                                record.fingerprint
                            ),
                        )
                    });
                    if index == selected && state.scrolled_to.as_ref() != Some(&record.id) {
                        ui.scroll_to_rect(rect, None);
                        state.scrolled_to = Some(record.id.clone());
                    }
                    if response.clicked() {
                        revoke = Some(record.id.clone());
                    }
                    response.on_hover_ui(|ui| {
                        ui.label(RichText::new(label(record)).color(t.text_strong));
                        fingerprint(ui, &record.fingerprint);
                        ui.label(
                            RichText::new(pairing_dates(record))
                                .size(t.small())
                                .color(t.text_muted),
                        );
                    });
                }
            });
        });
    if let Some(id) = revoke {
        state.request_revoke(&id);
    }

    if let Some(record) = state.confirmation.clone() {
        // Line breaks keep the complete fingerprint readable within the standard
        // confirmation width; the compact row is never the final identity check.
        let groups: Vec<_> = record.fingerprint.split(':').collect();
        let fingerprint = groups
            .chunks(8)
            .map(|groups| groups.join(":"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!(
            "{}\n{}\n{}\n\nThis browser will disconnect. Pair it again to restore access.",
            label(&record),
            fingerprint,
            pairing_dates(&record),
        );
        match widgets::confirm_dialog(
            ui.ctx(),
            &widgets::ConfirmDialog {
                title: "Revoke browser access?",
                body: &body,
                confirm_label: "Revoke access",
                danger: true,
                key: widgets::ConfirmKey::CtrlEnter,
                busy: state.revoking.is_some(),
                error: state.error.as_deref(),
            },
        ) {
            Some(false) => state.cancel_confirmation(),
            Some(true) => action = state.confirm_revoke(),
            None => {}
        }
    }
    action
}

fn short_fingerprint(fingerprint: &str) -> String {
    let mut groups = fingerprint.split(':');
    let short = groups.by_ref().take(3).collect::<Vec<_>>().join(":");
    if groups.next().is_some() {
        format!("{short}…")
    } else {
        short
    }
}

fn pairing_dates(record: &PairingRecord) -> String {
    let paired = format_timestamp(record.created_at).unwrap_or_else(|| "Unknown".into());
    let mut dates = format!("Paired {paired}");
    if let Some(seen) = format_timestamp(record.last_seen_at) {
        dates.push_str(&format!("\nLast authenticated {seen}"));
    }
    dates
}

fn label(record: &PairingRecord) -> &str {
    if record.label.trim().is_empty() {
        "Unnamed browser"
    } else {
        &record.label
    }
}

fn fingerprint(ui: &mut Ui, fingerprint: &str) {
    let t = theme();
    let mut job = egui::text::LayoutJob::simple(
        fingerprint.to_owned(),
        egui::FontId::monospace(t.small()),
        t.text_muted,
        ui.available_width(),
    );
    job.wrap.break_anywhere = true;
    ui.add(egui::Label::new(job).wrap().selectable(true))
        .on_hover_text("Browser public-key fingerprint");
}

/// Pairing timestamps are Unix seconds. Explicit UTC avoids implying the daemon
/// recorded a local timezone or treating an unavailable timestamp as recent use.
fn format_timestamp(seconds: u64) -> Option<String> {
    if seconds == 0 {
        return None;
    }
    let seconds = libc::time_t::try_from(seconds).ok()?;
    let mut date = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: both pointers reference valid, correctly aligned storage;
    // gmtime_r initializes date on success and does not retain either pointer.
    if unsafe { libc::gmtime_r(&seconds, date.as_mut_ptr()) }.is_null() {
        return None;
    }
    // SAFETY: gmtime_r succeeded above and initialized the entire struct.
    let date = unsafe { date.assume_init() };
    let year = date.tm_year.checked_add(1900)?;
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let month = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .get(usize::try_from(date.tm_mon).ok()?)?;
    Some(format!(
        "{} {month} {year}, {:02}:{:02} UTC",
        date.tm_mday, date.tm_hour, date.tm_min
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> PairingRecord {
        PairingRecord {
            id: id.into(),
            label: "Firefox on laptop".into(),
            public_key_spki: "PUBLIC-KEY-NOT-DISPLAYED".into(),
            fingerprint:
                "ABCD:1234:5678:90EF:ABCD:1234:5678:90EF:ABCD:1234:5678:90EF:ABCD:1234:5678:90EF"
                    .into(),
            created_at: 1_759_276_800,
            last_seen_at: 1_759_363_260,
        }
    }

    fn loaded() -> PairedBrowsersState {
        let mut state = PairedBrowsersState::default();
        assert!(state.begin_refresh());
        state.finish_refresh(Ok(vec![record("one"), record("two")]));
        state
    }

    fn frame(
        ctx: &egui::Context,
        state: &mut PairedBrowsersState,
        events: Vec<egui::Event>,
    ) -> (Option<PairedBrowsersAction>, Vec<String>) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                widgets::WINDOW_SIZE,
            )),
            events,
            ..Default::default()
        };
        let mut action = None;
        let mut output = ctx.run_ui(input, |root| {
            egui::CentralPanel::default().show(root, |ui| {
                action = draw_paired_browsers(ui, state);
            });
        });
        output.textures_delta.clear();
        let texts = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some(text.galley.job.text.clone()),
                _ => None,
            })
            .collect();
        (action, texts)
    }

    fn key(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    #[test]
    fn serializes_refresh_confirmation_and_revoke() {
        let mut state = loaded();
        assert!(state.begin_refresh());
        state.request_revoke("one");
        assert!(!state.has_confirmation());
        state.finish_refresh(Ok(vec![record("one"), record("two")]));
        state.request_revoke("one");
        assert!(!state.begin_refresh());
        assert_eq!(
            state.confirm_revoke(),
            Some(PairedBrowsersAction::Revoke("one".into()))
        );
        assert!(state.is_busy());
        assert!(state.confirm_revoke().is_none());
        assert!(!state.begin_refresh());
        assert_eq!(state.records.len(), 2, "no optimistic removal");
        state.finish_revoke("two", Ok(()));
        assert_eq!(state.records.len(), 2, "ignore a stale reply");
        state.finish_revoke("one", Ok(()));
        assert_eq!(state.records[0].id, "two");
        assert!(!state.is_busy());
        assert!(!state.has_confirmation());
        assert!(state.notice.is_some());
        assert!(state.begin_refresh());
        state.finish_refresh(Ok(vec![record("two")]));
        assert!(state.notice.is_some(), "refresh preserves success feedback");
    }

    #[test]
    fn errors_keep_existing_records_and_allow_retry() {
        let mut state = loaded();
        assert!(state.begin_refresh());
        state.finish_refresh(Err("Daemon unavailable".into()));
        assert_eq!(state.records.len(), 2);
        assert_eq!(state.error.as_deref(), Some("Daemon unavailable"));
        state.request_revoke("one");
        state.confirm_revoke();
        state.finish_revoke("one", Err("Could not save pairing store".into()));
        assert_eq!(state.records.len(), 2);
        assert!(state.has_confirmation());
        assert!(!state.is_busy());
        assert!(state.confirm_revoke().is_some());
    }

    #[test]
    fn leaving_confirmation_does_not_finish_inflight_revoke() {
        let mut state = loaded();
        state.request_revoke("one");
        state.confirm_revoke();
        state.cancel_confirmation();
        assert!(!state.has_confirmation());
        assert!(state.is_busy());
        state.finish_revoke("one", Ok(()));
        assert!(!state.is_busy());
        assert_eq!(state.records.len(), 1);
    }

    #[test]
    fn compact_rows_keep_full_identity_in_confirmation_and_distinguish_failed_from_empty() {
        let ctx = egui::Context::default();
        let mut state = loaded();
        let (_, texts) = frame(&ctx, &mut state, vec![]);
        assert!(
            texts
                .iter()
                .any(|text| text.contains("Firefox on laptop") && text.contains("ABCD:1234:5678…"))
        );
        assert!(!texts.iter().any(|text| text == "Paired browsers"));
        assert!(
            !texts
                .iter()
                .any(|text| text.contains(&record("one").fingerprint))
        );
        state.request_revoke("one");
        frame(&ctx, &mut state, vec![]);
        let (_, texts) = frame(&ctx, &mut state, vec![]);
        let fingerprint = record("one").fingerprint.replace(':', "");
        assert!(
            texts
                .iter()
                .any(|text| text.replace([':', '\n'], "").contains(&fingerprint))
        );
        assert!(
            texts
                .iter()
                .any(|text| text.contains("Paired 1 Oct 2025, 00:00 UTC"))
        );
        assert!(
            texts
                .iter()
                .any(|text| text.contains("Last authenticated "))
        );
        assert!(
            !texts
                .iter()
                .any(|text| text.contains("PUBLIC-KEY-NOT-DISPLAYED"))
        );

        state.reset();
        state.begin_refresh();
        state.finish_refresh(Err("Daemon unavailable".into()));
        let (_, texts) = frame(&ctx, &mut state, vec![]);
        assert!(texts.iter().any(|text| text.contains("Daemon unavailable")));
        assert!(!texts.iter().any(|text| text == "No paired browsers"));
        state.begin_refresh();
        state.finish_refresh(Ok(vec![]));
        let (_, texts) = frame(&ctx, &mut state, vec![]);
        assert!(
            texts
                .iter()
                .any(|text| text.starts_with("No paired browsers"))
        );
    }

    #[test]
    fn plain_enter_never_confirms_and_escape_cancels() {
        let ctx = egui::Context::default();
        let mut state = loaded();
        state.request_revoke("one");
        frame(&ctx, &mut state, vec![]);
        let (_, texts) = frame(&ctx, &mut state, vec![]);
        assert!(texts.iter().any(|text| text == "Revoke browser access?"));
        let (action, _) = frame(&ctx, &mut state, vec![key(egui::Key::Enter)]);
        assert!(action.is_none());
        assert!(
            state.has_confirmation(),
            "plain Enter must not revoke access"
        );
        assert_eq!(state.records.len(), 2);
        let (action, _) = frame(&ctx, &mut state, vec![key(egui::Key::Escape)]);
        assert!(action.is_none());
        assert!(!state.has_confirmation());
        assert_eq!(state.records.len(), 2);
    }

    #[test]
    fn arrow_selection_opens_confirmation_and_ctrl_enter_revokes() {
        let ctx = egui::Context::default();
        let mut state = loaded();
        frame(&ctx, &mut state, vec![]);
        frame(&ctx, &mut state, vec![key(egui::Key::ArrowUp)]);
        assert_eq!(
            state.selected.as_deref(),
            Some("two"),
            "up wraps to the final row"
        );
        frame(&ctx, &mut state, vec![key(egui::Key::ArrowDown)]);
        assert_eq!(
            state.selected.as_deref(),
            Some("one"),
            "down wraps to the first row"
        );
        let (action, _) = frame(&ctx, &mut state, vec![key(egui::Key::ArrowDown)]);
        assert!(action.is_none());
        assert_eq!(state.selected.as_deref(), Some("two"));
        let (action, _) = frame(&ctx, &mut state, vec![key(egui::Key::Enter)]);
        assert!(action.is_none());
        assert!(state.has_confirmation());
        let mut confirm = key(egui::Key::Enter);
        if let egui::Event::Key { modifiers, .. } = &mut confirm {
            *modifiers = egui::Modifiers::COMMAND;
        }
        let (action, _) = frame(&ctx, &mut state, vec![confirm]);
        assert_eq!(action, Some(PairedBrowsersAction::Revoke("two".into())));
        assert!(state.is_busy());
        assert_eq!(state.records.len(), 2);
    }

    #[test]
    fn automatic_refresh_preserves_selected_identity_when_order_changes() {
        let mut state = loaded();
        state.move_selection(1);
        assert_eq!(state.selected.as_deref(), Some("two"));
        assert!(state.begin_refresh());
        let mut newer = record("new");
        newer.created_at += 60;
        state.finish_refresh(Ok(vec![newer, record("one"), record("two")]));
        assert_eq!(state.records[state.selected_index()].id, "two");
    }

    #[test]
    fn identity_content_fits_quick_access_and_full_window_widths() {
        for size in [widgets::WINDOW_SIZE, egui::vec2(1024.0, 760.0)] {
            let ctx = egui::Context::default();
            let mut state = loaded();
            state.records[0].label = "A very long browser profile name ".repeat(4);
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        draw_paired_browsers(ui, &mut state);
                    });
                },
            );
            output.textures_delta.clear();
            for shape in output.shapes {
                if let egui::Shape::Text(text) = shape.shape {
                    assert!(
                        text.pos.x + text.galley.size().x <= size.x + 1.0,
                        "text exceeds viewport: {}",
                        text.galley.job.text
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_and_unrepresentable_timestamps_are_not_recent_activity() {
        assert_eq!(format_timestamp(0), None);
        assert_eq!(format_timestamp(u64::MAX), None);
        assert_eq!(
            format_timestamp(1_759_276_800).as_deref(),
            Some("1 Oct 2025, 00:00 UTC")
        );
    }
}
