//! Release notices shared by the vault window and quick access. The daemon does the
//! checking; this only polls its cached snapshot on a worker thread, never per frame.

use crate::backend::AppBackend;
use crate::releases::{CheckState, DesktopUpdate, ReleaseInfo, ReleaseSnapshot};
use crate::ui::theme::theme;
use crate::ui::widgets;
use eframe::egui::{self, RichText, Ui};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(60);
/// While the daemon reports a queued or running check, look again soon.
const CHECKING_POLL_INTERVAL: Duration = Duration::from_secs(2);

enum Request {
    Snapshot,
    Check,
    Dismiss(String),
}

pub enum ReleaseAction {
    SetAutoCheck(bool),
}

/// Survives locking: release data is public and unrelated to the vault.
#[derive(Default)]
pub struct ReleaseUi {
    snapshot: Option<ReleaseSnapshot>,
    /// The reply and whether the user asked for it; failed background polls stay quiet.
    reply: Option<mpsc::Receiver<(bool, Result<ReleaseSnapshot, String>)>>,
    queued: Option<Request>,
    polled_at: Option<Instant>,
    error: Option<String>,
}

impl ReleaseUi {
    /// Collects finished replies and starts the next request when one is due.
    pub fn poll(&mut self, ctx: &egui::Context, backend: &AppBackend) {
        if let Some(reply) = &self.reply {
            match reply.try_recv() {
                Ok((requested, result)) => {
                    self.reply = None;
                    self.polled_at = Some(Instant::now());
                    match result {
                        Ok(snapshot) => {
                            self.snapshot = Some(snapshot);
                            self.error = None;
                        }
                        Err(error) if requested => self.error = Some(error),
                        Err(_) => {}
                    }
                }
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => self.reply = None,
            }
        }
        let interval = if self.checking() {
            CHECKING_POLL_INTERVAL
        } else {
            POLL_INTERVAL
        };
        let request = match self.queued.take() {
            Some(request) => request,
            None => match self.polled_at {
                Some(at) if at.elapsed() < interval => {
                    ctx.request_repaint_after(interval - at.elapsed());
                    return;
                }
                _ => Request::Snapshot,
            },
        };
        let (tx, rx) = mpsc::channel();
        let backend = backend.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let reply = match request {
                Request::Snapshot => (false, backend.release_snapshot()),
                Request::Check => (true, backend.check_releases()),
                Request::Dismiss(version) => (true, backend.dismiss_release(&version)),
            };
            let _ = tx.send(reply);
            ctx.request_repaint();
        });
        self.reply = Some(rx);
    }

    fn checking(&self) -> bool {
        self.snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.state == CheckState::Checking)
    }

    fn queue(&mut self, request: Request) {
        self.queued = Some(request);
    }

    /// A compact, dismissible notice above the current screen when a newer release is
    /// offered. It takes no keyboard focus.
    pub fn draw_notice(&mut self, root: &mut Ui, id: &str) {
        let Some(offer) = self
            .snapshot
            .as_ref()
            .and_then(ReleaseSnapshot::notice)
            .cloned()
        else {
            return;
        };
        let installed = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.desktop.installed.clone())
            .unwrap_or_default();
        let t = theme();
        egui::Panel::top(id.to_owned())
            .frame(
                egui::Frame::new()
                    .fill(t.surface)
                    .inner_margin(egui::Margin::symmetric(12, 6)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Boltwarden {} is available", offer.version))
                            .color(t.text_strong),
                    );
                    ui.label(
                        RichText::new(format!("You have {installed}"))
                            .color(t.text_muted)
                            .size(t.small()),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .button("Dismiss")
                            .on_hover_text("Hide this notice until a newer release is published")
                            .clicked()
                        {
                            self.queue(Request::Dismiss(offer.version.clone()));
                        }
                        if ui
                            .button("Release notes")
                            .on_hover_text("Open the release page on GitHub")
                            .clicked()
                        {
                            self.error = open_release(&offer).err();
                        }
                        if let Some(error) = &self.error {
                            ui.colored_label(t.danger, error);
                        }
                    });
                });
            });
    }

    /// The About page section with version details, check state and controls.
    pub fn draw_about(&mut self, ui: &mut Ui, auto_check: bool) -> Option<ReleaseAction> {
        let t = theme();
        let mut action = None;
        ui.add_space(8.0);
        ui.label(RichText::new("Updates").color(t.text_strong).strong());
        let Some(snapshot) = self.snapshot.clone() else {
            ui.label(RichText::new("Loading release information…").color(t.text_muted));
            return None;
        };
        ui.label(status_text(&snapshot, auto_check));
        if let Some(error) = snapshot
            .error
            .filter(|_| snapshot.state == CheckState::Error)
        {
            ui.label(
                RichText::new(format!("The last check failed: {}.", error.describe()))
                    .color(t.warning),
            );
        }
        for line in detail_lines(&snapshot) {
            ui.label(RichText::new(line).color(t.text_muted).size(t.small()));
        }
        let supported = snapshot.state != CheckState::Unsupported;
        ui.horizontal(|ui| {
            let checking = snapshot.state == CheckState::Checking;
            if widgets::button(ui, "Check now", false, supported && !checking)
                .on_hover_text("Ask GitHub for the latest public releases")
                .clicked()
            {
                self.queue(Request::Check);
            }
            if let Some(offer) = snapshot.desktop.offer.as_ref()
                && widgets::button(ui, "Release notes", false, true)
                    .on_hover_text("Open the release page on GitHub")
                    .clicked()
            {
                self.error = open_release(offer).err();
            }
        });
        if let Some(error) = &self.error {
            widgets::error_line(ui, error);
        }
        if supported
            && widgets::toggle_row(
                ui,
                false,
                auto_check,
                "Check for updates automatically",
                "Once a day; you can always check manually",
            )
            .clicked()
        {
            action = Some(ReleaseAction::SetAutoCheck(!auto_check));
        }
        ui.label(
            RichText::new(
                "Checks request public release information from GitHub. \
                 No vault, account or browsing data is sent.",
            )
            .color(t.text_muted)
            .size(t.small()),
        );
        action
    }
}

fn open_release(release: &ReleaseInfo) -> Result<(), String> {
    // The daemon builds these links itself; check again before handing one to the OS.
    let prefix = format!("{}/releases/tag/", crate::releases::REPOSITORY_URL);
    let url = release
        .url
        .strip_prefix(&prefix)
        .filter(|tag| *tag == release.tag)
        .and_then(|_| url::Url::parse(&release.url).ok())
        .ok_or_else(|| "Invalid release link".to_string())?;
    crate::platform::open_url(&url).map_err(|error| format!("Could not open the browser: {error}"))
}

fn status_text(snapshot: &ReleaseSnapshot, auto_check: bool) -> String {
    let desktop = &snapshot.desktop;
    if snapshot.state == CheckState::Unsupported {
        return "Release checks run in the Boltwarden background service.".into();
    }
    if desktop.update == DesktopUpdate::Development {
        return format!(
            "Development build {}: update notices are off.",
            desktop.installed
        );
    }
    if snapshot.state == CheckState::Checking {
        return "Checking for updates…".into();
    }
    match (desktop.update, &desktop.offer) {
        (DesktopUpdate::Available, Some(offer)) => {
            format!("Boltwarden {} is available.", offer.version)
        }
        (DesktopUpdate::UpToDate, _) => "Boltwarden is up to date.".into(),
        _ if snapshot.checked_at.is_none() && !auto_check => {
            "Automatic checks are off. Use Check now to look for updates.".into()
        }
        _ if snapshot.checked_at.is_none() => "Not checked yet.".into(),
        _ => "Could not confirm that this is the newest release.".into(),
    }
}

fn detail_lines(snapshot: &ReleaseSnapshot) -> Vec<String> {
    let desktop = &snapshot.desktop;
    let published = |release: &ReleaseInfo| {
        format!(
            "{} (published {})",
            release.version,
            crate::releases::format_day(release.published_at)
        )
    };
    let mut lines = Vec::new();
    if let Some(stable) = &desktop.stable {
        lines.push(format!("Latest release: {}", published(stable)));
    }
    if let Some(preview) = desktop
        .preview
        .as_ref()
        .filter(|preview| desktop.stable.as_ref() != Some(*preview))
    {
        lines.push(format!("Latest release candidate: {}", published(preview)));
    }
    if let Some(extension) = &snapshot.extension {
        lines.push(format!(
            "Latest browser extension: {} (store availability may lag)",
            published(extension)
        ));
    }
    if let Some(checked_at) = snapshot.checked_at {
        lines.push(format!(
            "Last checked: {}",
            crate::releases::format_day(checked_at)
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ReleaseSnapshot {
        ReleaseSnapshot::demo(true)
    }

    #[test]
    fn describes_each_check_state() {
        let available = snapshot();
        assert_eq!(
            status_text(&available, true),
            "Boltwarden 1.0.0 is available."
        );
        let mut checking = available.clone();
        checking.state = CheckState::Checking;
        assert_eq!(status_text(&checking, true), "Checking for updates…");
        let mut current = available.clone();
        current.desktop.update = DesktopUpdate::UpToDate;
        current.desktop.offer = None;
        assert_eq!(status_text(&current, true), "Boltwarden is up to date.");
        let mut development = available.clone();
        development.desktop.update = DesktopUpdate::Development;
        development.desktop.installed = "1.0.0-rc.5+2.gabc".into();
        assert!(status_text(&development, true).starts_with("Development build"));
        let empty = ReleaseSnapshot::demo(false);
        assert_eq!(status_text(&empty, true), "Not checked yet.");
        assert!(status_text(&empty, false).starts_with("Automatic checks are off"));
        let mut incomplete = current.clone();
        incomplete.desktop.update = DesktopUpdate::Unknown;
        assert!(status_text(&incomplete, true).starts_with("Could not confirm"));
        assert!(status_text(&ReleaseSnapshot::unsupported(), true).contains("background service"));
    }

    #[test]
    fn lists_latest_releases_without_repeating_the_stable_one() {
        let lines = detail_lines(&snapshot());
        assert_eq!(lines[0], "Latest release: 1.0.0 (published 2026-09-21)");
        assert!(lines.iter().all(|line| !line.contains("candidate")));
        assert!(lines.last().unwrap().starts_with("Last checked:"));
    }

    #[test]
    fn refuses_release_links_that_were_not_built_from_the_tag() {
        let mut release = snapshot().desktop.offer.unwrap();
        release.url = "https://evil.example/releases/tag/v1.0.0".into();
        assert_eq!(open_release(&release), Err("Invalid release link".into()));
        let mut release = snapshot().desktop.offer.unwrap();
        release.tag = "v2.0.0".into();
        assert_eq!(open_release(&release), Err("Invalid release link".into()));
    }

    #[test]
    fn notice_is_hidden_after_dismissal_and_kept_across_polls() {
        let ctx = egui::Context::default();
        let backend = AppBackend::demo();
        let mut ui = ReleaseUi::default();
        ui.snapshot = Some(snapshot());
        assert!(ui.snapshot.as_ref().unwrap().notice().is_some());
        // A failed background poll keeps the earlier snapshot quietly.
        let (tx, rx) = mpsc::channel();
        tx.send((false, Err("daemon unavailable".into()))).unwrap();
        ui.reply = Some(rx);
        ui.poll(&ctx, &backend);
        assert!(ui.snapshot.is_some());
        assert_eq!(ui.error, None);
        // A failed user action is reported.
        let (tx, rx) = mpsc::channel();
        tx.send((true, Err("could not save".into()))).unwrap();
        ui.reply = Some(rx);
        ui.poll(&ctx, &backend);
        assert!(ui.snapshot.is_some());
        assert_eq!(ui.error.as_deref(), Some("could not save"));
        let mut dismissed = snapshot();
        dismissed.desktop.dismissed = true;
        assert!(dismissed.notice().is_none());
    }

    #[test]
    fn notice_and_about_controls_render_and_act_without_taking_focus() {
        let ctx = egui::Context::default();
        let mut releases = ReleaseUi {
            snapshot: Some(snapshot()),
            polled_at: Some(Instant::now()),
            ..Default::default()
        };
        let mut render = |events| {
            let mut action = None;
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800., 700.),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| {
                    releases.draw_notice(ui, "release-notice");
                    egui::CentralPanel::default().show(ui, |ui| {
                        action = releases.draw_about(ui, true);
                    });
                },
            );
            output.textures_delta.clear();
            let texts: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) => {
                        Some((text.galley.job.text.clone(), text.pos + egui::vec2(4., 6.)))
                    }
                    _ => None,
                })
                .collect();
            (action, texts)
        };
        render(vec![]);
        let (_, texts) = render(vec![]);
        for label in [
            "Boltwarden 1.0.0 is available",
            "Release notes",
            "Dismiss",
            "Updates",
            "Check now",
            "Check for updates automatically",
        ] {
            assert!(
                texts.iter().any(|(text, _)| text == label),
                "missing {label}"
            );
        }
        assert!(ctx.memory(|memory| memory.focused()).is_none());
        let click = |texts: &[(String, egui::Pos2)], label: &str| {
            let pos = texts.iter().find(|(text, _)| text == label).unwrap().1;
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ]
        };
        let (action, _) = render(click(&texts, "Check for updates automatically"));
        assert!(matches!(action, Some(ReleaseAction::SetAutoCheck(false))));
        render(click(&texts, "Dismiss"));
        drop(render);
        assert!(
            matches!(releases.queued, Some(Request::Dismiss(ref version)) if version == "1.0.0")
        );
    }
}
