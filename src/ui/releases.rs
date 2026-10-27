//! Release notices shared by the vault window and quick access. The daemon does the
//! checking; this only polls its cached snapshot on a worker thread, never per frame.

use crate::backend::{AppBackend, ReleaseRequestError};
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
    reply: Option<mpsc::Receiver<(bool, Result<ReleaseSnapshot, ReleaseRequestError>)>>,
    queued: Option<Request>,
    polled_at: Option<Instant>,
    /// When `snapshot` arrived, to count down its `retry_after_seconds`.
    received_at: Option<Instant>,
    error: Option<String>,
    /// The last background poll failed: the daemon did not answer, so `snapshot` is
    /// only the last known state and may no longer be true.
    unreachable: bool,
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
                            self.received_at = Some(Instant::now());
                            self.error = None;
                            self.unreachable = false;
                        }
                        Err(error) => {
                            // Without a valid daemon answer the old snapshot may no longer
                            // be true, whoever asked. Only requests the user made show
                            // their error; background polls stay quiet.
                            if matches!(error, ReleaseRequestError::Unavailable(_)) {
                                self.unreachable = true;
                            }
                            if requested {
                                self.error = Some(error.to_string());
                            }
                        }
                    }
                }
                Err(mpsc::TryRecvError::Empty) => return,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.reply = None;
                    self.unreachable = true;
                }
            }
        }
        let mut interval = if self.checking() {
            CHECKING_POLL_INTERVAL
        } else {
            POLL_INTERVAL
        };
        // Refresh as soon as Check now becomes available again.
        if let Some(wait) = self.retry_wait() {
            interval = interval.min(wait + Duration::from_secs(1));
        }
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
        !self.unreachable
            && self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.state == CheckState::Checking)
    }

    /// Time left before the daemon accepts another manual check.
    fn retry_wait(&self) -> Option<Duration> {
        if self.unreachable {
            return None;
        }
        let seconds = self.snapshot.as_ref()?.retry_after_seconds?;
        Duration::from_secs(seconds)
            .checked_sub(self.received_at?.elapsed())
            .filter(|wait| !wait.is_zero())
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
                // Wraps in the narrow quick access window instead of clipping.
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("Boltwarden {} is available", offer.version))
                            .color(t.text_strong),
                    );
                    ui.label(
                        RichText::new(format!("You have {installed}"))
                            .color(t.text_muted)
                            .size(t.small()),
                    );
                    if ui
                        .button("Release notes")
                        .on_hover_text("Open the release page on GitHub")
                        .clicked()
                    {
                        self.error = open_release(&offer).err();
                    }
                    if ui
                        .button("Dismiss")
                        .on_hover_text("Hide this notice until a newer release is published")
                        .clicked()
                    {
                        self.queue(Request::Dismiss(offer.version.clone()));
                    }
                    if let Some(error) = &self.error {
                        ui.colored_label(t.danger, error);
                    }
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
        ui.label(self.status_line(auto_check).unwrap_or_default());
        if self.unreachable {
            ui.label(
                RichText::new(
                    "The Boltwarden background service is not responding; \
                     showing the last known release information.",
                )
                .color(t.warning),
            );
        } else if let Some(error) = snapshot
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
        let wait = self.retry_wait();
        ui.horizontal(|ui| {
            let checking = snapshot.state == CheckState::Checking;
            if widgets::button(
                ui,
                "Check now",
                false,
                supported && !checking && wait.is_none(),
            )
            .on_hover_text("Ask GitHub for the latest public releases")
            .on_disabled_hover_text(if wait.is_some() {
                "Checks are limited to one a minute, or longer when GitHub asks"
            } else {
                "Not available right now"
            })
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
        if let Some(wait) = wait {
            let reason = if snapshot.error == Some(crate::releases::ReleaseError::RateLimited) {
                "GitHub asked to wait. "
            } else {
                ""
            };
            ui.label(
                RichText::new(format!(
                    "{reason}You can check again in {}.",
                    format_wait(wait)
                ))
                .color(t.text_muted)
                .size(t.small()),
            );
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
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

impl ReleaseUi {
    /// The main About status. Without an answer from the daemon only a known newer
    /// release is still claimed, never "up to date" or a GitHub failure.
    fn status_line(&self, auto_check: bool) -> Option<String> {
        let snapshot = self.snapshot.as_ref()?;
        if self.unreachable
            && !(snapshot.desktop.update == DesktopUpdate::Available
                && snapshot.desktop.offer.is_some())
        {
            return Some("Update status unknown.".into());
        }
        Some(status_text(snapshot, auto_check))
    }
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
        _ if snapshot.state == CheckState::Error => {
            "Could not check for updates. Release information may be outdated.".into()
        }
        _ if snapshot.state == CheckState::Stale => {
            "Release information is outdated. Use Check now to refresh it.".into()
        }
        _ if snapshot.checked_at.is_none() && !auto_check => {
            "Automatic checks are off. Use Check now to look for updates.".into()
        }
        _ if snapshot.checked_at.is_none() => "Not checked yet.".into(),
        _ => "Could not confirm that this is the newest release.".into(),
    }
}

/// "45 seconds", "3 minutes", "2 hours", rounded up.
fn format_wait(wait: Duration) -> String {
    let seconds = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
    let (count, unit) = if seconds < 60 {
        (seconds, "second")
    } else if seconds < 2 * 60 * 60 {
        (seconds.div_ceil(60), "minute")
    } else {
        (seconds.div_ceil(60 * 60), "hour")
    };
    format!("{count} {unit}{}", if count == 1 { "" } else { "s" })
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
        let mut failed = incomplete.clone();
        failed.state = CheckState::Error;
        assert!(status_text(&failed, true).starts_with("Could not check for updates"));
        let mut stale = incomplete.clone();
        stale.state = CheckState::Stale;
        assert!(status_text(&stale, true).starts_with("Release information is outdated"));
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
        tx.send((
            false,
            Err(ReleaseRequestError::Unavailable(
                "daemon unavailable".into(),
            )),
        ))
        .unwrap();
        ui.reply = Some(rx);
        ui.poll(&ctx, &backend);
        assert!(ui.snapshot.is_some());
        assert_eq!(ui.error, None);
        // A failed user action is reported.
        let (tx, rx) = mpsc::channel();
        tx.send((
            true,
            Err(ReleaseRequestError::Rejected("could not save".into())),
        ))
        .unwrap();
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

    #[test]
    fn formats_retry_waits_rounding_up() {
        assert_eq!(format_wait(Duration::from_millis(500)), "1 second");
        assert_eq!(format_wait(Duration::from_secs(59)), "59 seconds");
        assert_eq!(format_wait(Duration::from_secs(61)), "2 minutes");
        assert_eq!(format_wait(Duration::from_secs(1_800)), "30 minutes");
        assert_eq!(format_wait(Duration::from_secs(6 * 3_600)), "6 hours");
    }

    fn render_texts(
        ctx: &egui::Context,
        width: f32,
        draw: &mut dyn FnMut(&mut Ui),
    ) -> Vec<(String, egui::Rect)> {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 460.),
                )),
                ..Default::default()
            },
            |ui| draw(ui),
        );
        output.textures_delta.clear();
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((
                    text.galley.job.text.clone(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn check_now_is_disabled_with_a_readable_wait() {
        let ctx = egui::Context::default();
        let mut cooling = snapshot();
        cooling.retry_after_seconds = Some(1_800);
        cooling.error = Some(crate::releases::ReleaseError::RateLimited);
        cooling.state = CheckState::Error;
        let mut releases = ReleaseUi {
            snapshot: Some(cooling),
            received_at: Some(Instant::now()),
            polled_at: Some(Instant::now()),
            ..Default::default()
        };
        let mut draw = |ui: &mut Ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                releases.draw_about(ui, true);
            });
        };
        render_texts(&ctx, 680., &mut draw);
        let texts = render_texts(&ctx, 680., &mut draw);
        assert!(
            texts
                .iter()
                .any(|(text, _)| text == "GitHub asked to wait. You can check again in 30 minutes."),
            "{texts:?}"
        );
        drop(draw);
        assert!(releases.retry_wait().is_some());
        releases.received_at = Some(Instant::now() - Duration::from_secs(1_800));
        assert!(
            releases.retry_wait().is_none(),
            "the wait counts down locally"
        );
    }

    #[test]
    fn notice_wraps_long_versions_in_the_quick_access_width() {
        let ctx = egui::Context::default();
        let mut long = snapshot();
        let offer = long.desktop.offer.as_mut().unwrap();
        offer.version = "100.200.300-rc.400".into();
        long.desktop.installed = "100.200.300-rc.399+1234.gabcdef1.dirty".into();
        let mut releases = ReleaseUi {
            snapshot: Some(long),
            polled_at: Some(Instant::now()),
            ..Default::default()
        };
        let width = crate::ui::widgets::WINDOW_SIZE.x;
        let mut draw = |ui: &mut Ui| {
            releases.draw_notice(ui, "release-notice");
            egui::CentralPanel::default().show(ui, |_| {});
        };
        render_texts(&ctx, width, &mut draw);
        let texts = render_texts(&ctx, width, &mut draw);
        for label in [
            "Boltwarden 100.200.300-rc.400 is available",
            "You have 100.200.300-rc.399+1234.gabcdef1.dirty",
            "Release notes",
            "Dismiss",
        ] {
            let (_, rect) = texts
                .iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing {label}"));
            assert!(rect.max.x <= width + 0.5, "{label} clipped at {rect:?}");
        }
    }

    #[test]
    fn unanswered_polls_withdraw_up_to_date_until_the_daemon_answers() {
        let ctx = egui::Context::default();
        let backend = AppBackend::demo();
        let mut current = snapshot();
        current.desktop.update = DesktopUpdate::UpToDate;
        current.desktop.offer = None;
        let mut ui = ReleaseUi::default();
        let mut reply =
            |ui: &mut ReleaseUi, result: Option<Result<ReleaseSnapshot, ReleaseRequestError>>| {
                let (tx, rx) = mpsc::channel();
                if let Some(result) = result {
                    tx.send((false, result)).unwrap();
                }
                drop(tx);
                ui.reply = Some(rx);
                ui.polled_at = None;
                ui.poll(&ctx, &backend);
                // Discard the follow-up poll the demo backend would answer.
                ui.reply = None;
            };
        reply(&mut ui, Some(Ok(current.clone())));
        assert_eq!(ui.status_line(true).unwrap(), "Boltwarden is up to date.");
        // Polls keep failing, for days: never up to date, never a GitHub error.
        for _ in 0..3 {
            reply(&mut ui, Some(Err(unavailable())));
            assert_eq!(ui.status_line(true).unwrap(), "Update status unknown.");
            assert_eq!(ui.error, None, "background failures stay out of the notice");
        }
        // A worker that disappeared counts the same.
        reply(&mut ui, None);
        assert!(ui.unreachable);
        assert_eq!(ui.snapshot.as_ref().unwrap().checked_at, current.checked_at);
        reply(&mut ui, Some(Ok(current)));
        assert_eq!(ui.status_line(true).unwrap(), "Boltwarden is up to date.");

        // A known newer release is still announced while the daemon is unreachable.
        reply(&mut ui, Some(Ok(snapshot())));
        reply(&mut ui, Some(Err(unavailable())));
        assert!(ui.snapshot.as_ref().unwrap().notice().is_some());
        assert_eq!(
            ui.status_line(true).unwrap(),
            "Boltwarden 1.0.0 is available."
        );
    }

    fn unavailable() -> ReleaseRequestError {
        ReleaseRequestError::Unavailable("could not connect to daemon".into())
    }

    /// Delivers the reply to a request the user made, as `ReleaseUi::poll` would.
    fn answer(ui: &mut ReleaseUi, result: Result<ReleaseSnapshot, ReleaseRequestError>) {
        let (tx, rx) = mpsc::channel();
        tx.send((true, result)).unwrap();
        ui.reply = Some(rx);
        ui.poll(&egui::Context::default(), &AppBackend::demo());
        ui.reply = None;
    }

    #[test]
    fn failed_manual_requests_withdraw_up_to_date_only_without_a_daemon_answer() {
        let mut current = snapshot();
        current.desktop.update = DesktopUpdate::UpToDate;
        current.desktop.offer = None;
        let fresh = |snapshot: ReleaseSnapshot| ReleaseUi {
            snapshot: Some(snapshot),
            received_at: Some(Instant::now()),
            polled_at: Some(Instant::now()),
            ..Default::default()
        };

        // Check now that never reached the daemon.
        let mut ui = fresh(current.clone());
        assert_eq!(ui.status_line(true).unwrap(), "Boltwarden is up to date.");
        answer(&mut ui, Err(unavailable()));
        assert_eq!(ui.status_line(true).unwrap(), "Update status unknown.");
        assert_eq!(ui.error.as_deref(), Some("could not connect to daemon"));
        assert_eq!(ui.snapshot.as_ref().unwrap().checked_at, current.checked_at);
        // Repeating it keeps the status unknown.
        answer(&mut ui, Err(unavailable()));
        assert_eq!(ui.status_line(true).unwrap(), "Update status unknown.");
        // An answer restores everything.
        answer(&mut ui, Ok(current.clone()));
        assert_eq!(ui.status_line(true).unwrap(), "Boltwarden is up to date.");
        assert_eq!(ui.error, None);
        assert!(!ui.unreachable);

        // Dismiss that never reached the daemon keeps the known newer release.
        let mut ui = fresh(snapshot());
        answer(&mut ui, Err(unavailable()));
        assert!(ui.unreachable);
        assert!(ui.snapshot.as_ref().unwrap().notice().is_some());
        assert_eq!(
            ui.status_line(true).unwrap(),
            "Boltwarden 1.0.0 is available."
        );

        // A daemon that refuses the dismissal is still reachable.
        let mut ui = fresh(current.clone());
        answer(
            &mut ui,
            Err(ReleaseRequestError::Rejected(
                "That release is no longer offered".into(),
            )),
        );
        assert!(!ui.unreachable);
        assert_eq!(
            ui.error.as_deref(),
            Some("That release is no longer offered")
        );
        assert_eq!(ui.status_line(true).unwrap(), "Boltwarden is up to date.");
    }
}
