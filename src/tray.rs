use std::sync::{LazyLock, mpsc};

use ksni::blocking::{Handle, TrayMethods};

static TRAY_ICONS: LazyLock<Vec<ksni::Icon>> = LazyLock::new(|| {
    vec![
        render_tray_icon(16),
        render_tray_icon(22),
        render_tray_icon(32),
        render_tray_icon(48),
        render_tray_icon(64),
    ]
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Show,
    Hide,
    Toggle,
    Window,
    Quit,
}

#[derive(Debug)]
pub struct AppTray {
    tx: mpsc::Sender<TrayCommand>,
}

impl AppTray {
    pub fn new(tx: mpsc::Sender<TrayCommand>) -> Self {
        Self { tx }
    }

    fn send(&self, command: TrayCommand) {
        let _ = self.tx.send(command);
    }
}

impl ksni::Tray for AppTray {
    fn id(&self) -> String {
        "boltwarden".into()
    }

    fn title(&self) -> String {
        "Boltwarden".into()
    }

    fn icon_name(&self) -> String {
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        TRAY_ICONS.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Boltwarden".into(),
            description: "Search and copy Vaultwarden entries".into(),
            ..Default::default()
        }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCommand::Show);
    }

    fn secondary_activate(&mut self, _x: i32, _y: i32) {
        self.send(TrayCommand::Toggle);
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        vec![
            StandardItem {
                label: "Show".into(),
                icon_name: "view-restore".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayCommand::Show)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Hide".into(),
                icon_name: "window-minimize".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayCommand::Hide)),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Open vault window".into(),
                icon_name: "view-fullscreen".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayCommand::Window)),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|tray: &mut Self| tray.send(TrayCommand::Quit)),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn spawn(tx: mpsc::Sender<TrayCommand>) -> Result<Handle<AppTray>, ksni::Error> {
    AppTray::new(tx).assume_sni_available(true).spawn()
}

/// The app's mark in the theme's text color, monochrome like the other tray icons.
fn render_tray_icon(size: i32) -> ksni::Icon {
    let color = crate::ui::theme::theme().text;
    // StatusNotifierItem pixmaps are ARGB32 in network byte order.
    let data = crate::logo::rgba(size as u32, color)
        .as_chunks::<4>()
        .0
        .iter()
        .flat_map(|[r, g, b, a]| [*a, *r, *g, *b])
        .collect();
    ksni::Icon {
        width: size,
        height: size,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_icon_pixmaps_have_argb_data() {
        for icon in TRAY_ICONS.iter() {
            assert_eq!(icon.width, icon.height);
            assert_eq!(icon.data.len(), (icon.width * icon.height * 4) as usize);
            assert!(icon.data.chunks_exact(4).any(|pixel| pixel[0] > 0));
        }
    }
}
