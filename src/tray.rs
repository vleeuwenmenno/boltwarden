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
        "bw-quick-access".into()
    }

    fn title(&self) -> String {
        "Bitwarden Quick Access".into()
    }

    fn icon_name(&self) -> String {
        String::new()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        TRAY_ICONS.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "Bitwarden Quick Access".into(),
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

/// The Bitwarden shield (Simple Icons' monochrome mark), in the theme's text color so
/// it sits in the bar like the other tray icons.
const BITWARDEN_SHIELD: &str = "M21.722.296A.964.964 0 0 0 21.018 0H2.982a.959.959 0 0 0-.703.296.96.96 0 0 0-.297.702v12c0 .895.174 1.783.523 2.665.349.88.783 1.66 1.3 2.345.517.68 1.132 1.346 1.848 1.993a21.807 21.807 0 0 0 1.98 1.609c.605.427 1.235.83 1.893 1.212.657.381 1.125.638 1.4.772.276.134.5.241.664.311a.916.916 0 0 0 .814 0c.168-.073.389-.177.667-.311.275-.134.743-.394 1.401-.772a25.305 25.305 0 0 0 1.894-1.212A21.891 21.891 0 0 0 18.348 20c.716-.647 1.33-1.31 1.847-1.993s.949-1.463 1.3-2.345c.35-.879.524-1.767.524-2.665V1.001a.95.95 0 0 0-.297-.705zm-2.325 12.815c0 4.344-7.397 8.087-7.397 8.087V2.57h7.397v10.54z";

fn render_tray_icon(size: i32) -> ksni::Icon {
    use resvg::{tiny_skia, usvg};
    let color = crate::ui::theme::theme().text;
    let svg = format!(
        r##"<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="#{:02x}{:02x}{:02x}" d="{BITWARDEN_SHIELD}"/></svg>"##,
        color.r(),
        color.g(),
        color.b()
    );
    let mut data = vec![0; (size * size * 4) as usize];
    let tree = usvg::Tree::from_str(&svg, &usvg::Options::default()).expect("valid tray icon");
    if let Some(mut pixmap) = tiny_skia::Pixmap::new(size as u32, size as u32) {
        // A little inset keeps the shield from touching the bar's edges.
        let scale = size as f32 * 0.9 / 24.0;
        let offset = size as f32 * 0.05;
        resvg::render(
            &tree,
            tiny_skia::Transform::from_scale(scale, scale).post_translate(offset, offset),
            &mut pixmap.as_mut(),
        );
        // StatusNotifierItem pixmaps are ARGB32 in network byte order, straight alpha.
        for (pixel, out) in pixmap.pixels().iter().zip(data.chunks_exact_mut(4)) {
            let color = pixel.demultiply();
            out.copy_from_slice(&[color.alpha(), color.red(), color.green(), color.blue()]);
        }
    }
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
