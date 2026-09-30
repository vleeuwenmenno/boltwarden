use std::sync::{LazyLock, mpsc};

use ksni::blocking::{Handle, TrayMethods};

static TRAY_ICONS: LazyLock<Vec<ksni::Icon>> = LazyLock::new(|| {
    vec![
        render_tray_icon(16),
        render_tray_icon(22),
        render_tray_icon(32),
    ]
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayCommand {
    Show,
    Hide,
    Toggle,
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

fn render_tray_icon(size: i32) -> ksni::Icon {
    let mut data = Vec::with_capacity((size * size * 4) as usize);
    let samples = 4;
    for y in 0..size {
        for x in 0..size {
            let mut coverage = 0.0;
            let mut highlight = 0.0;
            let mut cutout = 0.0;

            for sy in 0..samples {
                for sx in 0..samples {
                    let px = (x as f32 + (sx as f32 + 0.5) / samples as f32) / size as f32;
                    let py = (y as f32 + (sy as f32 + 0.5) / samples as f32) / size as f32;
                    if in_shield(px, py) {
                        coverage += 1.0;
                        if py < 0.22 && px > 0.30 && px < 0.70 {
                            highlight += 1.0;
                        }
                        if in_keyhole(px, py) {
                            cutout += 1.0;
                        }
                    }
                }
            }

            let total = (samples * samples) as f32;
            let shield_alpha = coverage / total;
            let cutout_alpha = (cutout / total).min(shield_alpha);
            let visible_alpha = (shield_alpha - cutout_alpha).clamp(0.0, 1.0);
            let highlight_mix = if coverage > 0.0 {
                (highlight / coverage).clamp(0.0, 1.0) * 0.28
            } else {
                0.0
            };

            let base = [23.0, 93.0, 220.0];
            let light = [71.0, 147.0, 255.0];
            let r = mix(base[0], light[0], highlight_mix) as u8;
            let g = mix(base[1], light[1], highlight_mix) as u8;
            let b = mix(base[2], light[2], highlight_mix) as u8;
            let a = (visible_alpha * 255.0).round() as u8;

            data.extend_from_slice(&[a, r, g, b]);
        }
    }

    ksni::Icon {
        width: size,
        height: size,
        data,
    }
}

fn in_shield(x: f32, y: f32) -> bool {
    let left = if y < 0.22 {
        0.25
    } else if y < 0.58 {
        0.18 + (y - 0.22) * 0.11
    } else {
        0.22 + (y - 0.58) * 0.76
    };
    let right = 1.0 - left;
    y >= 0.08 && y <= 0.92 && x >= left && x <= right
}

fn in_keyhole(x: f32, y: f32) -> bool {
    let dx = x - 0.50;
    let dy = y - 0.42;
    let head = dx * dx + dy * dy <= 0.105 * 0.105;
    let stem = x >= 0.455 && x <= 0.545 && y >= 0.47 && y <= 0.70;
    head || stem
}

fn mix(a: f32, b: f32, t: f32) -> f32 {
    a + (b - a) * t
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
