use std::sync::mpsc;

use ksni::blocking::{Handle, TrayMethods};

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
        "dialog-password".into()
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
    AppTray::new(tx)
        .assume_sni_available(true)
        .spawn()
}
