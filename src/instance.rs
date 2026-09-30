use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

const SOCKET_NAME: &str = "bw-quick-access.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchCommand {
    Show,
    Toggle,
    Daemon,
}

impl LaunchCommand {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        for arg in args {
            if arg == "--daemon" || arg == "daemon" {
                return Self::Daemon;
            }
            if arg == "--toggle" || arg == "toggle" {
                return Self::Toggle;
            }
        }
        Self::Show
    }

    fn wire(self) -> &'static [u8] {
        match self {
            Self::Show => b"show\n",
            Self::Toggle => b"toggle\n",
            Self::Daemon => b"daemon\n",
        }
    }

    pub fn parse(message: &str) -> Self {
        match message.trim() {
            "toggle" => Self::Toggle,
            "daemon" => Self::Daemon,
            _ => Self::Show,
        }
    }
}

pub enum Instance {
    Primary(Option<UnixListener>),
    ActivatedExisting,
}

pub fn prepare(command: LaunchCommand) -> Instance {
    let Some(path) = socket_path() else {
        return Instance::Primary(None);
    };

    prepare_at_path(path, command)
}

fn prepare_at_path(path: PathBuf, command: LaunchCommand) -> Instance {
    if activate_existing(&path, command) {
        return Instance::ActivatedExisting;
    }

    match crate::unix_socket::bind_private(&path) {
        Ok(listener) => Instance::Primary(Some(listener)),
        Err(e) => {
            eprintln!("could not start activation socket: {e}");
            Instance::Primary(None)
        }
    }
}

fn activate_existing(path: &PathBuf, command: LaunchCommand) -> bool {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return false;
    };
    if command == LaunchCommand::Daemon {
        return true;
    }
    stream.write_all(command.wire()).is_ok()
}

fn socket_path() -> Option<PathBuf> {
    match crate::unix_socket::runtime_dir() {
        Ok(dir) => Some(dir.join(SOCKET_NAME)),
        Err(e) => {
            eprintln!("could not prepare socket directory: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn activating_existing_instance_sends_show_message() {
        let temp = std::env::temp_dir().join(format!("bwqa-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp).unwrap();
        let socket = temp.join(SOCKET_NAME);
        match UnixListener::bind(&socket) {
            Ok(listener) => drop(listener),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = fs::remove_dir_all(temp);
                return;
            }
            Err(e) => panic!("test could not preflight bind Unix socket: {e}"),
        }
        let _ = fs::remove_file(&socket);

        let first = prepare_at_path(socket.clone(), LaunchCommand::Show);
        let listener = match first {
            Instance::Primary(Some(listener)) => listener,
            Instance::Primary(None) => panic!("first prepare could not create a listener"),
            Instance::ActivatedExisting => panic!("first prepare activated an existing instance"),
        };

        assert!(matches!(
            prepare_at_path(socket, LaunchCommand::Show),
            Instance::ActivatedExisting
        ));
        let (mut stream, _) = listener.accept().unwrap();
        let mut message = String::new();
        stream.read_to_string(&mut message).unwrap();

        let _ = fs::remove_dir_all(temp);
        assert_eq!(message, "show\n");
    }

    #[test]
    fn activating_existing_instance_sends_toggle_message() {
        let temp = std::env::temp_dir().join(format!("bwqa-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp).unwrap();
        let socket = temp.join(SOCKET_NAME);
        match UnixListener::bind(&socket) {
            Ok(listener) => drop(listener),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                let _ = fs::remove_dir_all(temp);
                return;
            }
            Err(e) => panic!("test could not preflight bind Unix socket: {e}"),
        }
        let _ = fs::remove_file(&socket);

        let first = prepare_at_path(socket.clone(), LaunchCommand::Show);
        let listener = match first {
            Instance::Primary(Some(listener)) => listener,
            Instance::Primary(None) => panic!("first prepare could not create a listener"),
            Instance::ActivatedExisting => panic!("first prepare activated an existing instance"),
        };

        assert!(matches!(
            prepare_at_path(socket, LaunchCommand::Toggle),
            Instance::ActivatedExisting
        ));
        let (mut stream, _) = listener.accept().unwrap();
        let mut message = String::new();
        stream.read_to_string(&mut message).unwrap();

        let _ = fs::remove_dir_all(temp);
        assert_eq!(message, "toggle\n");
    }

    #[test]
    fn launch_command_parses_toggle_arg() {
        assert_eq!(
            LaunchCommand::from_args(["--toggle".to_string()]),
            LaunchCommand::Toggle
        );
        assert_eq!(
            LaunchCommand::from_args(["toggle".to_string()]),
            LaunchCommand::Toggle
        );
        assert_eq!(
            LaunchCommand::from_args(["--anything-else".to_string()]),
            LaunchCommand::Show
        );
    }

    #[test]
    fn launch_command_parses_daemon_arg() {
        assert_eq!(
            LaunchCommand::from_args(["--daemon".to_string()]),
            LaunchCommand::Daemon
        );
        assert_eq!(
            LaunchCommand::from_args(["daemon".to_string()]),
            LaunchCommand::Daemon
        );
    }
}
