use crate::platform::ipc::{Listener as UnixListener, Stream as UnixStream};
use std::path::PathBuf;

const SOCKET_NAME: &str = "boltwarden.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchCommand {
    Show,
    Toggle,
    /// Open the full vault window.
    Window,
    ToggleWindow,
    Daemon,
    Quit,
}

impl LaunchCommand {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Self {
        for arg in args {
            if arg == "quit" || arg == "--quit" {
                return Self::Quit;
            }
            if arg == "--daemon" || arg == "daemon" {
                return Self::Daemon;
            }
            if arg == "--toggle" || arg == "toggle" {
                return Self::Toggle;
            }
            if arg == "--window" || arg == "window" {
                return Self::Window;
            }
            if arg == "--toggle-window" || arg == "toggle-window" {
                return Self::ToggleWindow;
            }
        }
        Self::Show
    }

    fn wire(self) -> &'static [u8] {
        match self {
            Self::Show => b"show\n",
            Self::Toggle => b"toggle\n",
            Self::Window => b"window\n",
            Self::ToggleWindow => b"toggle-window\n",
            Self::Daemon => b"daemon\n",
            Self::Quit => b"quit\n",
        }
    }

    pub fn parse(message: &str) -> Self {
        match message.trim() {
            "toggle" => Self::Toggle,
            "window" => Self::Window,
            "toggle-window" => Self::ToggleWindow,
            "daemon" => Self::Daemon,
            "quit" => Self::Quit,
            _ => Self::Show,
        }
    }
}

pub enum Instance {
    Primary(Option<UnixListener>),
    Failed(String),
    ActivatedExisting,
}

pub fn prepare(command: LaunchCommand) -> Instance {
    let Some(path) = socket_path() else {
        return Instance::Failed("Activation endpoint unavailable".into());
    };

    prepare_at_path(path, command)
}

fn prepare_at_path(path: PathBuf, command: LaunchCommand) -> Instance {
    match activate_existing(&path, command) {
        Ok(true) => return Instance::ActivatedExisting,
        Ok(false) => (),
        Err(error) => return Instance::Failed(error.to_string()),
    }
    if command == LaunchCommand::Quit {
        return Instance::ActivatedExisting;
    }

    match crate::platform::ipc::bind_private(&path) {
        Ok(listener) => Instance::Primary(Some(listener)),
        Err(e) => {
            eprintln!("could not start activation socket: {e}");
            Instance::Failed(e.to_string())
        }
    }
}

fn activate_existing(path: &PathBuf, command: LaunchCommand) -> std::io::Result<bool> {
    #[cfg(windows)]
    use std::io::Read;
    use std::io::Write;
    let mut stream = match UnixStream::connect(path) {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    #[cfg(windows)]
    let quitting_process = if command == LaunchCommand::Quit {
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
        Some(crate::platform::windows::handle(unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE,
                0,
                crate::platform::ipc::peer_pid(&stream)?,
            )
        })?)
    } else {
        None
    };
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.write_all(command.wire())?;
    #[cfg(windows)]
    {
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut ack = [0];
        stream.read_exact(&mut ack)?;
        if ack != [1] {
            return Err(std::io::Error::other("Activation was rejected"));
        }
    }
    #[cfg(windows)]
    if let Some(process) = quitting_process {
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject,
        };
        if unsafe { WaitForSingleObject(crate::platform::windows::raw(&process), 15_000) }
            != WAIT_OBJECT_0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Boltwarden did not exit; save edits and quit before upgrading",
            ));
        }
    }
    Ok(true)
}

fn socket_path() -> Option<PathBuf> {
    match crate::platform::ipc::runtime_dir() {
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
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::io::Read;

    #[test]
    #[cfg(unix)]
    fn activating_existing_instance_sends_show_message() {
        let temp = crate::test_temp_dir().join(format!("boltwarden-{}", uuid::Uuid::new_v4()));
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
            Instance::Failed(error) => panic!("{error}"),
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
    #[cfg(unix)]
    fn activating_existing_instance_sends_toggle_message() {
        let temp = crate::test_temp_dir().join(format!("boltwarden-{}", uuid::Uuid::new_v4()));
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
            Instance::Failed(error) => panic!("{error}"),
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
    fn launch_command_parses_window_args() {
        for (arg, command) in [
            ("--window", LaunchCommand::Window),
            ("window", LaunchCommand::Window),
            ("--toggle-window", LaunchCommand::ToggleWindow),
            ("toggle-window", LaunchCommand::ToggleWindow),
        ] {
            assert_eq!(LaunchCommand::from_args([arg.to_string()]), command);
            let wire = std::str::from_utf8(command.wire()).unwrap();
            assert_eq!(LaunchCommand::parse(wire), command);
        }
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
