//! Stdio reframer. HostContext is local transport evidence, never a daemon message.
use super::{protocol, session};
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Duration;

pub fn run_native_host() -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let context = serde_json::json!({"version": protocol::VERSION, "type": "HostContext", "host_pid": std::process::id()});
    session::write_frame(&mut output, &serde_json::to_vec(&context)?, true)?;
    let mut socket = match super::socket_path().and_then(UnixStream::connect) {
        Ok(socket) => socket,
        Err(_) => {
            let error = serde_json::json!({"version": protocol::VERSION, "type": "Error", "code": "DaemonUnavailable", "message": "Start the Boltwarden daemon and try again"});
            session::write_frame(&mut output, &serde_json::to_vec(&error)?, true)?;
            return Ok(());
        }
    };
    if crate::unix_socket::peer_uid(&socket)? != crate::unix_socket::current_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Daemon peer is not allowed",
        ));
    }
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut outgoing = socket.try_clone()?;
    std::thread::spawn(move || {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        while let Ok(body) = session::read_frame(&mut input, true) {
            if session::write_frame(&mut outgoing, &body, false).is_err() {
                break;
            }
        }
        let _ = outgoing.shutdown(Shutdown::Both);
    });
    while let Ok(body) = session::read_frame(&mut socket, false) {
        // A fake local daemon must not impersonate the PID emitted by this host.
        #[derive(serde::Deserialize)]
        struct MessageType {
            #[serde(rename = "type")]
            kind: String,
        }
        let message: MessageType = serde_json::from_slice(&body)?;
        if message.kind == "HostContext" {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Reserved native-host message received",
            ));
        }
        if session::write_frame(&mut output, &body, true).is_err() {
            break;
        }
    }
    let _ = socket.shutdown(Shutdown::Both);
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reframes_native_json_without_changing_payload() {
        let payload = br#"{"version":1,"id":"status","type":"Status"}"#;
        let mut native = Vec::new();
        session::write_frame(&mut native, payload, true).unwrap();
        let decoded = session::read_frame(&mut native.as_slice(), true).unwrap();
        let mut daemon = Vec::new();
        session::write_frame(&mut daemon, &decoded, false).unwrap();
        assert_eq!(&daemon[4..], payload);
        assert_eq!(&daemon[..4], &(payload.len() as u32).to_be_bytes());
    }
}
