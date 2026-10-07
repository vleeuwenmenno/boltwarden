//! Pairing proof verification and bounded framing shared by the daemon and native host.
use super::protocol::MAX_FRAME_BYTES;
use crate::platform::ipc::Stream as UnixStream;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use signature::Verifier;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

pub fn transcript(nonce: &str, pairing_id: &str, host_pid: u32) -> Vec<u8> {
    format!("boltwarden-browser-v1\n{nonce}\n{pairing_id}\n{host_pid}").into_bytes()
}

pub fn verify_proof(
    spki: &str,
    nonce: &str,
    pairing_id: &str,
    signed_pid: u32,
    peer_pid: u32,
    signature: &str,
) -> Result<(), String> {
    if signed_pid != peer_pid || peer_pid == 0 {
        return Err("Native host identity does not match this connection".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(spki)
        .map_err(|_| "Invalid public key encoding")?;
    if bytes.len() > 256 {
        return Err("Public key is too large".into());
    }
    let key = VerifyingKey::from_public_key_der(&bytes).map_err(|_| "Invalid P-256 public key")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "Invalid signature encoding")?;
    let signature = Signature::from_slice(&bytes).map_err(|_| "Invalid P-256 signature")?;
    key.verify(&transcript(nonce, pairing_id, signed_pid), &signature)
        .map_err(|_| "Pairing proof is not valid".into())
}

pub fn read_frame(
    reader: &mut impl Read,
    native_endian: bool,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = [0; 4];
    reader.read_exact(&mut bytes)?;
    let length = if native_endian {
        u32::from_ne_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    } as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Browser frame length is invalid",
        ));
    }
    let mut body = zeroize::Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut body)?;
    Ok(body)
}

/// macOS rejects socket options with EINVAL once the peer has closed, although data it
/// sent before closing is still readable. Let the read itself report end of stream.
pub fn set_read_timeout(socket: &UnixStream, timeout: Option<Duration>) -> io::Result<()> {
    match socket.set_read_timeout(timeout) {
        #[cfg(target_os = "macos")]
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        result => result,
    }
}

/// Idle authenticated connections are harmless; a partially delivered frame is not.
/// Start a cumulative five-second deadline after its first byte arrives.
pub fn read_socket_frame(
    socket: &mut UnixStream,
    lifetime_deadline: Option<Instant>,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let idle_timeout = lifetime_deadline
        .map(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "Browser handshake deadline expired",
                    )
                })
        })
        .transpose()?;
    set_read_timeout(socket, idle_timeout)?;
    let mut header = [0; 4];
    socket.read_exact(&mut header[..1]).map_err(|error| {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            io::Error::new(io::ErrorKind::WouldBlock, "Browser idle wait expired")
        } else {
            error
        }
    })?;
    let frame_deadline = Instant::now() + Duration::from_secs(5);
    let deadline = lifetime_deadline.map_or(frame_deadline, |end| end.min(frame_deadline));
    read_exact_before(socket, &mut header[1..], deadline)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Browser frame length is invalid",
        ));
    }
    let mut body = zeroize::Zeroizing::new(vec![0; length]);
    read_exact_before(socket, &mut body, deadline)?;
    Ok(body)
}

fn read_exact_before(
    socket: &mut UnixStream,
    mut buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !buffer.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "Browser frame deadline expired")
            })?;
        set_read_timeout(socket, Some(remaining))?;
        match socket.read(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Incomplete browser frame",
                ));
            }
            Ok(count) => buffer = &mut buffer[count..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Browser frame deadline expired",
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn write_socket_frame(socket: &mut UnixStream, body: &[u8]) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Browser frame length is invalid",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    for mut part in [&(body.len() as u32).to_be_bytes()[..], body] {
        while !part.is_empty() {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "Browser write deadline expired")
                })?;
            socket.set_write_timeout(Some(remaining))?;
            match socket.write(part) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "Browser connection stopped reading",
                    ));
                }
                Ok(count) => part = &part[count..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

pub fn write_frame(writer: &mut impl Write, body: &[u8], native_endian: bool) -> io::Result<()> {
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Browser frame length is invalid",
        ));
    }
    let length = body.len() as u32;
    writer.write_all(&if native_endian {
        length.to_ne_bytes()
    } else {
        length.to_be_bytes()
    })?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;
    use signature::Signer;
    #[test]
    fn proof_is_bound_to_nonce_id_and_kernel_peer() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let spki =
            URL_SAFE_NO_PAD.encode(key.verifying_key().to_public_key_der().unwrap().as_bytes());
        let signature: Signature = key.sign(&transcript("nonce", "id", 123));
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        assert!(verify_proof(&spki, "nonce", "id", 123, 123, &signature).is_ok());
        assert!(verify_proof(&spki, "other", "id", 123, 123, &signature).is_err());
        assert!(verify_proof(&spki, "nonce", "other", 123, 123, &signature).is_err());
        assert!(verify_proof(&spki, "nonce", "id", 123, 124, &signature).is_err());
    }

    #[test]
    fn verifies_shared_webcrypto_signature_fixture() {
        #[derive(serde::Deserialize)]
        struct Proof {
            public_key_spki: String,
            nonce: String,
            pairing_id: String,
            host_pid: u32,
            sig: String,
        }
        let proof: Proof = serde_json::from_str(include_str!(
            "../../extension/protocol/fixtures/pairing-proof.json"
        ))
        .unwrap();
        assert!(
            verify_proof(
                &proof.public_key_spki,
                &proof.nonce,
                &proof.pairing_id,
                proof.host_pid,
                proof.host_pid,
                &proof.sig
            )
            .is_ok()
        );
        assert!(
            verify_proof(
                &proof.public_key_spki,
                &proof.nonce,
                &proof.pairing_id,
                proof.host_pid,
                proof.host_pid + 1,
                &proof.sig
            )
            .is_err()
        );
    }
    #[test]
    fn bounded_framing_round_trips_native_and_network_byte_orders() {
        for little in [false, true] {
            let mut wire = Vec::new();
            write_frame(&mut wire, b"{}", little).unwrap();
            assert_eq!(&**read_frame(&mut wire.as_slice(), little).unwrap(), b"{}");
        }
        assert!(
            read_frame(
                &mut (MAX_FRAME_BYTES as u32 + 1).to_be_bytes().as_slice(),
                false
            )
            .is_err()
        );
        assert!(read_frame(&mut [0, 0, 0, 0].as_slice(), false).is_err());
        assert!(read_frame(&mut [0, 0, 0, 2, 1].as_slice(), false).is_err());
    }

    #[test]
    fn partial_frame_has_cumulative_deadline_even_with_progress() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            for _ in 0..10 {
                if writer.write_all(&[1]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let mut body = [0; 10];
        let error = read_exact_before(
            &mut reader,
            &mut body,
            Instant::now() + Duration::from_millis(50),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        drop(reader);
        sender.join().unwrap();
    }

    #[test]
    fn socket_frame_accepts_an_idle_connection_then_a_complete_message() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            write_socket_frame(&mut writer, b"{}").unwrap();
        });
        assert_eq!(&**read_socket_frame(&mut reader, None).unwrap(), b"{}");
        sender.join().unwrap();
    }
}
