//! Operating-system boundaries. Vault policy and browser framing stay platform independent.

/// Windows uses Direct3D, which can fall back to WARP on VMs without a GPU.
/// Linux retains the existing OpenGL renderer.
pub fn native_options() -> eframe::NativeOptions {
    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions::default();
    #[cfg(windows)]
    {
        options.renderer = eframe::Renderer::Wgpu;
        if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_options.wgpu_setup
        {
            setup.instance_descriptor.backends = wgpu::Backends::DX12;
            // Windows includes FXC; do not require separately installed DXC DLLs.
            setup
                .instance_descriptor
                .backend_options
                .dx12
                .shader_compiler = wgpu::Dx12Compiler::Fxc;
            if std::env::var("BOLTWARDEN_SOFTWARE_RENDERING").as_deref() == Ok("1") {
                setup.native_adapter_selector = Some(std::sync::Arc::new(|adapters, surface| {
                    adapters
                        .iter()
                        .find(|adapter| {
                            adapter.get_info().device_type == wgpu::DeviceType::Cpu
                                && surface
                                    .is_none_or(|surface| adapter.is_surface_supported(surface))
                        })
                        .cloned()
                        .ok_or_else(|| "Windows software renderer is unavailable".to_owned())
                }));
            }
        }
    }
    options
}
#[cfg(target_os = "linux")]
pub mod ipc {
    pub use crate::unix_socket::*;
    pub use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};

    pub fn peer_pid(stream: &Stream) -> std::io::Result<u32> {
        use std::os::fd::AsRawFd;
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if credentials.uid != current_uid() || credentials.pid <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Peer is not allowed",
            ));
        }
        Ok(credentials.pid as u32)
    }
}
#[cfg(windows)]
#[path = "ipc_windows.rs"]
pub mod ipc;
#[cfg(windows)]
pub mod windows;
