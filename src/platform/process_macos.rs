//! Process details from libproc and sysctl, the macOS counterparts of Linux `/proc` reads.
use std::ffi::{CStr, c_char, c_int};

fn bsd_info(pid: u32) -> Option<libc::proc_bsdinfo> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (written == size).then_some(info)
}

fn c_string(bytes: &[c_char]) -> Option<String> {
    let bytes: Vec<u8> = bytes
        .iter()
        .map(|&byte| byte as u8)
        .take_while(|&byte| byte != 0)
        .collect();
    let value = String::from_utf8_lossy(&bytes).trim().to_string();
    (!value.is_empty()).then_some(value)
}

pub fn ppid(pid: u32) -> Option<u32> {
    bsd_info(pid).map(|info| info.pbi_ppid)
}

/// Process start time in microseconds since the epoch. Together with the pid it
/// identifies one process, so a reused pid does not match an earlier approval.
pub fn start_time(pid: u32) -> Option<u64> {
    bsd_info(pid).map(|info| {
        info.pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(info.pbi_start_tvusec)
    })
}

pub fn name(pid: u32) -> Option<String> {
    let info = bsd_info(pid)?;
    c_string(&info.pbi_name).or_else(|| c_string(&info.pbi_comm))
}

pub fn executable(pid: u32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        libc::proc_pidpath(
            pid as c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    buffer.truncate(length as usize);
    String::from_utf8(buffer).ok()
}

pub fn cwd(pid: u32) -> Option<String> {
    let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as c_int,
            libc::PROC_PIDVNODEPATHINFO,
            0,
            (&mut info as *mut libc::proc_vnodepathinfo).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    c_string(info.pvi_cdir.vip_path.as_flattened())
}

/// Arguments from `KERN_PROCARGS2`: argc, the executable path, padding, then argv.
pub fn command_line(pid: u32) -> Option<String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as c_int];
    let mut length = 0usize;
    let mut sysctl = |buffer: *mut libc::c_void, length: &mut usize| unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buffer,
            length,
            std::ptr::null_mut(),
            0,
        )
    };
    if sysctl(std::ptr::null_mut(), &mut length) != 0 || length < 4 {
        return None;
    }
    let mut buffer = vec![0u8; length];
    if sysctl(buffer.as_mut_ptr().cast(), &mut length) != 0 || length < 4 {
        return None;
    }
    buffer.truncate(length);
    let argc = i32::from_ne_bytes(buffer[..4].try_into().ok()?);
    let mut rest = &buffer[4..];
    let path = CStr::from_bytes_until_nul(rest).ok()?;
    rest = &rest[path.to_bytes_with_nul().len()..];
    let start = rest.iter().position(|&byte| byte != 0)?;
    let parts: Vec<&str> = rest[start..]
        .split(|&byte| byte == 0)
        .take(usize::try_from(argc).ok()?)
        .filter(|part| !part.is_empty())
        .filter_map(|part| std::str::from_utf8(part).ok())
        .collect();
    (!parts.is_empty()).then(|| parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_the_current_process() {
        let pid = std::process::id();
        assert_eq!(ppid(pid), Some(std::os::unix::process::parent_id()));
        assert!(start_time(pid).is_some_and(|time| time > 0));
        assert!(name(pid).is_some());
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
        assert_eq!(executable(pid).map(std::path::PathBuf::from), Some(exe));
        let dir = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert_eq!(cwd(pid).map(std::path::PathBuf::from), Some(dir));
        let command = command_line(pid).unwrap();
        assert!(command.contains(std::env::args().next().unwrap().as_str()));
    }

    #[test]
    fn missing_process_has_no_details() {
        assert_eq!(start_time(u32::MAX >> 1), None);
        assert_eq!(executable(u32::MAX >> 1), None);
    }
}
