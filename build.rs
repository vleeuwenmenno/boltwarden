use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        windows_resources();
    }
    println!("cargo:rustc-env=BOLTWARDEN_VERSION={}", build_version());
    println!("cargo:rerun-if-changed=THIRD_PARTY_NOTICES.txt");
    let notices = match fs::read_to_string("THIRD_PARTY_NOTICES.txt") {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => panic!("cannot read third-party notices: {error}"),
    };
    fs::write(
        PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"))
            .join("third_party_notices.txt"),
        notices,
    )
    .expect("write embedded third-party notices");
}

/// Version shown by the app. Tagged release builds (CI stamps the tag into
/// Cargo.toml) keep the plain package version; any other build from a git
/// checkout appends the commits since the latest release tag, the commit, and
/// `.dirty` for uncommitted changes, e.g. `1.0.0-rc.4+3.gabc1234.dirty`.
/// Builds without git metadata (Docker, Nix) keep the package version.
fn build_version() -> String {
    let package = env::var("CARGO_PKG_VERSION").unwrap();
    for path in ["src", "Cargo.toml", "Cargo.lock", "build.rs"] {
        println!("cargo:rerun-if-changed={path}");
    }
    for name in ["HEAD", "index", "refs", "packed-refs"] {
        if let Some(path) = git(&["rev-parse", "--git-path", name]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let Some(describe) = git(&[
        "describe", "--tags", "--long", "--dirty", "--match", "v[0-9]*",
    ]) else {
        return git(&["rev-parse", "--short", "HEAD"]).map_or(package.clone(), |commit| {
            format!("{package}+g{commit}.untagged")
        });
    };
    let (describe, dirty) = match describe.strip_suffix("-dirty") {
        Some(clean) => (clean, true),
        None => (describe.as_str(), false),
    };
    let mut parts = describe.rsplitn(3, '-');
    let (Some(commit), Some(ahead), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
        return package;
    };
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    if ahead == "0" && tag == package {
        // A release build at its tag; set-version.py's stamp makes the tree dirty.
        return package;
    }
    let mut version = format!("{tag}+{ahead}.{commit}");
    if dirty {
        version.push_str(".dirty");
    }
    version
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(env::var_os("CARGO_MANIFEST_DIR")?)
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    (output.status.success() && !text.trim().is_empty()).then(|| text.trim().to_owned())
}

fn windows_resources() {
    println!("cargo:rerun-if-changed=packaging/windows/app.manifest");
    println!("cargo:rerun-if-changed=extension/public/icon/128.png");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    // ICO supports PNG entries directly; use the existing canonical project icon.
    let png = fs::read("extension/public/icon/128.png").unwrap();
    let mut ico = vec![0, 0, 1, 0, 1, 0, 128, 128, 0, 0, 1, 0, 32, 0];
    ico.extend_from_slice(&(png.len() as u32).to_le_bytes());
    ico.extend_from_slice(&22u32.to_le_bytes());
    ico.extend_from_slice(&png);
    fs::write(out.join("boltwarden.ico"), ico).unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numeric = format!(
        "{},{},{},0",
        env::var("CARGO_PKG_VERSION_MAJOR").unwrap(),
        env::var("CARGO_PKG_VERSION_MINOR").unwrap(),
        env::var("CARGO_PKG_VERSION_PATCH").unwrap()
    );
    let manifest = fs::canonicalize("packaging/windows/app.manifest").unwrap();
    let icon = out.join("boltwarden.ico");
    let resource = format!(
        r#"
1 ICON "{icon}"
1 24 "{manifest}"
1 VERSIONINFO
 FILEVERSION {numeric}
 PRODUCTVERSION {numeric}
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0
 FILEOS 0x40004L
 FILETYPE 1
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "040904b0"
  BEGIN
   VALUE "CompanyName", "Menno van Leeuwen\0"
   VALUE "FileDescription", "Boltwarden\0"
   VALUE "FileVersion", "{version}\0"
   VALUE "ProductName", "Boltwarden\0"
   VALUE "ProductVersion", "{version}\0"
   VALUE "LegalCopyright", "Copyright Menno van Leeuwen\0"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x409, 1200
 END
END
"#,
        icon = icon.display().to_string().replace('\\', "/"),
        manifest = manifest.display().to_string().replace('\\', "/")
    );
    let rc = out.join("boltwarden.rc");
    fs::write(&rc, resource).unwrap();
    embed_resource::compile_for(
        &rc,
        &["boltwarden", "boltwarden-native-host"],
        embed_resource::NONE,
    )
    .manifest_required()
    .expect("compile Windows icon, version, and application manifest");
}
