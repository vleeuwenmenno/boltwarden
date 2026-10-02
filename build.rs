use std::{env, fs, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        windows_resources();
    }
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
