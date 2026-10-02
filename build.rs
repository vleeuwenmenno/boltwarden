use std::{env, fs, path::PathBuf};

fn main() {
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
