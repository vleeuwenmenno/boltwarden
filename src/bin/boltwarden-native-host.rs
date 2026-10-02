fn main() {
    if let Err(error) = boltwarden::native_host_main() {
        eprintln!("native host: {error}");
        std::process::exit(1);
    }
}
