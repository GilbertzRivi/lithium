#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(e) = lithiumd::run() {
        eprintln!("fatal: {e}");
        std::process::exit(1);
    }
}
