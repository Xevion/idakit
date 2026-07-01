//! Record EULA acceptance into `$HOME/.idapro`, once. Headless `idalib` refuses to open a
//! database until the agreement is accepted, so a fresh home needs this run before tests.
//!
//!   cargo run -p idakit --example accept_eula

fn main() {
    let idb = idakit::Ida::here().expect("kernel init failed");
    if idb.accept_eula() {
        println!("EULA accepted for this $HOME");
    } else {
        eprintln!("failed to record EULA acceptance");
        std::process::exit(1);
    }
}
