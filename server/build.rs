use std::{env, process::Command};

fn main() {
    let rustc_version = env::var("RUSTC_VERSION").unwrap_or_else(|_| {
        Command::new("rustc")
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .unwrap_or_else(|| "unknown".to_string())
            .trim()
            .to_string()
    });

    println!("cargo:rustc-env=RUSTC_VERSION={rustc_version}");
}
