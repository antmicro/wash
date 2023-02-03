// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .expect("Failed getting commit hash from git")
        .stdout;
    println!(
        "cargo:rustc-env=SHELL_COMMIT_HASH={}",
        std::str::from_utf8(&hash)?
    );
    let date_commit = std::process::Command::new("git")
        .args([
            "show",
            "--quiet",
            "--format=%cd",
            "--date",
            "format-local:%Y-%m-%d %H:%M:%S %z",
        ])
        .env("TZ", "UTC0")
        .output()
        .expect("Failed getting commit date from git")
        .stdout;
    println!(
        "cargo:rustc-env=SHELL_COMMIT_DATE={}",
        std::str::from_utf8(&date_commit)?
    );
    let date_compile = std::process::Command::new("date")
        .args(["+%Y-%m-%d %R:%S %z"])
        .env("TZ", "UTC0")
        .output()
        .expect("Failed getting compile date")
        .stdout;
    println!(
        "cargo:rustc-env=SHELL_COMPILE_DATE={}",
        std::str::from_utf8(&date_compile)?
    );
    println!("cargo:rustc-env=SHELL_TARGET={}", std::env::var("TARGET")?);

    Ok(())
}
