#![expect(
    clippy::disallowed_methods,
    reason = "the scratch directory is private to the test and its paths are only compared"
)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn ci_outside_its_checkout_exits_1_and_names_both_paths() {
    let outside = env::temp_dir().join(format!("xtask-ci-outside-{}", std::process::id()));
    if outside.exists() {
        fs::remove_dir_all(&outside).unwrap();
    }
    fs::create_dir_all(&outside).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("ci")
        .current_dir(&outside)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    let built = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let here = fs::canonicalize(&outside).unwrap();
    for path in [built, here] {
        assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    }
    assert!(
        output.stdout.is_empty(),
        "ci ran a step before the checkout check"
    );
    fs::remove_dir_all(&outside).unwrap();
}
