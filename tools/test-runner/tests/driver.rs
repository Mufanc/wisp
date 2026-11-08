use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::{env, fs};

fn check(fixture: &Path, args: &[&str], success: bool) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_wisp-test-runner"))
        .arg(fixture)
        .args(args)
        .env("WISP_TEST_TIMEOUT", "1")
        .output()
        .unwrap();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(output.status.success(), success, "{text}");

    text
}

fn compile_fixture(case: &str) -> PathBuf {
    let directory = env::temp_dir().join(format!("wisp-runner-check-{}-{case}", process::id()));

    fs::create_dir(&directory).unwrap();

    let fixture = directory.join("cases");
    let status = Command::new("rustc")
        .args(["--test", "--edition=2024"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/cases.rs"))
        .arg("-o")
        .arg(&fixture)
        .status()
        .unwrap();

    assert!(status.success());

    fixture
}

#[test]
fn isolates_tests_and_limits_concurrency() {
    let fixture = compile_fixture("isolation");

    for threads in ["1", "4", "8"] {
        let text = check(
            &fixture,
            &["isolated_", "--nocapture", "--test-threads", threads],
            true,
        );
        let mut pids = HashSet::new();
        let mut events = Vec::new();

        for line in text.lines().filter(|line| line.starts_with("PROCESS ")) {
            let fields: Vec<_> = line.split_whitespace().collect();

            assert!(pids.insert(fields[1].to_owned()), "{text}");
            events.push((fields[2].parse::<u128>().unwrap(), 1));
            events.push((fields[3].parse::<u128>().unwrap(), -1));
        }

        assert_eq!(pids.len(), 8, "{text}");
        events.sort_unstable();

        let mut active = 0;
        let mut peak = 0;

        for (_, change) in events {
            active += change;
            peak = peak.max(active);
        }

        assert!(
            peak <= if threads == "1" { 1 } else { 4 },
            "peak={peak}\n{text}"
        );

        if threads != "1" {
            assert!(peak > 1, "tests did not overlap\n{text}");
        }
    }

    fs::remove_dir_all(fixture.parent().unwrap()).unwrap();
}

#[test]
fn filters_tests_and_preserves_ignored_status() {
    let fixture = compile_fixture("filters");
    let text = check(&fixture, &["--list", "--ignored"], true);

    assert!(text.contains("intentional_abort: test"));
    assert!(!text.contains("isolated_a: test"));

    let text = check(&fixture, &["isolated_a", "--exact"], true);

    assert!(text.contains("1 passed; 0 failed"));

    let text = check(&fixture, &["isolated_", "--skip", "isolated_a"], true);

    assert!(text.contains("7 passed; 0 failed"));

    fs::remove_dir_all(fixture.parent().unwrap()).unwrap();
}

#[test]
fn continues_after_panics_crashes_and_timeouts() {
    let fixture = compile_fixture("failures");
    let text = check(
        &fixture,
        &["--ignored", "--nocapture", "--test-threads=1"],
        false,
    );

    assert!(text.contains("1 passed; 3 failed"), "{text}");
    assert!(text.contains("fixture panic"), "{text}");
    assert!(text.contains("exceeded 1s"), "{text}");
    assert!(text.contains("SURVIVED"), "{text}");
    fs::remove_dir_all(fixture.parent().unwrap()).unwrap();
}

#[test]
fn captures_large_stdout_and_stderr_without_blocking() {
    let fixture = compile_fixture("output");
    let text = check(&fixture, &["large_output", "--exact", "--nocapture"], true);

    for (start, end, byte) in [
        ("OUT_DATA\n", "\nOUT_END", b'o'),
        ("ERR_DATA\n", "\nERR_END", b'e'),
    ] {
        let data = text.split_once(start).unwrap().1.split_once(end).unwrap().0;
        assert_eq!(data.len(), 1024 * 1024);
        assert!(data.bytes().all(|value| value == byte));
    }

    fs::remove_dir_all(fixture.parent().unwrap()).unwrap();
}
