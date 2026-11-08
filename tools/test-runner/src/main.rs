use libtest_mimic::{Arguments, Trial};
use std::env;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_PROCESSES: usize = 4;

fn execute(binary: &Path, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    // Drain both pipes while waiting so verbose tests cannot block on a full pipe.
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();

                break Err(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, format!("exceeded {timeout:?}"))
                }));
            }
        }
    };
    let stdout = out.join().unwrap()?;
    let stderr = err.join().unwrap()?;

    match status {
        Ok(status) => Ok(Output {
            status,
            stdout,
            stderr,
        }),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "{error}\n{}\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            ),
        )),
    }
}

fn discover(binary: &Path, ignored: bool, timeout: Duration) -> Result<Vec<String>, String> {
    let mut args = vec!["--list", "--format=terse"];

    if ignored {
        args.push("--ignored");
    }

    let output = execute(binary, &args, timeout).map_err(|error| error.to_string())?;

    if !output.status.success() {
        return Err(format!(
            "test discovery failed: {}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;

    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.strip_suffix(": test")
                .map(str::to_owned)
                .ok_or_else(|| format!("unexpected test listing: {line}"))
        })
        .collect()
}

fn run() -> Result<(), String> {
    let mut cli = env::args_os();
    let program = cli.next().unwrap();
    let binary = PathBuf::from(
        cli.next()
            .ok_or("usage: wisp-test-runner TEST_BINARY [TEST_ARGS...]")?,
    );
    let mut args = Arguments::from_iter(std::iter::once(program).chain(cli));

    args.test_threads = Some(
        args.test_threads
            .unwrap_or(MAX_PROCESSES)
            .clamp(1, MAX_PROCESSES),
    );

    let seconds = env::var("WISP_TEST_TIMEOUT")
        .unwrap_or_else(|_| "30".into())
        .parse::<u64>()
        .map_err(|_| "WISP_TEST_TIMEOUT must be a positive number of seconds")?;

    if seconds == 0 {
        return Err("WISP_TEST_TIMEOUT must be positive".into());
    }

    let timeout = Duration::from_secs(seconds);
    let names = discover(&binary, false, timeout)?;
    let ignored = discover(&binary, true, timeout)?;
    let show_output = args.nocapture || args.show_output;
    let tests = names
        .into_iter()
        .map(|name| {
            let binary = binary.clone();
            let is_ignored = ignored.contains(&name);

            Trial::test(name.clone(), move || {
                let output = execute(
                    &binary,
                    &[
                        &name,
                        "--exact",
                        "--include-ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ],
                    timeout,
                )?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if !output.status.success() {
                    return Err(format!("{}\n{stdout}\n{stderr}", output.status).into());
                }

                if !stdout
                    .lines()
                    .any(|line| line.starts_with("test result: ok. 1 passed;"))
                {
                    return Err(
                        format!("expected exactly one passing test\n{stdout}\n{stderr}").into(),
                    );
                }

                if show_output {
                    println!("--- {name} ---\n{stdout}\n{stderr}");
                }

                Ok(())
            })
            .with_ignored_flag(is_ignored)
        })
        .collect();

    libtest_mimic::run(&args, tests).exit();
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}
