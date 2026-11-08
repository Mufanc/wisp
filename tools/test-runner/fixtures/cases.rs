use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{process, thread};

static USED: AtomicBool = AtomicBool::new(false);

fn isolated_case() {
    assert!(!USED.swap(true, Ordering::SeqCst), "shared test process");

    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    thread::sleep(Duration::from_millis(200));

    let end = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();

    println!("\nPROCESS {} {start} {end}", process::id());
}

macro_rules! cases {
    ($($name:ident),*) => { $(#[test] fn $name() { isolated_case(); })* };
}

cases!(
    isolated_a, isolated_b, isolated_c, isolated_d, isolated_e, isolated_f, isolated_g, isolated_h
);

#[test]
#[ignore]
fn intentional_panic() {
    panic!("fixture panic");
}

#[test]
#[ignore]
fn intentional_abort() {
    process::abort();
}

#[test]
#[ignore]
fn intentional_timeout() {
    thread::sleep(Duration::from_secs(10));
}

#[test]
#[ignore]
fn z_after_failures() {
    println!("SURVIVED");
}

#[test]
fn large_output() {
    let stdout = thread::spawn(|| {
        let mut output = io::stdout().lock();

        output.write_all(b"\nOUT_DATA\n").unwrap();
        output.write_all(&vec![b'o'; 1024 * 1024]).unwrap();
        output.write_all(b"\nOUT_END\n").unwrap();
    });
    let mut stderr = io::stderr().lock();

    stderr.write_all(b"\nERR_DATA\n").unwrap();
    stderr.write_all(&vec![b'e'; 1024 * 1024]).unwrap();
    stderr.write_all(b"\nERR_END\n").unwrap();
    drop(stderr);
    stdout.join().unwrap();
}
