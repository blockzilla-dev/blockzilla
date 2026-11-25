//! Native process fixture for ledger reader bounds and exit-code tests.
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
    process, thread,
    time::Duration,
};

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(args[1], "read-slot-compact");
    assert_eq!(args[2], "--ledger");
    assert_eq!(args[4], "--slot");
    let ledger = PathBuf::from(&args[3]);
    fs::write(ledger.join("helper.pid"), process::id().to_string())?;
    let action = fs::read_to_string(std::env::current_exe()?.with_extension("config"))?;
    match action.as_str() {
        "emit" => {}
        "absent" => process::exit(3),
        "unrooted" => process::exit(4),
        "incomplete" => process::exit(5),
        "timeout" => thread::sleep(Duration::from_secs(30)),
        "wait_release" => {
            while !ledger.join("release").exists() {
                thread::sleep(Duration::from_millis(5));
            }
        }
        "stderr" => {
            io::stderr().write_all(&vec![b'x'; 16_385])?;
            io::stderr().flush()?;
        }
        "stdout" => {
            let mut output = io::stdout().lock();
            output.write_all(b"BZLGR01!\x01\0\0\0{}")?;
            output.write_all(&vec![b'x'; 16 * 1024 * 1024 + 4096])?;
            output.flush()?;
        }
        _ => panic!("unknown fixture action"),
    }
    io::stdout().write_all(&fs::read(ledger.join("fixture.frame"))?)
}
