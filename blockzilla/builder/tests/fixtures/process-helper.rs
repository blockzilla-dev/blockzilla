//! Native subprocess fixture for descriptor inheritance and converter overlap.
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    process::{self, Command},
    thread,
    time::{Duration, Instant},
};

fn change(path: &Path, enter: bool, finish: bool) -> io::Result<[u64; 4]> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    file.lock()?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut counts: [u64; 4] = text
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    if enter {
        counts[0] += 1;
        counts[1] += 1;
        counts[2] = counts[2].max(counts[1]);
    }
    if finish {
        counts[1] -= 1;
        counts[3] += 1;
    }
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    writeln!(
        file,
        "{} {} {} {}",
        counts[0], counts[1], counts[2], counts[3]
    )?;
    file.flush()?;
    Ok(counts)
}

fn main() -> io::Result<()> {
    let config = std::env::current_exe()?.with_extension("config");
    if !config.exists() {
        if std::env::args().nth(1).as_deref() == Some("fds") {
            for entry in fs::read_dir("/proc/self/fd")? {
                if let Ok(path) = fs::read_link(entry?.path()) {
                    println!("{}", path.display());
                }
            }
        }
        return Ok(());
    }
    let text = fs::read_to_string(config)?;
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 4);
    let state = Path::new(lines[0]);
    change(state, true, false)?;
    let result = (|| -> io::Result<i32> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while change(state, false, false)?[0] < 4 {
            if Instant::now() >= deadline {
                return Err(io::Error::other("four converters did not overlap"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        if lines[3] == "true" {
            let stage = Path::new(lines[2]).join(format!("moving-{}", process::id()));
            let compact = stage.with_extension("compact");
            let until = Instant::now() + Duration::from_millis(400);
            while Instant::now() < until {
                fs::create_dir(&stage)?;
                fs::write(stage.join("payload"), [b'x'; 4096])?;
                fs::rename(&stage, &compact)?;
                thread::sleep(Duration::from_millis(1));
                fs::remove_file(compact.join("payload"))?;
                fs::remove_dir(&compact)?;
            }
        }
        Ok(Command::new(lines[1])
            .args(std::env::args_os().skip(1))
            .status()?
            .code()
            .unwrap_or(1))
    })();
    change(state, false, true)?;
    match result {
        Ok(code) => process::exit(code),
        Err(error) => Err(error),
    }
}
