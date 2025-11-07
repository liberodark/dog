//! Debug error logging.

use owo_colors::OwoColorize;
use std::ffi::OsStr;

/// Sets the internal logger, changing the log level based on the value of an
/// environment variable.
pub fn configure<T: AsRef<OsStr>>(ev: Option<T>) {
    let ev = match ev {
        Some(v) => v,
        None => return,
    };

    let env_var = ev.as_ref();
    if env_var.is_empty() {
        return;
    }

    if env_var == "trace" {
        log::set_max_level(log::LevelFilter::Trace);
    } else {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let result = log::set_logger(GLOBAL_LOGGER);
    if let Err(e) = result {
        eprintln!("Failed to initialise logger: {}", e);
    }
}

#[derive(Debug)]
struct Logger;

const GLOBAL_LOGGER: &Logger = &Logger;

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true // no need to filter after using 'set_max_level'.
    }

    fn log(&self, record: &log::Record<'_>) {
        let open = "[".truecolor(150, 150, 150); // Fixed 243 approximation
        let level = level(record.level());
        let close = "]".truecolor(150, 150, 150);

        eprintln!(
            "{}{} {}{} {}",
            open,
            level,
            record.target(),
            close,
            record.args()
        );
    }

    fn flush(&self) {
        // no need to flush with 'eprintln!'.
    }
}

fn level(level: log::Level) -> String {
    match level {
        log::Level::Error => "ERROR".red().to_string(),
        log::Level::Warn => "WARN".yellow().to_string(),
        log::Level::Info => "INFO".cyan().to_string(),
        log::Level::Debug => "DEBUG".blue().to_string(),
        log::Level::Trace => "TRACE".truecolor(180, 180, 180).to_string(), // Fixed 245 approximation
    }
}
