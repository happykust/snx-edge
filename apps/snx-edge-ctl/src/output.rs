use serde::Serialize;
use tabled::settings::Style;
use tabled::{Table, Tabled};

/// Output mode controlled by --json / --quiet flags.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputMode {
    Table,
    Json,
    Quiet,
}

impl OutputMode {
    pub fn from_flags(json: bool, quiet: bool) -> Self {
        if quiet {
            OutputMode::Quiet
        } else if json {
            OutputMode::Json
        } else {
            OutputMode::Table
        }
    }
}

/// Print a list of items as a table or JSON.
pub fn print_list<T: Tabled + Serialize>(mode: OutputMode, items: &[T]) {
    match mode {
        OutputMode::Table => {
            if items.is_empty() {
                println!("(no results)");
            } else {
                let mut table = Table::new(items);
                table.with(Style::rounded());
                println!("{table}");
            }
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(items).unwrap_or_else(|_| "[]".to_string())
            );
        }
        OutputMode::Quiet => {}
    }
}

/// Print a single item as formatted debug output or JSON.
pub fn print_item<T: Serialize + std::fmt::Debug>(mode: OutputMode, item: &T) {
    match mode {
        OutputMode::Table => {
            println!("{:#?}", item);
        }
        OutputMode::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(item).unwrap_or_else(|_| "null".to_string())
            );
        }
        OutputMode::Quiet => {}
    }
}

/// Print a success message.
pub fn print_ok(mode: OutputMode, message: &str) {
    match mode {
        OutputMode::Table => println!("{}", message),
        OutputMode::Json => println!(r#"{{"status":"ok","message":"{}"}}"#, message),
        OutputMode::Quiet => {}
    }
}

/// Print an error message to stderr and exit with code 1.
pub fn print_error(mode: OutputMode, err: &anyhow::Error) {
    match mode {
        OutputMode::Json => {
            eprintln!(
                r#"{{"status":"error","message":"{}"}}"#,
                err.to_string().replace('"', "\\\"")
            );
        }
        _ => {
            eprintln!("Error: {err:#}");
        }
    }
}
