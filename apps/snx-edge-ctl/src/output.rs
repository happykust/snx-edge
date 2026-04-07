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

/// Print a single item as key-value pairs or JSON.
pub fn print_item<T: Serialize>(mode: OutputMode, item: &T) {
    match mode {
        OutputMode::Table => {
            if let Ok(serde_json::Value::Object(map)) = serde_json::to_value(item) {
                // Find the longest key for alignment
                let max_key_len = map.keys().map(|k| k.len()).max().unwrap_or(0);
                for (key, value) in &map {
                    let display_value = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => "-".to_string(),
                        serde_json::Value::Array(arr) => {
                            let items: Vec<String> = arr
                                .iter()
                                .map(|v| match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    other => other.to_string(),
                                })
                                .collect();
                            if items.is_empty() {
                                "-".to_string()
                            } else {
                                items.join(", ")
                            }
                        }
                        other => other.to_string(),
                    };
                    println!("{:<width$}  {}", format!("{}:", key), display_value, width = max_key_len + 1);
                }
            } else {
                // Fallback for non-object types
                println!(
                    "{}",
                    serde_json::to_string_pretty(item).unwrap_or_else(|_| "null".to_string())
                );
            }
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
