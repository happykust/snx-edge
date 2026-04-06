use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;

// ============================================================================
// Widget names used for tree lookups
// ============================================================================

const LOG_TEXT_VIEW: &str = "log-text-view";
const LEVEL_DROPDOWN: &str = "level-dropdown";

// ============================================================================
// Tag names for coloured log levels
// ============================================================================

const TAG_ERROR: &str = "log-error";
const TAG_WARN: &str = "log-warn";
const TAG_INFO: &str = "log-info";
const TAG_DEBUG: &str = "log-debug";
const TAG_TIMESTAMP: &str = "log-timestamp";

// ============================================================================
// Public: build the log viewer window
// ============================================================================

/// Build the log viewer window.
///
/// Contains a header bar with a level filter dropdown and a read-only,
/// monospace `TextView` inside a `ScrolledWindow` that auto-scrolls to
/// the latest entry.
pub fn build_logs_window(parent: &impl IsA<gtk4::Window>) -> adw::Window {
    let window = adw::Window::builder()
        .title("Log Viewer")
        .default_width(720)
        .default_height(520)
        .modal(true)
        .transient_for(parent)
        .build();

    // ── Level filter dropdown ───────────────────────────────────────────

    let level_model = gtk4::StringList::new(&["All", "Error", "Warn", "Info", "Debug"]);
    let level_dropdown = gtk4::DropDown::builder()
        .model(&level_model)
        .selected(0)
        .tooltip_text("Filter by log level")
        .build();
    level_dropdown.set_widget_name(LEVEL_DROPDOWN);

    // ── Header ──────────────────────────────────────────────────────────

    let header = adw::HeaderBar::new();
    header.pack_end(&level_dropdown);

    // ── Text buffer with colour tags ────────────────────────────────────

    let buffer = gtk4::TextBuffer::new(None::<&gtk4::TextTagTable>);

    // Create colour tags
    let tag_table = buffer.tag_table();

    let error_tag = gtk4::TextTag::builder()
        .name(TAG_ERROR)
        .foreground("red")
        .weight(700)
        .build();
    tag_table.add(&error_tag);

    let warn_tag = gtk4::TextTag::builder()
        .name(TAG_WARN)
        .foreground("orange")
        .weight(600)
        .build();
    tag_table.add(&warn_tag);

    let info_tag = gtk4::TextTag::builder()
        .name(TAG_INFO)
        .foreground("#4a90d9")
        .build();
    tag_table.add(&info_tag);

    let debug_tag = gtk4::TextTag::builder()
        .name(TAG_DEBUG)
        .foreground("gray")
        .build();
    tag_table.add(&debug_tag);

    let ts_tag = gtk4::TextTag::builder()
        .name(TAG_TIMESTAMP)
        .foreground("#888888")
        .family("monospace")
        .build();
    tag_table.add(&ts_tag);

    // ── TextView (monospace, read-only) ─────────────────────────────────

    let text_view = gtk4::TextView::builder()
        .buffer(&buffer)
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .left_margin(8)
        .right_margin(8)
        .top_margin(4)
        .bottom_margin(4)
        .build();
    text_view.set_widget_name(LOG_TEXT_VIEW);

    // ── Scrolled window (auto-scroll to bottom) ─────────────────────────

    let scrolled = gtk4::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .hscrollbar_policy(gtk4::PolicyType::Automatic)
        .vscrollbar_policy(gtk4::PolicyType::Automatic)
        .build();
    scrolled.set_child(Some(&text_view));

    // Auto-scroll: whenever the buffer changes, scroll to the end.
    let adj = scrolled.vadjustment();
    adj.connect_upper_notify({
        let adj = adj.clone();
        move |_| {
            // Scroll to bottom when new content is added
            adj.set_value(adj.upper() - adj.page_size());
        }
    });

    // ── Layout ──────────────────────────────────────────────────────────

    let content = gtk4::Box::builder()
        .orientation(gtk4::Orientation::Vertical)
        .build();
    content.append(&header);
    content.append(&scrolled);

    window.set_content(Some(&content));

    // ── Signal: level filter changed ────────────────────────────────────
    //
    // The filter works by hiding/showing lines.  For simplicity this
    // implementation uses tag visibility -- a more robust approach would
    // re-filter the full buffer or use a `TextChildAnchor` model.

    level_dropdown.connect_selected_notify({
        let win = window.clone();
        let level_model = level_model.clone();
        move |dd| {
            let idx = dd.selected();
            let level = level_model
                .string(idx)
                .map(|g| g.to_string())
                .unwrap_or_else(|| "All".to_string());
            set_level_filter(&win, &level);
        }
    });

    window
}

// ============================================================================
// Public: append a single log line
// ============================================================================

/// Append a formatted, colour-tagged log line to the text view.
///
/// Format: `[LEVEL] message\n`
///
/// The level is colour-coded via text tags.
pub fn append_log(window: &adw::Window, level: &str, message: &str) {
    let Some(text_view) = find_text_view(window) else {
        return;
    };
    let buffer = text_view.buffer();

    let tag_name = tag_for_level(level);

    let mut end = buffer.end_iter();

    // Timestamp prefix
    let now = chrono::Local::now().format("%H:%M:%S");
    let ts_text = format!("{now} ");
    let ts_start = buffer.end_iter().offset();
    buffer.insert(&mut end, &ts_text);
    let ts_end = buffer.end_iter().offset();

    if let Some(tag) = buffer.tag_table().lookup(TAG_TIMESTAMP) {
        buffer.apply_tag(
            &tag,
            &buffer.iter_at_offset(ts_start),
            &buffer.iter_at_offset(ts_end),
        );
    }

    // Level + message
    let line = format!("[{level:>5}] {message}\n");
    let line_start = buffer.end_iter().offset();
    let mut end = buffer.end_iter();
    buffer.insert(&mut end, &line);
    let line_end = buffer.end_iter().offset();

    if let Some(tag) = buffer.tag_table().lookup(tag_name) {
        buffer.apply_tag(
            &tag,
            &buffer.iter_at_offset(line_start),
            &buffer.iter_at_offset(line_end),
        );
    }
}

// ============================================================================
// Public: level filter
// ============================================================================

/// Filter visible entries by log level.
///
/// Accepted values: `"All"`, `"Error"`, `"Warn"`, `"Info"`, `"Debug"`.
///
/// This hides non-matching lines by making the corresponding text tags
/// invisible.  "All" makes every tag visible.
pub fn set_level_filter(window: &adw::Window, level: &str) {
    let Some(text_view) = find_text_view(window) else {
        return;
    };
    let buffer = text_view.buffer();
    let tag_table = buffer.tag_table();

    let level_priority = level_priority(level);

    // For each log-level tag, set invisible if below the requested priority.
    for (tag_name, tag_priority) in &[(TAG_ERROR, 4), (TAG_WARN, 3), (TAG_INFO, 2), (TAG_DEBUG, 1)]
    {
        if let Some(tag) = tag_table.lookup(tag_name) {
            // level_priority == 0 means "All" -> everything visible
            let invisible = level_priority > 0 && *tag_priority < level_priority;
            tag.set_invisible(invisible);
        }
    }
}

// ============================================================================
// Public: bulk load from history
// ============================================================================

/// Bulk-load log entries from the server history endpoint.
///
/// Each entry is expected to have `"level"`, `"message"`, and optionally
/// `"timestamp"` keys.
pub fn load_history(window: &adw::Window, entries: &[serde_json::Value]) {
    let Some(text_view) = find_text_view(window) else {
        return;
    };

    // Clear the buffer before loading history.
    let buffer = text_view.buffer();
    buffer.set_text("");

    for entry in entries {
        let level = entry["level"].as_str().unwrap_or("INFO");
        let message = entry["message"].as_str().unwrap_or("");
        let timestamp = entry["timestamp"].as_str().unwrap_or("");

        let tag_name = tag_for_level(level);

        let mut end = buffer.end_iter();

        // Timestamp
        if !timestamp.is_empty() {
            let ts_start = buffer.end_iter().offset();
            let ts_text = format!("{timestamp} ");
            buffer.insert(&mut end, &ts_text);
            let ts_end = buffer.end_iter().offset();

            if let Some(tag) = buffer.tag_table().lookup(TAG_TIMESTAMP) {
                buffer.apply_tag(
                    &tag,
                    &buffer.iter_at_offset(ts_start),
                    &buffer.iter_at_offset(ts_end),
                );
            }
        }

        // Level + message
        let line = format!("[{level:>5}] {message}\n");
        let line_start = buffer.end_iter().offset();
        let mut end = buffer.end_iter();
        buffer.insert(&mut end, &line);
        let line_end = buffer.end_iter().offset();

        if let Some(tag) = buffer.tag_table().lookup(tag_name) {
            buffer.apply_tag(
                &tag,
                &buffer.iter_at_offset(line_start),
                &buffer.iter_at_offset(line_end),
            );
        }
    }
}

// ============================================================================
// Internal: helpers
// ============================================================================

/// Map a level string (case-insensitive) to the corresponding text-tag name.
fn tag_for_level(level: &str) -> &'static str {
    match level.to_ascii_uppercase().as_str() {
        "ERROR" | "FATAL" => TAG_ERROR,
        "WARN" | "WARNING" => TAG_WARN,
        "INFO" => TAG_INFO,
        "DEBUG" | "TRACE" => TAG_DEBUG,
        _ => TAG_INFO,
    }
}

/// Map a level name to a numeric priority for filtering.
///
/// `0` = All, `1` = Debug, `2` = Info, `3` = Warn, `4` = Error.
fn level_priority(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "error" => 4,
        "warn" => 3,
        "info" => 2,
        "debug" => 1,
        _ => 0, // "All"
    }
}

/// Find the log `TextView` inside the window by widget name.
fn find_text_view(window: &adw::Window) -> Option<gtk4::TextView> {
    find_widget_by_name::<gtk4::TextView>(window.upcast_ref(), LOG_TEXT_VIEW)
}

fn find_widget_by_name<T: IsA<gtk4::Widget>>(widget: &gtk4::Widget, name: &str) -> Option<T> {
    if widget.widget_name() == name {
        if let Some(typed) = widget.clone().downcast::<T>().ok() {
            return Some(typed);
        }
    }

    let mut child = widget.first_child();
    while let Some(c) = child {
        if let Some(found) = find_widget_by_name::<T>(&c, name) {
            return Some(found);
        }
        child = c.next_sibling();
    }
    None
}
