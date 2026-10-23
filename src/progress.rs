//! Progress output on stderr, in the style of cargo: one line per finished
//! step, with a right-aligned verb and the time it took. On a terminal the
//! step in progress is shown on one extra line (spinner, elapsed time, current
//! request or command) that is redrawn in place; elsewhere (CI, pipes) only
//! finished steps are printed. stdout carries only the report.

use std::fmt::Display;
use std::io::{IsTerminal, Write};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Style {
    /// `--quiet`: warnings and errors only.
    Quiet,
    /// Not a terminal: finished steps only, no colors.
    Plain,
    /// A terminal: live status line, colors unless `NO_COLOR` is set.
    Terminal { color: bool },
}

/// The step in progress (terminal only).
struct Active {
    verb: String,
    message: String,
    detail: String,
    started: Instant,
    /// Whether the status line is currently on screen.
    drawn: bool,
}

static STYLE: OnceLock<Style> = OnceLock::new();
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const RED: &str = "\x1b[1;31m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";
const ERASE: &str = "\r\x1b[2K";

/// Pick the output style once, at startup. Without a call (unit tests) the
/// style is `Plain`.
pub fn init(quiet: bool) {
    let style = if quiet {
        Style::Quiet
    } else if std::io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|t| t != "dumb")
    {
        Style::Terminal {
            color: std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty()),
        }
    } else {
        Style::Plain
    };
    if STYLE.set(style).is_ok() && matches!(style, Style::Terminal { .. }) {
        crate::platform::enable_ansi();
        std::thread::spawn(|| {
            let mut frame = 0usize;
            loop {
                std::thread::sleep(Duration::from_millis(100));
                frame = frame.wrapping_add(1);
                let mut active = lock();
                if let Some(a) = active.as_mut() {
                    draw(a, frame);
                }
            }
        });
    }
}

fn style() -> Style {
    STYLE.get().copied().unwrap_or(Style::Plain)
}

fn color() -> bool {
    matches!(style(), Style::Terminal { color: true })
}

fn lock() -> MutexGuard<'static, Option<Active>> {
    ACTIVE.lock().unwrap_or_else(|e| e.into_inner())
}

/// A running step. Finish it with [`Step::done`] or [`Step::failed`];
/// dropping it (e.g. on `?`) just removes the status line.
#[must_use]
pub struct Step {
    started: Instant,
}

/// Start a step: `verb` and `message` are shown on the status line.
pub fn begin(verb: &str, message: impl Display) -> Step {
    if matches!(style(), Style::Terminal { .. }) {
        let mut active = lock();
        erase(&mut active);
        *active = Some(Active {
            verb: verb.to_string(),
            message: message.to_string(),
            detail: String::new(),
            started: Instant::now(),
            drawn: false,
        });
    }
    Step {
        started: Instant::now(),
    }
}

/// What the current step is doing right now (a URL, a command). Shown on the
/// status line only.
pub fn detail(text: &str) {
    if let Some(a) = lock().as_mut() {
        a.detail = text.to_string();
    }
}

impl Step {
    /// The step succeeded: print `verb message (time)`.
    pub fn done(self, verb: &str, message: impl Display) {
        print_line(
            GREEN,
            verb,
            &format!("{message} ({})", elapsed(self.started)),
        );
    }

    /// The step did not succeed (the run continues): same, verb in yellow.
    pub fn failed(self, verb: &str, message: impl Display) {
        print_line(
            YELLOW,
            verb,
            &format!("{message} ({})", elapsed(self.started)),
        );
    }
}

impl Drop for Step {
    fn drop(&mut self) {
        let mut active = lock();
        erase(&mut active);
        *active = None;
    }
}

/// A one-off status line, e.g. `Updated Cargo.lock`.
pub fn line(verb: &str, message: impl Display) {
    print_line(GREEN, verb, &message.to_string());
}

/// `warning: ...`, also printed with `--quiet`.
pub fn warn(message: impl Display) {
    print_tagged(YELLOW, "warning", &message.to_string());
}

/// `error: ...`, also printed with `--quiet`.
pub fn error(message: impl Display) {
    print_tagged(RED, "error", &message.to_string());
}

/// `1.2s` below a minute, `3m 05s` above.
pub fn elapsed(since: Instant) -> String {
    let d = since.elapsed();
    if d.as_secs() < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{}m {:02}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

/// `1 change`, `2 changes`.
pub fn count(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn print_line(code: &str, verb: &str, message: &str) {
    if matches!(style(), Style::Quiet) {
        return;
    }
    let mut active = lock();
    erase(&mut active);
    let verb = paint(code, &format!("{verb:>12}"));
    let _ = writeln!(std::io::stderr(), "{verb} {message}");
}

fn print_tagged(code: &str, tag: &str, message: &str) {
    let mut active = lock();
    erase(&mut active);
    let _ = writeln!(std::io::stderr(), "{}: {message}", paint(code, tag));
}

fn paint(code: &str, text: &str) -> String {
    if color() {
        format!("{code}{text}{RESET}")
    } else {
        text.to_string()
    }
}

/// Remove the status line from the screen (it is redrawn on the next tick).
fn erase(active: &mut Option<Active>) {
    if let Some(a) = active.as_mut().filter(|a| a.drawn) {
        let _ = write!(std::io::stderr(), "{ERASE}");
        a.drawn = false;
    }
}

/// `    Planning fixes  ⠹ 4s  registry.npmjs.org/router`, cut to the terminal
/// width so it never wraps.
fn draw(a: &mut Active, frame: usize) {
    let head = format!(
        "{:>12} {}  {} {}s",
        a.verb,
        a.message,
        FRAMES[frame % FRAMES.len()],
        a.started.elapsed().as_secs()
    );
    let width = crate::platform::terminal_width()
        .unwrap_or(80)
        .saturating_sub(1);
    let mut text = truncate(&head, width);
    let room = width.saturating_sub(text.chars().count() + 2);
    if !a.detail.is_empty() && room > 8 {
        text = format!("{text}  {}", paint(DIM, &truncate(&a.detail, room)));
    }
    let verb_len = format!("{:>12}", a.verb).len().min(text.len());
    if color() && text.is_char_boundary(verb_len) {
        text = format!("{}{}", paint(GREEN, &text[..verb_len]), &text[verb_len..]);
    }
    let _ = write!(std::io::stderr(), "{ERASE}{text}");
    let _ = std::io::stderr().flush();
    a.drawn = true;
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_by_chars() {
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("äöüß", 2), "ä…");
    }

    #[test]
    fn counts() {
        assert_eq!(count(1, "change", "changes"), "1 change");
        assert_eq!(count(0, "change", "changes"), "0 changes");
    }
}
