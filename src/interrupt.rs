//! Interrupts: Ctrl-C, SIGTERM and SIGHUP (on Windows Ctrl-C, Ctrl-Break and
//! closing the console). The platform's handler
//! ([`crate::platform::install_interrupt_handlers`]) calls [`record`] and
//! makes sure the running command gets the interrupt too. Outside of
//! `verify` and `write_back` (nothing to clean up) mendr then exits at once;
//! inside, a [`defer`] guard is alive and mendr unwinds at the next
//! [`check`], so the temp copy is removed and nothing is half-written, and
//! [`catch`] turns that into an exit code. A second interrupt exits at once.

use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

/// Signal numbers, also used on Windows for its console events: they set
/// the exit code (128 + number), the same on every platform.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;

/// The interrupt that arrived (0 = none yet).
pub static SIGNAL: AtomicI32 = AtomicI32::new(0);
/// Number of active [`Defer`] guards.
static DEFERRING: AtomicUsize = AtomicUsize::new(0);

/// Unwind payload of an interrupted run; see [`catch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interrupted(pub i32);

impl Interrupted {
    /// Conventional exit code: 128 + signal number (130 for SIGINT, 143 for
    /// SIGTERM, 129 for SIGHUP).
    pub fn exit_code(self) -> u8 {
        u8::try_from(128 + self.0).unwrap_or(255)
    }
}

/// Records interrupt `sig` and returns whether mendr must exit at once (a
/// second interrupt, or no [`Defer`] guard alive). Only atomics, so a Unix
/// signal handler may call it.
pub fn record(sig: i32) -> bool {
    let first = SIGNAL
        .compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    !first || DEFERRING.load(Ordering::SeqCst) == 0
}

/// While a guard is alive, an interrupt does not exit at once but makes
/// [`check`] unwind.
pub struct Defer;

pub fn defer() -> Defer {
    DEFERRING.fetch_add(1, Ordering::SeqCst);
    Defer
}

impl Drop for Defer {
    fn drop(&mut self) {
        DEFERRING.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Unwind with [`Interrupted`] if an interrupt arrived. Called between
/// steps, so the temp copy (a `TempDir`) is removed on the way out.
pub fn check() {
    let sig = SIGNAL.load(Ordering::SeqCst);
    if sig != 0 {
        unwind(sig);
    }
}

pub fn unwind(sig: i32) -> ! {
    // `resume_unwind` does not run the panic hook: no panic message.
    std::panic::resume_unwind(Box::new(Interrupted(sig)))
}

/// Run `f`, turning an unwind from [`check`] into `Err(Interrupted)`. Real
/// panics keep unwinding.
pub fn catch<T>(f: impl FnOnce() -> T) -> Result<T, Interrupted> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|payload| {
        match payload.downcast::<Interrupted>() {
            Ok(i) => *i,
            Err(other) => std::panic::resume_unwind(other),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unwinds_and_removes_temp_dirs() {
        let parent = tempfile::tempdir().unwrap();
        let mut path = std::path::PathBuf::new();
        let result = catch(|| {
            let tmp = tempfile::tempdir_in(parent.path()).unwrap();
            path = tmp.path().to_path_buf();
            unwind(SIGTERM);
        });
        assert_eq!(result, Err(Interrupted(SIGTERM)));
        assert_eq!(Interrupted(SIGTERM).exit_code(), 143);
        assert_eq!(Interrupted(SIGINT).exit_code(), 130);
        assert!(!path.as_os_str().is_empty() && !path.exists());
        assert_eq!(catch(|| 7), Ok(7));
    }
}
