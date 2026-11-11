//! The clock, so a test can fix the time a trusted start is signed at.

/// Wall-clock time.
pub trait Clock: Send + Sync {
    /// Unix seconds.
    fn now_secs(&self) -> i64;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}
