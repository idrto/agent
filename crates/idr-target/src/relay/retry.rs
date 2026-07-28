use std::time::{Duration, Instant};

pub fn backoff_duration(initial: Duration, max: Duration, failure_count: u32) -> Duration {
    let shift = failure_count.min(16);
    let scaled = initial.saturating_mul(1u32 << shift);
    scaled.min(max)
}

pub fn retry_after_from_now(initial: Duration, max: Duration, failure_count: u32) -> Instant {
    Instant::now() + backoff_duration(initial, max, failure_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_caps_at_max() {
        let d = backoff_duration(Duration::from_millis(250), Duration::from_secs(30), 100);
        assert_eq!(d, Duration::from_secs(30));
    }
}
