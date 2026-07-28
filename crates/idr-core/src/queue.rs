//! Bounded queues for backpressure (no unbounded buffering).

use crate::error::{IdrError, IdrErrorKind, Result};

/// Fixed-capacity FIFO; push fails with `Backpressure` when full.
#[derive(Debug)]
pub struct BoundedQueue<T> {
    inner: std::collections::VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedQueue<T> {
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "bounded queue capacity must be > 0");
        Self {
            inner: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.len() >= self.capacity
    }

    pub fn try_push(&mut self, item: T) -> Result<()> {
        if self.is_full() {
            return Err(IdrError::new(
                IdrErrorKind::Backpressure,
                "bounded queue full",
            ));
        }
        self.inner.push_back(item);
        Ok(())
    }

    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_when_full() {
        let mut q = BoundedQueue::new(1);
        q.try_push(1).unwrap();
        let err = q.try_push(2).unwrap_err();
        assert_eq!(err.kind(), IdrErrorKind::Backpressure);
    }
}
