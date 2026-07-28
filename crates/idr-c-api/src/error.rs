//! Thread-local last-error for the C ABI.

use std::cell::RefCell;

use idr_core::{IdrError, IdrErrorKind};

thread_local! {
    static LAST_KIND: RefCell<u32> = const { RefCell::new(0) };
    static LAST_MSG: RefCell<String> = const { RefCell::new(String::new()) };
}

pub fn clear_last_error() {
    LAST_KIND.with(|k| *k.borrow_mut() = 0);
    LAST_MSG.with(|m| m.borrow_mut().clear());
}

pub fn set_last_error(err: &IdrError) {
    LAST_KIND.with(|k| *k.borrow_mut() = err.kind as u32);
    LAST_MSG.with(|m| *m.borrow_mut() = err.message.clone());
}

pub fn set_last_error_kind(kind: IdrErrorKind, message: impl Into<String>) {
    set_last_error(&IdrError::new(kind, message));
}

pub fn last_error_code() -> u32 {
    LAST_KIND.with(|k| *k.borrow())
}

pub fn last_error_message() -> String {
    LAST_MSG.with(|m| m.borrow().clone())
}
