#![no_std]

pub mod models;
pub mod rules;
pub mod utils;

pub use models::{BShieldAction, BShieldEvent, BShieldEventClass, BShieldEventType};

pub const ARGV_COUNT: usize = 10;
