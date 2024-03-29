#![no_std]

pub mod models;
pub mod rules;
pub mod utils;

pub use models::{BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType};

pub const ARGV_COUNT: usize = 10;
pub const RULES_PER_KEY: usize = 10;
pub const OPS_PER_RULE: usize = 5;
