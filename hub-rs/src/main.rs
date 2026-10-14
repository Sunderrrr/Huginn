//! huginn-hub — the Huginn hub (Rust port of hub/).
//!
//! Phased migration: this crate replaces the FastAPI hub module by module.
//! Security primitives are parity-tested against the Python implementation
//! (see security_vectors.json, generated from the Python code itself).

pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod routes;
pub mod security;
pub mod services;

fn main() {
    println!("huginn-hub scaffold");
}
