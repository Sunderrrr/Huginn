//! huginn-hub — the Huginn hub (Rust port of hub/).
//!
//! Phased migration: this crate replaces the FastAPI hub module by module.
//! Security primitives are parity-tested against the Python implementation
//! (see security_vectors.json, generated from the Python code itself).

mod config;
mod db;
mod error;
mod models;
mod security;

fn main() {
    println!("huginn-hub scaffold");
}
