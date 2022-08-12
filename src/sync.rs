//! Experimental synchronous implementation, using `genio` `Read`/`Write` traits,
//! mostly for no_std environments.

pub mod client;
pub use client::client_side;
pub mod server;
pub use server::server_side;
pub mod util;
