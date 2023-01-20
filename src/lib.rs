//! Based on Duncan's fantastic
//! [Scuttlebutt Protocol Guide](https://ssbc.github.io/scuttlebutt-protocol-guide/)
//! ([repo](https://github.com/ssbc/scuttlebutt-protocol-guide)),
//! which he graciously released into the public domain.
#![cfg_attr(not(feature = "std"), no_std)]

extern "C" {
    fn __cc_trace(msg: *const u8);
    fn __cc_trace_exec(
        name: *const u8,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    );
}

macro_rules! cc_trace {
    ($msg:expr) => {
        unsafe { crate::__cc_trace(concat!($msg, "\0").as_ptr()) }
    };
}

macro_rules! cc_trace_exec {
    ($msg:expr, $arg0:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {
        unsafe { crate::__cc_trace_exec(concat!($msg, "\0").as_ptr(), $arg0, $arg1, $arg2, $arg3) }
    };
}


pub mod bytes;
pub mod error;
pub use error::HandshakeError;
pub mod crypto;

#[cfg(feature = "std")]
pub mod util;

#[cfg(feature = "std")]
#[path = ""]
mod std_stuff {
    mod client;
    pub use client::client_side;
    mod server;
    pub use server::server_side;
}
#[cfg(feature = "std")]
pub use std_stuff::*;

pub mod sync;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use std::io::ErrorKind;

    use futures::executor::block_on;
    use futures::future::join;

    extern crate async_ringbuffer;
    use async_ringbuffer::Duplex;
    use ssb_crypto::{Keypair, NetworkKey, PublicKey};

    #[test]
    fn basic() {
        let (mut c_stream, mut s_stream) = Duplex::pair(1024);
        let skey = Keypair::generate();
        let ckey = Keypair::generate();

        let net_key = NetworkKey::SSB_MAIN_NET;
        let client_side = client_side(&mut c_stream, &net_key, &ckey, &skey.public);
        let server_side = server_side(&mut s_stream, &net_key, &skey);

        let (c_out, s_out) = block_on(async { join(client_side, server_side).await });

        let c_out = c_out.unwrap();
        let s_out = s_out.unwrap();

        assert_eq!(c_out.write_key.0, s_out.read_key.0);
        assert_eq!(c_out.read_key.0, s_out.write_key.0);

        assert_eq!(c_out.write_starting_nonce.0, s_out.read_starting_nonce.0);
        assert_eq!(c_out.read_starting_nonce.0, s_out.write_starting_nonce.0);
    }

    fn is_eof_err<T>(r: &Result<T, HandshakeError<std::io::Error>>) -> bool {
        match r {
            Err(HandshakeError::Io(e)) => e.kind() == ErrorKind::UnexpectedEof,
            _ => false,
        }
    }

    #[test]
    fn server_rejects_wrong_netkey() {
        let (mut c_stream, mut s_stream) = Duplex::pair(1024);
        let skey = Keypair::generate();
        let ckey = Keypair::generate();

        let cnet = NetworkKey::generate();
        let snet = NetworkKey::generate();

        let client = client_side(&mut c_stream, &cnet, &ckey, &skey.public);
        let server = server_side(&mut s_stream, &snet, &skey);

        let (c_out, s_out) = block_on(async { join(client, server).await });

        assert!(is_eof_err(&c_out));
        match s_out {
            Err(HandshakeError::ClientHelloVerifyFailed) => {}
            _ => panic!(),
        };
    }

    #[test]
    fn server_rejects_wrong_pk() {
        test_handshake_with_bad_server_pk(&PublicKey([0; 32]));

        let key = Keypair::generate();
        test_handshake_with_bad_server_pk(&key.public);
    }

    fn test_handshake_with_bad_server_pk(bad_pk: &PublicKey) {
        let (mut c_stream, mut s_stream) = Duplex::pair(1024);
        let skey = Keypair::generate();
        let ckey = Keypair::generate();

        let net_key = NetworkKey::SSB_MAIN_NET;

        let client_side = client_side(&mut c_stream, &net_key, &ckey, &bad_pk);
        let server_side = server_side(&mut s_stream, &net_key, &skey);

        let (c_out, s_out) = block_on(async { join(client_side, server_side).await });

        assert!(c_out.is_err());
        assert!(s_out.is_err());
    }
}
